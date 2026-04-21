#!/usr/bin/env python3
"""
=============================================================================
  Multi-Switch Flow Table Analyzer — Ryu SDN Controller
  Course  : Computer Networks (UE24CS252B)
  Project : SDN Mininet-based Simulation (Orange Problem)
=============================================================================

WHAT THIS FILE DOES:
  1. L2 Learning Switch — learns MAC→port per switch, installs unicast rules.
  2. Installs explicit OpenFlow 1.3 match-action flow rules on every switch.
  3. Handles packet_in correctly (no duplicate buffer consumption).
  4. Polls every switch for FlowStatsReply every POLL_INTERVAL seconds.
  5. Classifies rules as ACTIVE (packet_count >= 1) or UNUSED (0 packets).
  6. Prints a structured Flow Table Report to terminal after every poll cycle.

KEY OPENFLOW CONCEPTS:
  packet_in    : switch → controller  (no matching rule found)
  flow_mod     : controller → switch  (install / delete a rule)
  packet_out   : controller → switch  (forward one specific packet NOW)
  flow_stats   : controller asks switch for its flow table counters
  match        : criteria a packet must satisfy  (in_port, eth_src, eth_dst …)
  action       : what to do when matched         (output port, drop, flood …)
  idle_timeout : auto-delete rule after N seconds of inactivity
  hard_timeout : auto-delete rule after N seconds regardless of traffic
=============================================================================
"""

# ── Ryu framework imports ──────────────────────────────────────────────────
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.lib import hub  # eventlet-based green threads# ── Standard library ───────────────────────────────────────────────────────
import time
import collections


# ── Tunable constants ──────────────────────────────────────────────────────
IDLE_TIMEOUT  = 30    # seconds of inactivity → rule auto-deleted by switch
HARD_TIMEOUT  = 120   # seconds max lifetime   → rule auto-deleted by switch
POLL_INTERVAL = 10    # seconds between flow-stats poll cycles
ACTIVE_THRESH = 1     # packet_count must reach this to be called "ACTIVE"


# ══════════════════════════════════════════════════════════════════════════
class FlowTableAnalyzer(app_manager.RyuApp):
    """
    Single Ryu application combining:
      • L2 learning switch   (MAC learning + unicast forwarding rules)
      • Flow statistics poller (periodic FlowStatsRequest)
      • Active/Unused classifier (printed report every POLL_INTERVAL s)
    """

    # Tell Ryu we speak OpenFlow 1.3 only
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # ------------------------------------------------------------------
    def __init__(self, *args, **kwargs):
        super(FlowTableAnalyzer, self).__init__(*args, **kwargs)

        # mac_table[dpid][mac_addr] = port_number
        # "Learning" part of the learning switch.
        # Each switch keeps its own independent table.
        self.mac_table = collections.defaultdict(dict)

        # datapaths[dpid] = Datapath object
        # Ryu's Datapath represents a live connection to one OVS switch.
        # We store it so the monitor thread can reach switches at any time.
        self.datapaths = {}

        # flow_stats_store[dpid] = list of OFPFlowStats
        # Refreshed every poll cycle by _flow_stats_reply_handler.
        self.flow_stats_store = collections.defaultdict(list)

        # Start the background green-thread that polls for stats
        self.monitor_thread = hub.spawn(self._monitor_loop)

        self.logger.info("=" * 62)
        self.logger.info("  Flow Table Analyzer — Controller started")
        self.logger.info(f"  Poll interval : {POLL_INTERVAL}s")
        self.logger.info(f"  Idle timeout  : {IDLE_TIMEOUT}s")
        self.logger.info(f"  Hard timeout  : {HARD_TIMEOUT}s")
        self.logger.info(f"  Active thresh : {ACTIVE_THRESH} packet(s)")
        self.logger.info("=" * 62)

    # ══════════════════════════════════════════════════════════════════
    # EVENT 1: Switch connects → install table-miss rule
    # ══════════════════════════════════════════════════════════════════
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Fired once when a switch completes its OpenFlow handshake.

        We install the TABLE-MISS rule:
          match    = empty  (matches EVERY packet that nothing else matches)
          action   = send to controller port
          priority = 0      (lowest possible — last resort)
          timeouts = 0, 0   (never expire — must always be present)

        Without this rule, unmatched packets are silently dropped by OVS.
        With it, they are sent up to us via packet_in so we can learn and
        install a proper forwarding rule.
        """
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dpid     = datapath.id

        # Store for later use by monitor thread
        self.datapaths[dpid] = datapath
        self.logger.info(f"[+] Switch connected  dpid={dpid}")

        # Empty match → matches everything
        match = parser.OFPMatch()

        # Action: send entire packet to controller
        # OFPCML_NO_BUFFER (0xffff) = "send the whole packet, don't buffer"
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        instructions = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]

        self._add_flow(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=instructions,
            idle_timeout=0,
            hard_timeout=0,
        )
        self.logger.info(f"    [S{dpid}] Table-miss rule installed (priority=0)")

    # ══════════════════════════════════════════════════════════════════
    # EVENT 2: packet_in — switch received a packet with no matching rule
    # ══════════════════════════════════════════════════════════════════
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        This is the core learning-switch + flow-install logic.

        Algorithm:
          1. Parse Ethernet header → get src_mac, dst_mac.
          2. LEARN:  record src_mac → in_port in this switch's mac_table.
          3. DECIDE: if dst_mac is known → unicast; else → flood.
          4. INSTALL (unicast only): push a flow rule so future packets
             with this dst_mac skip the controller entirely.
          5. FORWARD: send THIS packet out (packet_out).

        CRITICAL BUG AVOIDED:
          When we install a flow_mod with buffer_id set, the switch
          immediately applies the rule to the buffered packet AND frees
          the buffer.  If we then ALSO send a packet_out referencing
          the same buffer_id, OVS returns "OFPBRC_BUFFER_UNKNOWN" error.
          Fix: only send packet_out when buffer_id was NOT consumed by
          a flow_mod (i.e., when out_port==FLOOD, or buffer==OFP_NO_BUFFER).
        """
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dpid     = datapath.id
        in_port  = msg.match['in_port']

        # ── Parse Ethernet layer ──────────────────────────────────────
        pkt     = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if eth_pkt is None:
            return   # Not Ethernet — nothing to do

        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        # Drop LLDP (ethertype 0x88CC) — used by OVS internally,
        # causes noise in our flow table if we install rules for it.
        if eth_pkt.ethertype == 0x88CC:
            return

        # ── Step 2: Learn src_mac → in_port ──────────────────────────
        self.mac_table[dpid][src_mac] = in_port
        self.logger.debug(f"    [S{dpid}] LEARN  {src_mac} → port {in_port}")

        # ── Step 3: Decide output port ────────────────────────────────
        if dst_mac in self.mac_table[dpid]:
            out_port = self.mac_table[dpid][dst_mac]
            self.logger.info(
                f"    [S{dpid}] UNICAST  {src_mac} → {dst_mac}  "
                f"in={in_port} out={out_port}"
            )
        else:
            out_port = ofproto.OFPP_FLOOD
            self.logger.info(
                f"    [S{dpid}] FLOOD    {src_mac} → {dst_mac}  "
                f"in={in_port} (dst unknown)"
            )

        # ── Step 4: Install flow rule for unicast paths ───────────────
        # We only install rules for unicast — flooding rules would waste
        # TCAM space and don't improve performance (floods are rare).
        flow_consumed_buffer = False   # tracks whether flow_mod took buffer

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=src_mac,
                eth_dst=dst_mac,
            )
            actions = [parser.OFPActionOutput(out_port)]
            instructions = [
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
            ]

            # Pass buffer_id to flow_mod ONLY if the switch buffered this packet.
            # When we do this, the switch applies the rule to the buffered packet
            # and releases the buffer — so we MUST NOT send a packet_out after.
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._add_flow(
                    datapath=datapath,
                    priority=1,
                    match=match,
                    instructions=instructions,
                    idle_timeout=IDLE_TIMEOUT,
                    hard_timeout=HARD_TIMEOUT,
                    buffer_id=msg.buffer_id,   # switch will apply + free buffer
                )
                flow_consumed_buffer = True    # buffer already handled
            else:
                self._add_flow(
                    datapath=datapath,
                    priority=1,
                    match=match,
                    instructions=instructions,
                    idle_timeout=IDLE_TIMEOUT,
                    hard_timeout=HARD_TIMEOUT,
                )

            self.logger.info(
                f"    [S{dpid}] FLOW_MOD  priority=1  "
                f"in={in_port} src={src_mac[-5:]} dst={dst_mac[-5:]} "
                f"→ out={out_port}  "
                f"idle={IDLE_TIMEOUT}s hard={HARD_TIMEOUT}s"
            )

        # ── Step 5: Send packet_out for THIS specific packet ──────────
        # Only needed if the buffer was NOT already consumed by flow_mod above.
        if not flow_consumed_buffer:
            out_actions = [parser.OFPActionOutput(out_port)]

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                # Packet is buffered at switch, reference by ID
                pkt_out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=out_actions,
                    data=None,
                )
            else:
                # No buffer — we must include the raw packet bytes
                pkt_out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=out_actions,
                    data=msg.data,
                )
            datapath.send_msg(pkt_out)

    # ══════════════════════════════════════════════════════════════════
    # BACKGROUND THREAD: periodic stats poll loop
    # ══════════════════════════════════════════════════════════════════
    def _monitor_loop(self):
        """
        Runs forever in a Ryu green-thread (hub.spawn).

        Cycle every POLL_INTERVAL seconds:
          1. Send OFPFlowStatsRequest to every connected switch.
          2. Sleep 2s to let replies arrive (handled asynchronously).
          3. Print the Flow Table Report.
        """
        self.logger.info("[Monitor] Polling thread started.")
        while True:
            hub.sleep(POLL_INTERVAL)
            if not self.datapaths:
                self.logger.info("[Monitor] No switches connected yet...")
                continue
            for dpid, datapath in list(self.datapaths.items()):
                self._send_stats_request(datapath)
            hub.sleep(2)            # wait for FlowStatsReply events to arrive
            self._print_flow_report()

    # ══════════════════════════════════════════════════════════════════
    # Send OFPFlowStatsRequest to one switch
    # ══════════════════════════════════════════════════════════════════
    def _send_stats_request(self, datapath):
        """
        Ask a switch: "Reply with every entry in your flow table."

        OFPFlowStatsRequest parameters:
          table_id  = OFPTT_ALL  → query all pipeline tables (usually just 0)
          out_port  = OFPP_ANY   → don't filter by output port
          out_group = OFPG_ANY   → don't filter by group
          match     = OFPMatch() → empty = match all entries
        """
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(
            datapath=datapath,
            flags=0,
            table_id=ofproto.OFPTT_ALL,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            cookie=0,
            cookie_mask=0,
            match=parser.OFPMatch(),
        )
        datapath.send_msg(req)
        self.logger.debug(f"[Monitor] StatsRequest → dpid={datapath.id}")

    # ══════════════════════════════════════════════════════════════════
    # EVENT 3: FlowStatsReply — switch returns its flow table
    # ══════════════════════════════════════════════════════════════════
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        Called when a switch responds to our OFPFlowStatsRequest.

        ev.msg.body is a list of OFPFlowStats, one per flow entry.
        Each entry exposes:
          .priority      — rule priority (higher = evaluated first)
          .match         — OFPMatch object (dict-like)
          .instructions  — list of OFPInstruction objects
          .packet_count  — cumulative packets matched since installation
          .byte_count    — cumulative bytes matched
          .duration_sec  — seconds since this rule was installed
          .idle_timeout  — configured idle timeout
          .hard_timeout  — configured hard timeout
          .table_id      — which pipeline table (0 for our setup)
        """
        dpid = ev.msg.datapath.id
        body = ev.msg.body

        # Sort: highest priority first; within same priority, newest last
        self.flow_stats_store[dpid] = sorted(
            body,
            key=lambda f: (f.priority, f.duration_sec),
            reverse=True,
        )
        self.logger.debug(
            f"[Monitor] StatsReply  dpid={dpid}  entries={len(body)}"
        )

    # ══════════════════════════════════════════════════════════════════
    # Print the Flow Table Report
    # ══════════════════════════════════════════════════════════════════
    def _print_flow_report(self):
        """
        Iterates over all switches and their stored flow entries.
        Classifies each entry:
          ACTIVE → packet_count >= ACTIVE_THRESH  (traffic has matched this rule)
          UNUSED → packet_count <  ACTIVE_THRESH  (no traffic yet, or expired+reinstalled)

        Prints a tabular report to stdout.

        CLASSIFICATION RATIONALE:
          The table-miss rule (priority=0) starts with packet_count=0 and
          increments each time packet_in fires.  Once learning rules are
          in place, new traffic matches them first (priority=1), so the
          table-miss count stops growing and it appears UNUSED — this is
          correct behaviour: it means the controller is no longer a
          bottleneck for that traffic flow.
        """
        if not self.flow_stats_store:
            self.logger.info("[Report] No stats stored yet — waiting...")
            return

        total_active = 0
        total_unused = 0
        report_time  = time.strftime("%H:%M:%S")

        print("\n" + "═" * 72)
        print(f"  FLOW TABLE REPORT   {report_time}")
        print("═" * 72)

        for dpid in sorted(self.flow_stats_store.keys()):
            entries = self.flow_stats_store[dpid]
            if not entries:
                continue

            print(f"\n  ┌─ Switch S{dpid}  (dpid={dpid})")
            print(
                f"  │  {'PRI':>4}  "
                f"{'MATCH':<38}  "
                f"{'PKTS':>7}  "
                f"{'BYTES':>9}  "
                f"{'AGE(s)':>6}  "
                f"{'STATUS':<8}"
            )
            print("  │  " + "─" * 64)

            for stat in entries:
                pkt_count  = stat.packet_count
                byte_count = stat.byte_count
                duration   = stat.duration_sec
                priority   = stat.priority
                match_str  = _format_match(stat.match)
                action_str = _format_instructions(stat.instructions)

                if pkt_count >= ACTIVE_THRESH:
                    status = "ACTIVE  ✓"
                    total_active += 1
                else:
                    status = "UNUSED  ✗"
                    total_unused += 1

                print(
                    f"  │  {priority:>4}  "
                    f"{match_str:<38}  "
                    f"{pkt_count:>7}  "
                    f"{byte_count:>9}  "
                    f"{duration:>6}  "
                    f"{status}"
                )
                # Sub-line: action detail
                print(f"  │        action: {action_str}")

            print(f"  └─ {len(entries)} entries on S{dpid}")

        print()
        print("─" * 72)
        print(
            f"  SUMMARY  |  "
            f"ACTIVE: {total_active}   "
            f"UNUSED: {total_unused}   "
            f"TOTAL: {total_active + total_unused}"
        )
        print("═" * 72 + "\n")

    # ══════════════════════════════════════════════════════════════════
    # Helper: install a flow rule (OFPFlowMod ADD)
    # ══════════════════════════════════════════════════════════════════
    def _add_flow(self, datapath, priority, match, instructions,
                  idle_timeout=0, hard_timeout=0, buffer_id=None):
        """
        Build and send an OFPFlowMod(command=OFPFC_ADD) to the switch.

        Parameters
        ----------
        datapath     : the target switch's Datapath object
        priority     : rule priority (higher wins on match conflict)
        match        : OFPMatch — criteria the packet must satisfy
        instructions : list of OFPInstruction — what to do when matched
        idle_timeout : seconds of inactivity before auto-delete (0=never)
        hard_timeout : seconds max lifetime before auto-delete   (0=never)
        buffer_id    : if not OFP_NO_BUFFER, apply rule to this buffered
                       packet immediately AND release the buffer.
                       Caller must NOT send a separate packet_out after.
        """
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        kwargs = dict(
            datapath=datapath,
            command=ofproto.OFPFC_ADD,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            priority=priority,
            match=match,
            instructions=instructions,
        )
        # Only include buffer_id in flow_mod when it's a real buffer reference
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs['buffer_id'] = buffer_id

        datapath.send_msg(parser.OFPFlowMod(**kwargs))


# ══════════════════════════════════════════════════════════════════════════
# Module-level helpers (pure functions — no self needed)
# ══════════════════════════════════════════════════════════════════════════

def _format_match(match):
    """
    Convert an OFPMatch object into a compact human-readable string.

    OFPMatch behaves like a dict — use 'in' to test field presence.
    Missing fields simply aren't printed (keeps output tidy).
    """
    parts = []

    if 'in_port' in match:
        parts.append(f"port={match['in_port']}")

    if 'eth_src' in match:
        # Show last 8 chars of MAC (e.g. "00:00:01") for compactness
        parts.append(f"src={str(match['eth_src'])[-8:]}")

    if 'eth_dst' in match:
        parts.append(f"dst={str(match['eth_dst'])[-8:]}")

    if 'eth_type' in match:
        parts.append(f"etype=0x{match['eth_type']:04x}")

    if 'ipv4_src' in match:
        parts.append(f"ip_src={match['ipv4_src']}")

    if 'ipv4_dst' in match:
        parts.append(f"ip_dst={match['ipv4_dst']}")

    return ", ".join(parts) if parts else "<table-miss (match-all)>"


def _format_instructions(instructions):
    """
    Convert a list of OFPInstruction objects into a readable string.
    We only inspect OFPInstructionActions (the most common type).
    """
    parts = []
    for inst in instructions:
        # OFPInstructionActions has an .actions list
        if hasattr(inst, 'actions'):
            for action in inst.actions:
                if hasattr(action, 'port'):
                    port = action.port
                    # Translate special port numbers to names
                    if port == 0xfffffffd:      # OFPP_CONTROLLER
                        parts.append("→ CONTROLLER")
                    elif port == 0xfffffff8:    # OFPP_FLOOD
                        parts.append("→ FLOOD")
                    else:
                        parts.append(f"→ port {port}")
                else:
                    parts.append(type(action).__name__)
    return "  ".join(parts) if parts else "(none)"
