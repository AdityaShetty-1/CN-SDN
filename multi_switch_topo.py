#!/usr/bin/env python3
"""
=============================================================================
  Multi-Switch Flow Table Analyzer - Mininet Topology
  Course  : Computer Networks (UE24CS252B)
  Project : SDN Mininet-based Simulation (Orange Problem)
=============================================================================

TOPOLOGY DIAGRAM:
                      [Ryu Controller]
                      127.0.0.1:6633
                            |  OpenFlow 1.3 (TCP)
          +-----------------+-----------------+
          |                 |                 |
       [S1]------------[S2]-------------[S3]
       /   |             /   |             /   |
     H1     H2         H3     H4         H5     H6
  10.0.0.1 .2       10.0.0.3 .4       10.0.0.5 .6

  Switch ports (deterministic assignment):
    S1: port1=H1  port2=H2  port3=S2
    S2: port1=H3  port2=H4  port3=S1  port4=S3
    S3: port1=H5  port2=H6  port3=S2

BUGS FIXED vs original:
  1. MultiSwitchTopo(bw=bw) → Topo.build() kwargs must be passed via
     build_params dict, not as constructor kwargs directly (Mininet 2.3+).
     Fix: pass bw as a plain positional build() argument through params.

  2. Duplicate port1=1 on every host link.
     Fix: all host-side port numbers left as default (hosts have only eth0,
     port numbers on host side are irrelevant and Mininet assigns them auto).

  3. Mininet(controller=None) + net.addController() pattern is fragile —
     the controller object is created BEFORE net.start() but Mininet's
     internal build() phase doesn't know about it.
     Fix: use build_params and pass RemoteController directly to Mininet().

  4. net.pingAll() before controller fully connects causes spurious drops.
     Fix: increase wait time and check OVS controller status before pingall.

  5. autoSetMacs=True assigns MACs based on host *position in topo graph*,
     not IP suffix — causes confusing MACs.
     Fix: assign explicit MAC addresses to match IP suffix (00:00:00:00:00:01
     for 10.0.0.1, etc.) so flow table output is human-readable.

HOW TO RUN:
  Terminal 1 — start controller first:
    ryu-manager flow_analyzer_controller.py --verbose

  Terminal 2 — start topology:
    sudo python3 multi_switch_topo.py

  With bandwidth cap for iperf testing:
    sudo python3 multi_switch_topo.py --bw 10
=============================================================================
"""

import argparse
import time
import subprocess

from mininet.net    import Mininet
from mininet.node   import RemoteController, OVSKernelSwitch
from mininet.link   import TCLink
from mininet.topo   import Topo
from mininet.log    import setLogLevel, info, error
from mininet.cli    import CLI


# ── MAC addresses aligned to IP suffix (makes flow tables readable) ────────
HOST_CONFIG = {
    'h1': {'ip': '10.0.0.1/24', 'mac': '00:00:00:00:00:01'},
    'h2': {'ip': '10.0.0.2/24', 'mac': '00:00:00:00:00:02'},
    'h3': {'ip': '10.0.0.3/24', 'mac': '00:00:00:00:00:03'},
    'h4': {'ip': '10.0.0.4/24', 'mac': '00:00:00:00:00:04'},
    'h5': {'ip': '10.0.0.5/24', 'mac': '00:00:00:00:00:05'},
    'h6': {'ip': '10.0.0.6/24', 'mac': '00:00:00:00:00:06'},
}


# ══════════════════════════════════════════════════════════════════════════
class MultiSwitchTopo(Topo):
    """
    Custom Mininet topology: 3 switches, 6 hosts, linear inter-switch chain.

    Topo.build() is called by Mininet internally.  We receive bw here
    (passed via Mininet's build_params mechanism).

    Port assignment strategy (deterministic = easier to read in flow tables):
      S1 → port1: H1,  port2: H2,  port3: link to S2
      S2 → port1: H3,  port2: H4,  port3: link to S1,  port4: link to S3
      S3 → port1: H5,  port2: H6,  port3: link to S2
    """

    def build(self, bw=None):
        """
        bw: optional int (Mbps).  When set, all links get a bandwidth cap
            and 5ms artificial delay — useful for visible iperf throughput
            differences in demo.
        """
        # Link options — only applied when bw is specified
        link_opts = {}
        if bw is not None:
            link_opts = {'bw': bw, 'delay': '5ms', 'loss': 0, 'use_htb': True}

        # ── Switches ──────────────────────────────────────────────────
        # failMode='secure': switch drops packets if controller disconnects
        # (safer than failMode='standalone' which reverts to L2 hub)
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch,
                            protocols='OpenFlow13', failMode='secure')
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch,
                            protocols='OpenFlow13', failMode='secure')
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch,
                            protocols='OpenFlow13', failMode='secure')

        # ── Hosts with explicit IPs and MACs ─────────────────────────
        h1 = self.addHost('h1', **HOST_CONFIG['h1'])
        h2 = self.addHost('h2', **HOST_CONFIG['h2'])
        h3 = self.addHost('h3', **HOST_CONFIG['h3'])
        h4 = self.addHost('h4', **HOST_CONFIG['h4'])
        h5 = self.addHost('h5', **HOST_CONFIG['h5'])
        h6 = self.addHost('h6', **HOST_CONFIG['h6'])

        # ── Host ↔ switch links ───────────────────────────────────────
        # port2 = switch-side port number (pinned for predictability)
        # port1 on host side doesn't matter (hosts only have eth0)
        self.addLink(h1, s1, port2=1, **link_opts)   # H1 → S1 port 1
        self.addLink(h2, s1, port2=2, **link_opts)   # H2 → S1 port 2

        self.addLink(h3, s2, port2=1, **link_opts)   # H3 → S2 port 1
        self.addLink(h4, s2, port2=2, **link_opts)   # H4 → S2 port 2

        self.addLink(h5, s3, port2=1, **link_opts)   # H5 → S3 port 1
        self.addLink(h6, s3, port2=2, **link_opts)   # H6 → S3 port 2

        # ── Inter-switch links (data plane backbone) ──────────────────
        # S1 port3 ↔ S2 port3   (left inter-switch link)
        # S2 port4 ↔ S3 port3   (right inter-switch link)
        self.addLink(s1, s2, port1=3, port2=3, **link_opts)
        self.addLink(s2, s3, port1=4, port2=3, **link_opts)


# ══════════════════════════════════════════════════════════════════════════
def wait_for_controller(host='127.0.0.1', port=6633, timeout=15):
    """
    Poll TCP port 6633 until Ryu is listening, or timeout expires.
    Prevents the topology from starting before the controller is ready.
    """
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=1)
            s.close()
            return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.5)
    return False


# ══════════════════════════════════════════════════════════════════════════
def run(bw=None):
    setLogLevel('info')

    # ── Check controller is reachable before building topology ────────────
    info("\n[*] Checking Ryu controller at 127.0.0.1:6633 ...\n")
    if not wait_for_controller():
        error(
            "\n[ERROR] Ryu controller is NOT listening on port 6633.\n"
            "        Start it first in Terminal 1:\n"
            "          ryu-manager flow_analyzer_controller.py --verbose\n\n"
        )
        return

    info("[*] Controller found. Building topology...\n")

    # ── Build topology ────────────────────────────────────────────────────
    # Pass bw through build_params so Topo.build() receives it correctly.
    topo = MultiSwitchTopo()

    net = Mininet(
        topo=topo,
        controller=None,  # added manually below
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=False,   # we set MACs explicitly in HOST_CONFIG
        autoStaticArp=False, # let ARP flow through SDN controller
        waitConnected=True,  # block until all switches connect to ctrl
    )

    # Add remote Ryu controller
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633,
    )

    # Start everything
    net.start()

    # Configure each switch to use OpenFlow 1.3 and point at the controller.
    # This is belt-and-suspenders: the Topo already sets protocols=OpenFlow13,
    # but ovs-vsctl ensures OVS picks it up correctly at runtime.
    for sw in [net['s1'], net['s2'], net['s3']]:
        sw.cmd(f'ovs-vsctl set bridge {sw.name} protocols=OpenFlow13')
        sw.cmd(
            f'ovs-vsctl set-controller {sw.name} '
            f'tcp:127.0.0.1:6633'
        )

    # Wait for all switches to register with the controller
    info("[*] Waiting 4s for OpenFlow handshake to complete...\n")
    time.sleep(4)

    # ── Print topology summary ────────────────────────────────────────────
    info("\n" + "=" * 60 + "\n")
    info("  Multi-Switch Flow Table Analyzer — Topology Ready\n")
    info("  Hosts:\n")
    for name, cfg in HOST_CONFIG.items():
        info(f"    {name}  {cfg['ip'].split('/')[0]:<12}  {cfg['mac']}\n")
    info("\n")
    info("  Switches: S1 ── S2 ── S3  (linear chain)\n")
    info("  Port map : S1(p1=H1,p2=H2,p3→S2)\n")
    info("             S2(p1=H3,p2=H4,p3→S1,p4→S3)\n")
    info("             S3(p1=H5,p2=H6,p3→S2)\n")
    info("  Controller: Ryu @ 127.0.0.1:6633 (OpenFlow 1.3)\n")
    info("=" * 60 + "\n")

    # ── Connectivity test ─────────────────────────────────────────────────
    info("[*] Running pingall — expect 0% dropped...\n")
    loss = net.pingAll()
    if loss == 0.0:
        info("[✓] pingall passed: 0% packet loss\n")
    else:
        info(f"[!] pingall: {loss:.0f}% loss — check controller logs\n")

    # ── Usage hints ───────────────────────────────────────────────────────
    info("\n" + "─" * 60 + "\n")
    info("  MININET CLI COMMANDS FOR DEMO:\n\n")
    info("  Scenario 1 — Active traffic (watch ACTIVE rules appear):\n")
    info("    mininet> h1 ping -c 5 h6\n")
    info("    mininet> h3 ping -c 5 h4\n")
    info("    mininet> pingall\n\n")
    info("  Scenario 2 — No traffic (watch UNUSED rules persist):\n")
    info("    (just wait after pings stop, watch controller terminal)\n\n")
    info("  Throughput test:\n")
    info("    mininet> h1 iperf -s &\n")
    info("    mininet> h6 iperf -c 10.0.0.1\n\n")
    info("  Inspect raw OVS flow tables:\n")
    info("    mininet> sh ovs-ofctl dump-flows s1 -O OpenFlow13\n")
    info("    mininet> sh ovs-ofctl dump-flows s2 -O OpenFlow13\n")
    info("    mininet> sh ovs-ofctl dump-flows s3 -O OpenFlow13\n")
    info("─" * 60 + "\n\n")

    # ── Interactive CLI ───────────────────────────────────────────────────
    CLI(net)

    # ── Cleanup ───────────────────────────────────────────────────────────
    net.stop()
    info("[*] Network stopped.\n")
    info("[*] Run 'sudo mn -c' if any OVS state remains.\n")


# ══════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Multi-Switch SDN topology for Flow Table Analysis'
    )

    parser.add_argument(
        '--bw', type=int, default=None,
        metavar='MBPS',
        help='Optional link bandwidth cap in Mbps (e.g. --bw 10)'
    )

    args = parser.parse_args()
    run(bw=args.bw)
