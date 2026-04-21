SDN Flow Table Analyzer using Ryu and Mininet

This project implements a Software Defined Networking (SDN) simulation using Mininet and a Ryu OpenFlow 1.3 controller. The controller behaves as an L2 learning switch, installs forwarding rules dynamically, polls switches for flow statistics, and classifies rules as ACTIVE or UNUSED based on packet counters.

Project Overview
The network consists of 3 Open vSwitch switches (s1, s2, s3) connected in a linear topology and 6 hosts (h1 to h6) distributed across the switches. The Ryu controller listens on 127.0.0.1:6633, manages OpenFlow 1.3 communication, installs table-miss and learned unicast flows, and periodically prints a structured flow table report.

Features
Multi-switch SDN topology in Mininet with deterministic port mapping.

Ryu-based L2 learning switch controller using OpenFlow 1.3.

Dynamic flow rule installation for known destinations.

Periodic polling of switches using OFPFlowStatsRequest.

Flow classification into:

ACTIVE: packet count is at least 1.

UNUSED: packet count is 0.

Human-readable flow table reports in the Ryu terminal.

Support for optional bandwidth limiting using --bw


Technologies Used
Python 3
Mininet
Ryu Controller


Files in the Project
flow_analyzer_controller.py — Ryu controller that performs MAC learning, installs flows, polls flow stats, and prints reports.

multi_switch_topo.py or multi_switch_topo-2.py — Mininet topology script that builds the 3-switch, 6-host network and connects it to the Ryu controller.

How It Works
When a switch connects, the controller installs a table-miss rule so unmatched packets are forwarded to the controller. When packets arrive, the controller learns source MAC-to-port mappings, decides whether to flood or unicast, and installs priority-1 forwarding rules for known destinations with configured idle and hard timeouts.

A background monitoring thread periodically sends FlowStatsRequest messages to all connected switches and stores the replies. The controller then prints a formatted table showing priority, match fields, packet count, byte count, rule age, and status. Rules with packet count greater than or equal to the active threshold are marked ACTIVE, and the rest are marked UNUSED


Sample Output
The controller prints a report like this in the Ryu terminal:

Switch ID

Flow priority

Match fields

Packet count

Byte count

Flow age

Status (ACTIVE or UNUSED)

This helps visualize how traffic changes the flow table over time.

Learning Outcomes
This project demonstrates:

SDN architecture with separated control plane and data plane.

OpenFlow-based communication between controller and switches.

Dynamic flow installation and packet handling.

Flow statistics monitoring and rule-state analysis.

Practical use of Mininet for SDN experimentation.
