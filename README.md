# Basic Packet Filtering Firewall Module

## Overview
This project implements a simple Linux kernel module that performs basic packet filtering using Netfilter hooks. It allows for the inspection and modification of incoming and outgoing network traffic based on user-defined rules. The module supports logging of packets, connection tracking, and stateful firewall functionalities for TCP traffic. Additionally, it can intercept and modify packets for Man-in-the-Middle (MITM) attacks for HTTP and FTP protocols.

## Features
- **Packet Filtering:** Basic filtering of TCP/UDP/ICMP packets based on rules such as source and destination IPs, ports, and protocols.
- **Connection Tracking:** Tracks state of TCP connections and allows for handling of connection states (SYN_SENT, LISTEN, ESTABLISHED, etc.).
- **MITM (Man-in-the-Middle) Support:** Modifies packets for HTTP and FTP protocols, intercepting and redirecting traffic to a specified port.
- **Logging:** Logs each packet passing through the firewall, providing details like timestamp, IPs, ports, action (accept/drop), and reason.
- **Sysfs Interface:** Provides a sysfs interface to manage firewall rules, view connection states, and reset logs.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/firewall-module.git
   cd firewall-module

## Sysfs Interface

This firewall module exposes several attributes via the sysfs interface. These attributes allow interaction with the firewall, such as adding/removing rules, viewing connection logs, and resetting the logs.

### Available Attributes

- **rules**: Displays or modifies the list of active firewall rules.
  - `cat /sys/class/fw/rules` - Displays current rules.
  - `echo "rule_str" > /sys/class/fw/rules` - Adds a new rule (format described in `modify_rules` function).

- **reset**: Resets the packet logs.
  - `echo "reset" > /sys/class/fw/reset` - Resets the log entries.

- **conns**: Displays the current connection tracking table.
  - `cat /sys/class/fw/conns` - Lists connections and their states.

- **mitm**: Modifies MITM (Man-in-the-Middle) port configuration for HTTP/FTP traffic.
  - `echo "<src_ip>,<src_port>,<mitm_port>" > /sys/class/fw/mitm` - Configures MITM for a given connection.

## Packet Handling

The module uses Netfilter hooks to handle packets during different phases of their journey:

1. **Pre-Routing** (`NF_INET_PRE_ROUTING`): Filters packets before routing.
2. **Local-In** (`NF_INET_LOCAL_IN`): Handles incoming packets to the local machine.
3. **Local-Out** (`NF_INET_LOCAL_OUT`): Handles outgoing packets from the local machine.

## Supported Protocols

- **TCP**: Handles packet filtering based on TCP flags (SYN, ACK, FIN, etc.).
- **UDP**: Filters based on UDP ports.
- **ICMP**: Filters based on ICMP type and code.