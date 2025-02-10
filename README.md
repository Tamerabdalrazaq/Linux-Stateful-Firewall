# Firewall 
This project was carried out with the guidance of Reuven Plevinsky @ Check Point Software Technologies 
## Overview
The firewall module performs comprehensive packet inspection, connection tracking, and logging, making it a versatile tool for network security on a Linux machine. By leveraging the Netfilter framework, it enables efficient and stateful packet filtering, MITM support for certain protocols, and real-time traffic monitoring. The sysfs interface further allows dynamic interaction with the firewall, providing flexibility in managing firewall rules and inspecting network traffic.


## Features
- **Packet Filtering:** Basic filtering of TCP/UDP/ICMP packets based on rules such as source and destination IPs, ports, and protocols.
- **Connection Tracking:** Tracks state of TCP connections and allows for handling of connection states (SYN_SENT, LISTEN, ESTABLISHED, etc.).
- **MITM (Man-in-the-Middle) Support:** Modifies packets for HTTP and FTP protocols, intercepting and redirecting traffic to a specified port.
- **Logging:** Logs each packet passing through the firewall, providing details like timestamp, IPs, ports, action (accept/drop), and reason.
- **Sysfs Interface:** Provides a sysfs interface to manage firewall rules, view connection states, and reset logs.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/tamerabdalrazaq/linux-stateful-firewall.git
   cd linux-stateful-firewall
2. Initialize the module:
    ```bash
    bash init_module.sh
    bash activate_proxies.sh http
    bash activate_proxies.sh ftp
    bash activate_proxies.sh smtp

## Sysfs Interface

This firewall module exposes several attributes via the sysfs interface. These attributes allow interaction with the firewall, such as adding/removing rules, viewing connection logs, and resetting the logs.
    ```bash
    bash run_user.sh

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
2. **Local-Out** (`NF_INET_LOCAL_OUT`): Handles outgoing packets from the local machine.

# How the Firewall Module Works

The firewall module is designed to intercept, filter, and log packets traveling through a Linux machine using the Netfilter framework. It processes both incoming and outgoing traffic based on user-defined rules, and it is capable of handling TCP, UDP, and ICMP packets. Below is a brief overview of the key functions and how they contribute to the operation of the firewall module.

## 1. Static Packet Filtering

One of the core functionality of the firewall module is filtering network packets based on the configured static rules. The module intercepts packets at various points in the networking stack using Netfilter hooks. Each packet is inspected, and its attributes (such as source/destination IP address, port, protocol, and flags) are matched against the predefined firewall rules.

### Relevant Functions:
- **`comp_packet_to_static_rules()`**:
  - Compares the attributes of an incoming packet (IP, port, protocol) with the defined rules in the module and returns a rule index if a match is found. If no match is found, it returns `-1` (indicating to drop the packet).
  
- **`module_hook()`**:
  - The main function that uses `comp_packet_to_static_rules()` to check if a packet matches any rules in the firewall. It determines the verdict for each packet (accept or drop) and handles the packet accordingly.

## 2. Stateful Filtering - Connection Tracking

The module tracks the state of TCP connections, maintaining connection states for each connection (e.g., SYN_SENT, LISTEN, ESTABLISHED). It is essential for stateful packet filtering, where the module allows or denies packets based on their relation to an existing connection.

### Relevant Functions:
- **`find_connection_row()`**:
  - Searches for an existing connection in the connection table and returns the corresponding connection rule if found. This helps determine whether a packet belongs to an established connection or if it should be treated as a new connection.
  
- **`initiate_connection()`**:
  - This function is responsible for adding a new connection to the connection table. It initializes the connection with state information (e.g., SYN_SENT, ESTABLISHED) and creates an entry in the table for future tracking.
  
- **`handle_tcp_state_machine()`**:
  - Implements the TCP state machine, which handles the transitions between various states of a TCP connection (e.g., SYN_SENT, ESTABLISHED, FIN_WAIT_1). It ensures that packets related to existing connections are processed based on their state.

## 3. Logging

The module logs every packet that it processes, including the packet’s timestamp, source and destination IPs, ports, protocol, action (accept/drop), and reason for the action. This helps administrators monitor network traffic and troubleshoot issues.

### Relevant Functions:
- **`add_or_update_log_entry()`**:
  - Adds a new log entry for each packet or updates an existing log entry if a matching packet is found in the log list. It tracks the packet count and updates the timestamp.
  
- **`read_logs()`**:
  - Reads the stored logs and displays them to the user. It formats each log entry and allows for inspection of all logged packets.
  
- **`reset_logs()`**:
  - Resets all packet logs, effectively clearing the current logging information stored in the system.

## 4. MITM (Man-in-the-Middle) Support

The module supports modifying packets in real-time for HTTP and FTP traffic, allowing for Man-in-the-Middle (MITM) attacks. In this case, packets can be redirected to a different server or port, enabling packet inspection and modification on the fly.

## 5. DLP
Prevention of leaking sensitive C code on HTTP and SMTP ports

## 6. IPS
Intrusion prevention system base layed with an implementation of a prevention of two known vulnerabilities for the ApacheOfbiz framework (CVE-2024-32113 and CVE-2024-38856)


### Relevant Functions:
- **`handle_mitm_pre_routing()`**:
  - Intercepts packets and modifies their destination IP or port, enabling MITM functionality. For example, it can redirect HTTP or FTP traffic to a different machine or port.
  
- **`handle_mitm_local_out()`**:
  - This function modifies outgoing packets for HTTP or FTP traffic, adjusting the source or destination address and port as necessary for MITM functionality.

## 5. Sysfs Interface

The module exposes several attributes via the sysfs interface, allowing the user to interact with the firewall dynamically. These attributes allow the user to view and modify firewall rules, reset logs, and inspect the current connection table.

### Relevant Functions:
- **`display_rules()`**:
  - Displays all the currently active firewall rules in a human-readable format. This allows administrators to check which rules are currently applied.
  
- **`modify_rules()`**:
  - Allows for the addition or modification of firewall rules via the sysfs interface. The user can send new rules in a specific format to this function, which then updates the rule set.
  
- **`read_connections_table()`**:
  - Displays the current connection table, showing all active connections and their respective states.
  
- **`modify_mitm_port()`**:
  - Allows users to modify MITM port configurations for HTTP or FTP traffic. This function enables the redirection of packets to the desired MITM proxy.

## 6. Netfilter Hooks

Netfilter hooks are used to integrate the module with the Linux networking stack. The module registers hooks at different stages of packet processing to inspect and act upon packets.

### Relevant Hooks:
- **`NF_INET_PRE_ROUTING`**: This hook is triggered before the routing decision is made. It is used to filter or modify incoming packets.
    
- **`NF_INET_LOCAL_OUT`**: This hook is triggered for outgoing packets originating from the local machine. It allows for filtering and modification of outbound traffic.
