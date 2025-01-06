import os
import socket
from datetime import datetime, timedelta
import sys

# Mapping enums to strings
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    255: "OTHER",
    143: "ANY"
}

REASON_MAP = {
    -1: "FW_INACTIVE",
    -2: "NO_MATCHING_RULE",
    -4: "XMAS_PACKET",
    -6: "ILLEGAL_VALUE"
}

ACTION_MAP = {
    0: "drop",
    1: "accept"
}

DIRECTION_MAP = {
    1: "in",
    2: "out",
    3: "any"
}

ACK_BIT_MAP = {
    1: "no",
    2: "yes",
    3: "any"
}

PORT_MAP = {
    0: "any",
    1023: ">1023",
}

STATE_MAP = {
    0x01: "STATE_LISTEN",
    0x02: "STATE_SYN_SENT",
    0x03: "STATE_SYN_RECEIVED",
    0x04: "STATE_ESTABLISHED",
    0x05: "STATE_FIN_WAIT_1",
    0x06: "STATE_FIN_WAIT_2",
    0x07: "STATE_CLOSE_WAIT",
    0x08: "STATE_CLOSING",
    0x09: "STATE_LAST_ACK",
    0x0A: "STATE_TIME_WAIT",
    0x0B: "STATE_CLOSED",
}


# Path to the sysfs file for the sysfs attribute
SYSFS_PATH_RULES='/sys/class/fw/rules/rules'
SYSFS_PATH_LOG = '/sys/class/fw/log/reset'
SYSFS_PATH_CONNS = "/sys/class/fw/conns/conns"
CHARDEV_PATH_LOG='/dev/fw_log'

def get_tcp_state_name(state_value):
    """
    Maps a TCP state value to its corresponding name.

    :param state_value: Integer value representing the TCP state.
    :return: String name of the TCP state or None if not found.
    """
    return STATE_MAP.get(int(state_value), "DNE")


def process_src_port(src_port):
    if src_port.isdigit():
        # The string represents an integer, convert it to int and then apply ntohs
        port_num = int(src_port)
        converted_port = socket.ntohs(port_num)
        if converted_port in PORT_MAP:
            return PORT_MAP.get(converted_port)
        return converted_port
    else:
        # The string does not represent an integer, keep it as is
        return src_port


def format_rules(rules_string):
    """
    Formats a string of firewall rules into a readable format.
    
    :param rules_string: String containing firewall rules, one per line.
    :return: Formatted rules as a string.
    """
    formatted_rules = []
    
    for line in rules_string.strip().splitlines():
        print(line)
        parts = line.split()
        if len(parts) != 9:
            formatted_rules.append("Invalid rule format: {}".format(line))
            continue
        
        # Extract fields
        name = parts[0]
        direction = int(parts[1])
        src_ip = parts[2]
        dst_ip = parts[3]
        protocol = int(parts[4])
        src_port = process_src_port(parts[5])
        dst_port = process_src_port(parts[6])
        ack_bit = int(parts[7])
        action = int(parts[8])

        # Map fields to human-readable strings
        direction_str = DIRECTION_MAP.get(direction, "UNKNOWN")
        protocol_str = PROTOCOL_MAP.get(protocol, "UNKNOWN")
        ack_bit_str = ACK_BIT_MAP.get(ack_bit, "UNKNOWN")
        action_str = ACTION_MAP.get(action, "UNKNOWN")

        # Format the rule
        formatted_rule = "{:<10} {:<4} {:<15} {:<15} {:<5} {:<6} {:<6} {:<3} {}".format(
            name, direction_str, src_ip, dst_ip, protocol_str, src_port, dst_port, ack_bit_str, action_str
        )

        formatted_rules.append(formatted_rule)
    
    return "\n".join(formatted_rules)


def show_connections_table():
    # Define the path to the sysfs device
    
    try:
        # Read the file content
        with open(SYSFS_PATH_CONNS, "r") as file:
            lines = file.readlines()
        
        # Print the header for the connections table
        print("{:<15} {:<15} {:<15} {:<15} {:<15}".format("Source IP", "Source Port", "Destination IP", "Destination Port", "State"))
        print("=" * 75)
        
        # Process each line and print the formatted table
        for line in lines:
            # Strip whitespace and split by commas
            parts = line.strip().split(",")
            if len(parts) == 5:
                src_ip, src_port, dst_ip, dst_port, state = parts
                print("{:<15} {:<15} {:<15} {:<15} {:<15}".format(src_ip, src_port, dst_ip, dst_port, get_tcp_state_name(state)))
            else:
                print("Invalid line format:", line.strip())
    
    except FileNotFoundError:
        print("Error: The sysfs device {} does not exist.".format(SYSFS_PATH_CONNS))
    except PermissionError:
        print("Error: Permission denied to read {}.".format(SYSFS_PATH_CONNS))
    except Exception as e:
        print("Error: An unexpected error occurred: {}".format(e))


def clear_log():
    try:
        with open(SYSFS_PATH_LOG, 'w') as f:
            f.write("{}\n".format(0))
    except IOError:
        print("Error: {} not found. Make sure the module is loaded.".format(SYSFS_PATH_LOG))
    except Exception as e:
        print("Error writing to sysfs: {}".format(e))


def jiffies_to_date(jiffies):
    """
    Convert jiffies to a human-readable timestamp.
    Assuming system jiffies increment at 1000 Hz (typical default on Linux).
    Adjust if your kernel uses a different HZ value.
    """
    HZ = 1000  # Modify this value if the HZ is different on your system.

    # System boot time
    with open('/proc/uptime', 'r') as f:
        uptime_seconds = float(f.readline().split()[0])
    boot_time = datetime.now() - timedelta(seconds=uptime_seconds)

    # Calculate the exact timestamp
    seconds_since_boot = jiffies / HZ
    return boot_time + timedelta(seconds=seconds_since_boot)


def show_log():
    """
    Reads logs from the firewall character device, parses, and prints them.
    """
    if not os.path.exists(CHARDEV_PATH_LOG):
        print("Error: Character device '{}' does not exist.".format(CHARDEV_PATH_LOG))
        return

    try:
        with open(CHARDEV_PATH_LOG, 'r') as f:
            print("Reading firewall logs...")
            print("{:<20} {:<15} {:<15} {:<10} {:<10} {:<8} {:<8} {:<15} {:<5}".format(
                "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "action", "reason", "count"
            ))

            for line in f:
                parts = line.split()
                if len(parts) != 9:
                    print("Invalid log format: ", line)
                    continue

                jiffies = int(parts[0])
                src_ip = parts[1]
                dst_ip = parts[2]
                src_port = process_src_port(parts[3])
                dst_port = process_src_port(parts[4])
                protocol = int(parts[5])
                action = int(parts[6])
                reason = int(parts[7])
                count = parts[8]

                # Convert jiffies to human-readable timestamp
                timestamp = jiffies_to_date(jiffies).strftime('%d/%m/%Y %H:%M:%S')

                    # Map enums to strings
                protocol_str = PROTOCOL_MAP.get(protocol, "UNKNOWN({})".format(protocol))
                action_str = ACTION_MAP.get(action, "{}".format(action))
                reason_str = REASON_MAP.get(reason, "{}".format(reason))

                print("{:<20} {:<15} {:<15} {:<10} {:<10} {:<8} {:<8} {:<15} {:<5}".format(
                    timestamp, src_ip, dst_ip, src_port, dst_port, protocol_str, action_str, reason_str, count
                ))
    except Exception as e:
        print("Error reading character device: {}".format(e))

def load_rules(file_path):
    """
    Writes the content of the given file to the sysfs device for loading rules.
    :param file_path: Path to the file containing the rules.
    :param sysfs_path: Path to the sysfs device to write the rules.
    """
    try:
        # Open the file containing rules and read its content
        with open(file_path, 'r') as rules_file:
            rules_content = rules_file.read()
        
        # Open the sysfs device and write the rules
        with open(SYSFS_PATH_RULES, 'w') as sysfs_device:
            sysfs_device.write(rules_content)
        
        print("Rules loaded successfully from {} to {}.".format(file_path, SYSFS_PATH_RULES))
    except FileNotFoundError:
        print("Error: File '{}' or sysfs device '{}' not found.".format(file_path, SYSFS_PATH_RULES))
    except PermissionError:
        print("Error: Permission denied when accessing '{}'. Try running as root.".format(file_path, SYSFS_PATH_RULES))
    except Exception as e:
        print("Error: {}".format(e))

def show_rules():
    """
    Reads the content of the sysfs device for rules and prints it to the console.
    :param SYSFS_PATH_RULES: Path to the sysfs device to read the rules.
    """
    try:
        # Open the sysfs device and read the content
        with open(SYSFS_PATH_RULES, 'r') as sysfs_device:
            rules_content = sysfs_device.read()
        
        print("Current Rules:\n{}".format(format_rules(rules_content)))
    except FileNotFoundError:
        print("Error: Sysfs device '{}' not found.".format(SYSFS_PATH_RULES))
    except PermissionError:
        print("Error: Permission denied when accessing '{}'. Try running as root.".format(SYSFS_PATH_RULES))
    except Exception as e:
        print("Error: {}".format(e))


def main():
        args = sys.argv
        # Check correct number of arguments
        if len(args) == 3 and args[1] == "load_rules":
            load_rules(args[2])
        # Reset stats
        elif len(args) == 2 and args[1] in ["show_log", "clear_log", "show_rules", "show_conns"]:
            param = args[1]
            if param == "show_log":
                show_log()
            elif param == "clear_log":
                clear_log()
            elif param == "show_rules":
                show_rules()
            elif param == "show_conns":
                show_connections_table()
        # Read Stats
        else:
            print("Invalid Argument.")

if __name__ == '__main__':
    main()
