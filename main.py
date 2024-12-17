import os
import time
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
    1: "IN",
    2: "OUT",
    3: "ANY"
}

ACK_BIT_MAP = {
    1: "NO",
    2: "YES",
    3: "ANY"
}


# Path to the sysfs file for the sysfs attribute
sysfs_clr_log_file_path = '/sys/class/fw/log/reset'

def format_rules(rules_string):
    """
    Formats a string of firewall rules into a readable format.
    
    :param rules_string: String containing firewall rules, one per line.
    :return: Formatted rules as a string.
    """
    formatted_rules = []
    
    for line in rules_string.strip().splitlines():
        parts = line.split()
        if len(parts) != 8:
            formatted_rules.append("Invalid rule format: {}".format(line))
            continue
        
        # Extract fields
        name = parts[0]
        direction = int(parts[1])
        src_ip = parts[2]
        dst_ip = parts[3]
        protocol = int(parts[4])
        src_port = parts[5]
        dst_port = parts[6]
        ack_bit = int(parts[7])
        action = int(parts[8])

        # Map fields to human-readable strings
        direction_str = DIRECTION_MAP.get(direction, "UNKNOWN")
        protocol_str = PROTOCOL_MAP.get(protocol, "UNKNOWN")
        ack_bit_str = ACK_BIT_MAP.get(ack_bit, "UNKNOWN")
        action_str = ACTION_MAP.get(action, "UNKNOWN")

        # Format the rule
        formatted_rule = "Name: {:<10} Direction: {:<4} Src IP: {:<15} Dst IP: {:<15} Protocol: {:<5} Src Port: {:<6} Dst Port: {:<6} Ack: {:<3} Action: {}".format(
            name, direction_str, src_ip, dst_ip, protocol_str, src_port, dst_port, ack_bit_str, action_str
        )

        formatted_rules.append(formatted_rule)
    
    return "\n".join(formatted_rules)


def clear_log():
    try:
        with open(sysfs_clr_log_file_path, 'w') as f:
            f.write("{}\n".format(0))
    except FileNotFoundError:
        print("Error: {} not found. Make sure the module is loaded.".format(sysfs_file_path))
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


def show_log(chardev_path='/dev/fw_log'):
    """
    Reads logs from the firewall character device, parses, and prints them.
    """
    if not os.path.exists(chardev_path):
        print("Error: Character device '{}' does not exist.".format(chardev_path))
        return

    try:
        with open(chardev_path, 'r') as f:
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
                src_port = parts[3]
                dst_port = parts[4]
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
    sysfs_path='/sys/class/fw/rules/rules'
    try:
        # Open the file containing rules and read its content
        with open(file_path, 'r') as rules_file:
            rules_content = rules_file.read()
        
        # Open the sysfs device and write the rules
        with open(sysfs_path, 'w') as sysfs_device:
            sysfs_device.write(rules_content)
        
        print("Rules loaded successfully from {} to {}.".format(file_path, sysfs_path))
    except FileNotFoundError:
        print("Error: File '{}' or sysfs device '{}' not found.".format(file_path, sysfs_path))
    except PermissionError:
        print("Error: Permission denied when accessing '{}'. Try running as root.".format(file_path, sysfs_path))
    except Exception as e:
        print("Error: {}".format(e))

def show_rules():
    """
    Reads the content of the sysfs device for rules and prints it to the console.
    :param sysfs_path: Path to the sysfs device to read the rules.
    """
    sysfs_path='/sys/class/fw/rules/rules'
    try:
        # Open the sysfs device and read the content
        with open(sysfs_path, 'r') as sysfs_device:
            rules_content = sysfs_device.read()
        
        print("Current Rules:\n{}".format(format_rules(rules_content)))
    except FileNotFoundError:
        print("Error: Sysfs device '{}' not found.".format(sysfs_path))
    except PermissionError:
        print("Error: Permission denied when accessing '{}'. Try running as root.".format(sysfs_path))
    except Exception as e:
        print("Error: {}".format(e))


def main():
        args = sys.argv
        print(args)
        # Check correct number of arguments
        if len(args) == 3 and args[1] == "load_rules":
            load_rules(args[2])
        # Reset stats
        elif len(args) == 2:
            param = args[1]
            if param == "show_log":
                show_log()
            elif param == "clear_log":
                clear_log()
            elif param == "show_rules":
                show_rules()
        # Read Stats
        else:
            print("Invalid Argument.")

if __name__ == '__main__':
    main()
