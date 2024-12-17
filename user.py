import os
import time
from datetime import datetime, timedelta
import sys

# Path to the sysfs file for the sysfs attribute
sysfs_file_path = '/sys/class/Sysfs_class/sysfs_class_sysfs_Device/sysfs_att'

def read_sysfs():
    try:
        with open(sysfs_file_path, 'r') as f:
            value = f.read().strip()
            print(value)  
    except FileNotFoundError:
        print("Error: {} not found. Make sure the module is loaded.".format(sysfs_file_path))
    except Exception as e:
        print("Error reading from sysfs: {}".format(e))

def write_sysfs():
    try:
        with open(sysfs_file_path, 'w') as f:
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

def show_log():
    """
    Reads logs from the firewall character device, parses, and prints them.
    """
    chardev_path='/dev/fw_log'
    if not os.path.exists(chardev_path):
        print(f"Error: Character device '{chardev_path}' does not exist.")
        return

    try:
        with open(chardev_path, 'r') as f:
            print("Reading firewall logs...")
            print("{:<20} {:<15} {:<15} {:<10} {:<10} {:<8} {:<8} {:<15} {:<5}".format(
                "Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Action", "Reason", "Count"
            ))
            print("=" * 100)

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
                protocol = parts[5]
                action = parts[6]
                reason = parts[7]
                count = parts[8]

                # Convert jiffies to human-readable timestamp
                timestamp = jiffies_to_date(jiffies).strftime('%d/%m/%Y %H:%M:%S')

                print("{:<20} {:<15} {:<15} {:<10} {:<10} {:<8} {:<8} {:<15} {:<5}".format(
                    timestamp, src_ip, dst_ip, src_port, dst_port, protocol, action, reason, count
                ))
    except Exception as e:
        print(f"Error reading character device: {e}")

def main():
        args = sys.argv
        print(args)
        # Check correct number of arguments
        if len(args) > 2:
            return sys.exit("Error: Invalid Input")
        # Reset stats
        elif len(args) == 2:
            param = args[1]
            if param == "show_log":
                show_log()
        # Read Stats
        else:
            read_sysfs()

if __name__ == '__main__':
    main()
