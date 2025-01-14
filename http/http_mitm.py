import socket
import select
import struct
import sys

SYSFS_PATH_CONNS = "/sys/class/fw/conns/conns"

def find_destination(ip, port):
    try:
        # Read the file content
        with open(SYSFS_PATH_CONNS, "r") as file:
            lines = file.readlines()

        # Process each line and print the formatted table
        for line in lines:
            # Strip whitespace and split by commas
            parts = line.strip().split(",")
            src_ip, src_port, dst_ip, dst_port, state = parts
            if src_ip == ip and src_port == port:
                return ((dst_ip, int(dst_port)))
            if dst_ip == ip and dst_port == port:
                return ((src_ip, int(src_port)))
        print("ERROR - Connection not found")

    
    except FileNotFoundError:
        print("Error: The sysfs device {} does not exist.".format(SYSFS_PATH_CONNS))
    except PermissionError:
        print("Error: Permission denied to read {}.".format(SYSFS_PATH_CONNS))
    except Exception as e:
        print("Error: An unexpected error occurred: {}".format(e))




# Placeholder for inspecting HTTP packets
def inspect_packet(http_packet):
    try:
    # Decode the received data to a readable format
        http_request = http_packet.decode('utf-8')
        
        # Print the GET request with all headers
        print("Received HTTP Request:")
        print(http_request)
    except UnicodeDecodeError as e:
        print("Failed to decode HTTP request: {}".format(e))
    return True

def forward_to_destination(original_dest, packet):
    """
    Forwards the inspected HTTP packet to the original destination.

    :param original_dest: Tuple (original_ip, original_port)
    :param packet: The inspected HTTP packet
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_sock:
            forward_sock.connect(original_dest)
            forward_sock.sendall(packet)
            response = forward_sock.recv(4096)
        return response
    except Exception as e:
        print("Error forwarding to destination: {}".format(e))
        return None


def start_mitm_server(listen_port):
    """
    Starts the MITM server to intercept and inspect HTTP packets.

    :param listen_port: The port on which the MITM server listens (e.g., 800 for HTTP)
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("0.0.0.0", listen_port))
        server_sock.listen(5)

        print("MITM Server listening on port {}...".format(listen_port))

        while True:
            client_sock, client_addr = server_sock.accept()
            cli_ip, cli_port = client_addr
            cli_port = str(cli_port)
            print("Accepted connection from {}".format(client_addr))

            try:
                data = client_sock.recv(4096)  # Read the HTTP packet

                if not data:
                    continue

                # Inspect the HTTP packet
                if inspect_packet(data):
                    print("Packet passed inspection.")

                    # Retrieve original destination from connection table (stub for now)
                    original_dest = find_destination(cli_ip, cli_port)  # This should query your sysfs device


                    if original_dest:
                        # Forward to the original destination
                        print("forwarding to: {}", original_dest)
                        response = forward_to_destination(original_dest, data)

                        if response:
                            # Send the response back to the client
                            client_sock.sendall(response)
                        else:
                            print("Failed to receive response from the original destination.")
                    else:
                        print("Original destination not found.")
                else:
                    print("Packet failed inspection. Dropping.")

            except Exception as e:
                print("Error handling connection: {}".format(e))
            finally:
                client_sock.close()



if __name__ == "__main__":
    try:
        listen_port = 800
        start_mitm_server(listen_port)
    except KeyboardInterrupt:
        print("Server shutting down.")
        sys.exit(0)
