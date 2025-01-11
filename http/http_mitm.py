import socket
import select
import struct
import sys

# Placeholder for inspecting HTTP packets
def inspect_packet(http_packet):
    # This is a trivial implementation; you can replace it with your actual inspection logic
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
            print("Accepted connection from {}".format(client_addr))

            try:
                data = client_sock.recv(4096)  # Read the HTTP packet

                if not data:
                    continue

                # Inspect the HTTP packet
                if inspect_packet(data):
                    print("Packet passed inspection.")

                    # Retrieve original destination from connection table (stub for now)
                    original_dest = get_original_destination()  # This should query your sysfs device

                    if original_dest:
                        # Forward to the original destination
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


def get_original_destination():
    """
    Stub function to retrieve the original destination IP and port from the connection table.
    Replace this with the actual implementation using your existing sysfs device and Python function.

    :return: Tuple (original_ip, original_port)
    """
    # For testing purposes, we'll return a dummy value
    return ("127.0.0.1", 8080)


if __name__ == "__main__":
    try:
        listen_port = 800
        start_mitm_server(listen_port)
    except KeyboardInterrupt:
        print("Server shutting down.")
        sys.exit(0)
