# import socket
# import threading

# # Function to handle the client connection
# def handle_client(client_socket, client_address):
#     print("[+] Connection received from {}".format(client_address))

#     try:
#         # Receive the HTTP request from the client
#         client_data = client_socket.recv(4096).decode()
#         print("[Client Request] {client_data}".format(client_data))

#         # Extract the original destination from the HTTP Host header
#         lines = client_data.split("\r\n")
#         host_line = next((line for line in lines if line.lower().startswith("host:")), None)
#         if not host_line:
#             print("[-] Host header not found!")
#             client_socket.close()
#             return

#         # Get the host and port from the Host header
#         host = host_line.split(":")[1].strip()
#         port = 80

#         if ':' in host:
#             host, port = host.split(':')
#             port = int(port)

#         # Connect to the original HTTP server
#         server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         server_socket.connect((host, port))
#         print("[+] Connected to server {}:{}".format(host, port))

#         # Forward the client's request to the server
#         server_socket.sendall(client_data.encode())

#         # Receive the server's response
#         server_data = server_socket.recv(4096).decode()
#         print("[Server Response] {}".format(server_data))

#         # Send the server's response back to the client
#         client_socket.sendall(server_data.encode())

#     except Exception as e:
#         print("[-] Error: {}".format(e))
#     finally:
#         client_socket.close()
#         print("[+] Connection closed with {}".format(client_address))

# # Main function to set up the MITM listener
# def start_mitm():
#     # Create a listening socket for the client connections
#     mitm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     mitm_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     mitm_socket.bind(("0.0.0.0", 800))  # Listen on port 800 (redirected HTTP traffic)
#     mitm_socket.listen(5)
#     print("[+] MITM HTTP Proxy listening on port 800...")

#     while True:
#         # Accept a new client connection
#         client_socket, client_address = mitm_socket.accept()

#         # Handle the client in a separate thread
#         client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
#         client_handler.start()

# # Run the MITM process
# if __name__ == "__main__":
#     try:
#         start_mitm()
#     except KeyboardInterrupt:
#         print("\n[+] Shutting down MITM...")




import socket
import select
import struct
import sys

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
