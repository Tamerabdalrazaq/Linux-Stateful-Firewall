import socket

def start_tcp_server(host='0.0.0.0', port=12345):
    """
    Starts a TCP server that listens for incoming packets.
    
    :param host: IP address to bind to (default: '0.0.0.0' for all interfaces)
    :param port: Port to bind the server to
    """
    # Create a socket object with IPv4 and TCP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Enable reuse of the address (useful for debugging)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        # Bind the socket to the host and port
        server_socket.bind((host, port))
        print(f"Server listening on {host}:{port}")

        # Start listening for incoming connections
        server_socket.listen(5)  # Maximum of 5 queued connections

        while True:
            # Accept a new connection
            client_socket, client_address = server_socket.accept()
            print(f"Connection established with {client_address}")

            # Handle the client connection
            with client_socket:
                while True:
                    # Receive data from the client
                    data = client_socket.recv(1024)  # Buffer size: 1024 bytes
                    if not data:
                        print(f"Connection closed by {client_address}")
                        break
                    
                    # Print the received data
                    print(f"Received from {client_address}: {data.decode('utf-8')}")

                    # Optionally, send a response back
                    client_socket.sendall(b"Message received")
    
    except KeyboardInterrupt:
        print("\nServer shutting down.")
    
    finally:
        # Close the server socket
        server_socket.close()

if __name__ == "__main__":
    start_tcp_server()
