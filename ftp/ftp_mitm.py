import socket
import threading

# Configuration
LISTEN_PORT = 210
FTP_SERVER_HOST = 'real.ftp.server'  # Replace with the actual FTP server IP or hostname
FTP_SERVER_PORT = 21

# Function to handle communication with the actual FTP server
def handle_server_connection(client_socket, server_socket):
    try:
        while True:
            data = server_socket.recv(4096)
            if not data:
                break
            client_socket.sendall(data)
    except Exception as e:
        print("Error handling server connection: ", e)
    finally:
        server_socket.close()
        client_socket.close()

# Function to handle client connections
def handle_client(client_socket):
    try:
        # Connect to the actual FTP server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((FTP_SERVER_HOST, FTP_SERVER_PORT))

        # Forward server's welcome message to the client
        client_socket.sendall(server_socket.recv(4096))

        while True:
            # Receive data from client
            client_data = client_socket.recv(4096)
            if not client_data:
                break

            print("Received from client: ", client_data.decode().strip())

            # Intercept the PORT command
            if client_data.decode().strip().upper().startswith('PORT'):
                print("Intercepted PORT command")
                
                # Forward the command to the real FTP server
                server_socket.sendall(client_data)

                # Wait for the server's response
                server_response = server_socket.recv(4096)

                # Send the server's response back to the client
                client_socket.sendall(server_response)
            else:
                # Forward all other commands to the server
                server_socket.sendall(client_data)

                # Wait for the server's response and forward it to the client
                server_response = server_socket.recv(4096)
                client_socket.sendall(server_response)
    except Exception as e:
        print("Error handling client: ", e)
    finally:
        client_socket.close()

# Main function to set up the MITM server
def main():
    try:
        # Create a socket to listen for incoming FTP connections
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('0.0.0.0', LISTEN_PORT))
        listener.listen(5)

        print("MITM FTP Server listening on port ", LISTEN_PORT)

        while True:
            client_socket, client_address = listener.accept()
            print("Connection accepted from ", client_address)

            # Handle the client in a new thread
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
    except KeyboardInterrupt:
        print("Shutting down MITM FTP server")
    except Exception as e:
        print("Error in main server: ", e)
    finally:
        listener.close()

if __name__ == "__main__":
    main()
