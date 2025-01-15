import socket
import threading

# Configuration
LISTEN_PORT = 210
FTP_SERVER_HOST = '10.1.2.2'  # Replace with the actual FTP server IP or hostname
FTP_SERVER_PORT = 21
SYSFS_PATH_MITM = "/sys/class/fw/mitm/mitm"

def update_mitm_process(client_address, mitm_port="0"):
    """
    Updates the MITM process by writing the relevant data to the sysfs device.

    :param client_address: Tuple (client_ip, client_port) from the accepted client socket
    :param mitm_port: The port of the current MITM process
    """
    try:
        client_ip, client_port = client_address
        data_to_write = "{},{},{}\n".format(client_ip, client_port, mitm_port)
        with open(SYSFS_PATH_MITM, "w") as sysfs_file:
            sysfs_file.write(data_to_write)
        print("MITM process updated with: {}".format(data_to_write.strip()))
    except Exception as e:
        print("Error updating MITM process: {}".format(e))

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
def handle_client(client_socket, client_address):
    server_socket = None
    try:
        # Connect to the actual FTP server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _, port = server_socket.getsockname()
        update_mitm_process(client_address, port)
        server_socket.connect((FTP_SERVER_HOST, FTP_SERVER_PORT))

        # Forward server's welcome message to the client
        client_socket.sendall(server_socket.recv(4096))

        while True:
            # Receive data from client
            client_data = client_socket.recv(4096)
            if not client_data:
                break

            print("Received from client: ", client_data.decode().strip())

            # Forward all commands to the real server
            server_socket.sendall(client_data)

            # Wait for the server's response and forward it to the client
            server_response = server_socket.recv(4096)
            client_socket.sendall(server_response)
    except Exception as e:
        print("Error handling client: ", e)
    finally:
        if server_socket:
            server_socket.close()
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
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
    except KeyboardInterrupt:
        print("Shutting down MITM FTP server")
    except Exception as e:
        print("Error in main server: ", e)
    finally:
        listener.close()

if __name__ == "__main__":
    main()
