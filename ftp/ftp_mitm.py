import socket
import threading
import select

# Configuration
LISTEN_PORT = 210
FTP_SERVER_HOST = '10.1.2.2'  # Replace with the actual FTP server IP or hostname
FTP_SERVER_PORT = 21
FTP_SERVER_PORT_ACTIVE = 20
SYSFS_PATH_MITM = "/sys/class/fw/mitm/mitm"

def format_mitm_port_for_kernel(client_address, mitm_port):
        client_ip, client_port = client_address
        data_to_write = "{},{},{}\n".format(client_ip, client_port, mitm_port)
        return data_to_write

def format_new_conn_for_kernel(cli_addr, srv_addr):
        cli_ip, cli_port = cli_addr
        srv_ip, srv_port = srv_addr
        data_to_write = "#{},{},{},{}\n".format(cli_ip, cli_port, srv_ip, srv_port)
        return data_to_write



def write_to_kernel(data_to_write,):
    """
    Updates the MITM process by writing the relevant data to the sysfs device.

    :param client_address: Tuple (client_ip, client_port) from the accepted client socket
    :param mitm_port: The port of the current MITM process
    """
    try:
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

def get_port_command(client_data):
    command = client_data.decode('utf-8')
    print("command: ", command)
    if command.upper().startswith("PORT"):
        try:
            # Extract the arguments after the "PORT" command
            args = command[5:].strip().split(",")
            if len(args) == 6:
                # Parse the IP address and port numbers
                ip_address = ".".join(args[:4])
                p1, p2 = int(args[4]), int(args[5])
                port = (p1 * 256) + p2

                # Print the extracted IP and port
                print("PORT command received. IP: {}, Port: {}".format(ip_address, port))
                return port
            else:
                print("Invalid PORT command format.")
                return None
        except Exception as e:
            print("Error parsing PORT command.\n", e)
            return None


def open_active_connection(srv_addr, cli_addr):
    write_to_kernel(format_new_conn_for_kernel(cli_addr, srv_addr))

def handle_client(client_socket, client_address):
    server_socket = None
    try:
        # Connect to the actual FTP server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((FTP_SERVER_HOST, FTP_SERVER_PORT))

        # Forward server's welcome message to the client
        client_socket.sendall(server_socket.recv(4096))

        while True:
            # Use select to monitor both sockets for incoming data
            readable, _, _ = select.select([client_socket, server_socket], [], [])

            if client_socket in readable:
                # Receive data from client
                client_data = client_socket.recv(4096)
                if not client_data:  # Client closed the connection
                    break

                print("Received from client: ", client_data.decode(errors='ignore').strip())

                # Forward all commands to the real server
                server_socket.sendall(client_data)

            if server_socket in readable:
                # Receive unsolicited or response data from server
                server_data = server_socket.recv(4096)
                if not server_data:  # Server closed the connection
                    break

                print("Received from server: ", server_data.decode(errors='ignore').strip())

                # Forward server's response or unsolicited data to the client
                client_socket.sendall(server_data)

    except Exception as e:
        print("Error handling client: ", e)
    finally:
        if server_socket:
            server_socket.close()
        client_socket.close()
        print("Closed connection with ",client_address)

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
