import socket
import threading
import select

# Configuration
LISTEN_PORT = 210
FTP_SERVER_HOST = '10.1.2.2'  # Replace with the actual FTP server IP or hostname
FTP_SERVER_PORT = 21
FTP_SERVER_PORT_ACTIVE = 20
SYSFS_PATH_MITM = "/sys/class/fw/mitm/mitm"
SYSFS_PATH_CONNS = "/sys/class/fw/conns/conns"


def find_destination(ip, port):
    try:
        with open(SYSFS_PATH_CONNS, "r") as file:
            lines = file.readlines()

        # Process each line and print the formatted table
        for line in lines:
            # Strip whitespace and split by commas
            print(line)
            parts = line.strip().split(",")
            src_ip, src_port, dst_ip, dst_port, MITM_proc, state = parts
            if src_ip == ip and src_port == port:
                return ((dst_ip, int(dst_port)))
            if dst_ip == ip and dst_port == port:
                return ((src_ip, int(src_port)))
        print("ERROR - Connection not found")
    except Exception as e:
        print(e)

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
    try:
        with open(SYSFS_PATH_MITM, "w") as sysfs_file:
            sysfs_file.write(data_to_write)
        print("MITM process updated with: {}".format(data_to_write.strip()))
        return 0
    except Exception as e:
        print("Error updating MITM process: {}".format(e))
        return -1

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
    return write_to_kernel(format_new_conn_for_kernel(cli_addr, srv_addr))


def forward_cli_srv(client_socket, server_socket, client_address, server_address):
    while True:
        # Receive data from client
        client_data = client_socket.recv(4096)
        if not client_data:
            break

        print("Received from client: ", client_data.decode().strip())
            # Check if the command is a PORT command
        port = get_port_command(client_data)
        if(port):
            ret = open_active_connection(server_address, (client_address[0], port))
            if ret < 0:
                error_message = "425 Can't open data connection\r\n"
                client_socket.sendall(error_message.encode())
                continue

        server_socket.sendall(client_data)

def forward_srv_cli(client_socket, server_socket):
    while True:
        # Receive data from client
        client_data = client_socket.recv(4096)
        if not client_data:
            break
        print("Received from server: ", client_data.decode().strip())
            # Check if the command is a PORT command
        server_socket.sendall(client_data)

def handle_client(client_socket, client_address):
    server_socket = None
    try:
        # Connect to the actual FTP server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', 0))
        _, port = server_socket.getsockname()
        write_to_kernel(format_mitm_port_for_kernel(client_address, port))
        server_address = find_destination(client_address[0], client_address[1])
        server_socket.connect(server_address)

        # Forward server's welcome message to the client
        client_socket.sendall(server_socket.recv(4096))

        client_to_server_thread = threading.Thread(
            target=forward_cli_srv, 
            args=(client_socket, server_socket, client_address, server_address)
        )
        server_to_client_thread = threading.Thread(
            target=forward_srv_cli, 
            args=(server_socket, client_socket)
        )

        client_to_server_thread.start()
        server_to_client_thread.start()

        client_to_server_thread.join()
        server_to_client_thread.join()

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
