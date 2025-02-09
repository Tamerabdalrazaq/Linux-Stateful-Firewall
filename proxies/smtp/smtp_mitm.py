import sys
import os
import socket
import threading
sys.path.insert(1, os.path.abspath("../C_detector"))
import analyze_dlp
# Configuration
LISTEN_PORT = 250
FTP_SERVER_PORT = 25
SYSFS_PATH_MITM = "/sys/class/fw/mitm/mitm"
SYSFS_PATH_CONNS = "/sys/class/fw/conns/conns"


def find_destination(ip, port):
    port = str(port)
    try:
        with open(SYSFS_PATH_CONNS, "r") as file:
            lines = file.readlines()
        print("looking for {} in {}".format((ip, port), lines))
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



def write_to_kernel(data_to_write,):
    try:
        with open(SYSFS_PATH_MITM, "w") as sysfs_file:
            sysfs_file.write(data_to_write)
        print("MITM process updated with: {}".format(data_to_write.strip()))
        return 0
    except Exception as e:
        print("Error updating MITM process: {}".format(e))
        return -1

def get_data_command(client_data):
    command = client_data.decode('utf-8')
    print("command: ", command)
    return command.upper().startswith("DATA")

def DLP_verdict(res):
    score = analyze_dlp.get_snippet_score(res)
    print("DLP Score: ", score)
    if score > analyze_dlp.THRESHOLD:
        return True
    return False

def forward_cli_srv(client_socket, server_socket, client_address, server_address):
    while True:
        # Receive data from client
        client_data = client_socket.recv(4096)
        if not client_data:
            break

        print("Received from client: ", client_data.decode().strip())
        server_socket.sendall(client_data)

def forward_srv_cli(server_socket, client_socket):
    while True:
        # Receive data from server
        server_data = server_socket.recv(4096)
        if not server_data:
            break
        print("Received from server: ", server_data.decode().strip())
        # Validate DLP
        if DLP_verdict(server_data.decode()):
            return client_socket.sendall("DLP Prevented".encode())
        client_socket.sendall(server_data)

def handle_client(client_socket, client_address):
    server_socket = None
    try:
        # Connect to the actual FTP server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', 0))
        _, port = server_socket.getsockname()
        write_to_kernel(format_mitm_port_for_kernel(client_address, port))
        server_address = find_destination(client_address[0], client_address[1])
        print("Connecting..", server_address)
        server_socket.connect(server_address)
        print("Connected to server ", server_address)

        # Forward server's welcome message to the client
        client_socket.sendall(server_socket.recv(4096))
        print("Hello sent")

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
