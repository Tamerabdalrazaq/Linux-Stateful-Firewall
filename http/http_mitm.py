import socket
import select
import struct
import sys

SYSFS_PATH_CONNS = "/sys/class/fw/conns/conns"
SYSFS_PATH_MITM = "/sys/class/fw/mitm/mitm"



def get_error_respons(reason):
        return  "HTTP/1.1 400 Bad Request\r\n" \
                    "Content-Type: text/plain\r\n" \
                    "Content-Length: {}\r\n" \
                    "Connection: close\r\n" \
                    "\r\n" \
                    "{}".format(len(reason),reason)
            


def find_destination(ip, port):
    try:
        # Read the file content
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
    except FileNotFoundError:
        print("Error: The sysfs device {} does not exist.".format(SYSFS_PATH_CONNS))
    except PermissionError:
        print("Error: Permission denied to read {}.".format(SYSFS_PATH_CONNS))
    except Exception as e:
        print("Error: An unexpected error occurred: {}".format(e))



def read_http_request(sock):
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        # Break if the headers are fully read
        if b"\r\n\r\n" in data:
            break
    print("\n@@@@@@@@@ received from client: ")
    print(data.decode())
    return data

#block any HTTP response with content length greater than 100KB (102400 bytes) OR when content is encoded with GZIP
def inspect_packet(http_packet):
    try:
        # Decode the received data to a readable format
        http_request = http_packet.decode('utf-8')
        
        # Print the GET request with all headers
        print("Received HTTP Request:")
        print(http_request)
        
        # Check headers for content length and encoding
        headers = http_request.split("\r\n")
        
        content_length = None
        content_encoding = None

        for header in headers:
            if header.lower().startswith("content-length:"):
                content_length = int(header.split(":")[1].strip())
            elif header.lower().startswith("content-encoding:"):
                content_encoding = header.split(":")[1].strip().lower()

        # Block response based on criteria
        if (content_length is not None and content_length > 102400):
            reason = ("Blocking HTTP response: Content-Length is greater than 100KB")
            return (False, reason)  # Block the packet
        if (content_encoding == "gzip"):
            reason = ("Blocking HTTP response: Content-Encoding is GZIP.")
            return (False, reason)  # Block the packet


        return (True, "")
    except Exception as e:
        print("Failed to decode HTTP request: {}".format(e))
        return (False, e)

    # Allow the packet if it doesn't meet the block criteria


def update_mitm_process(client_address, mitm_port):
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


def forward_to_destination(client_address, original_dest, packet):
    """
    Forwards the inspected HTTP packet to the original destination.

    :param original_dest: Tuple (original_ip, original_port)
    :param packet: The inspected HTTP packet
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_sock:
            forward_sock.bind(('0.0.0.0', 0))
            _, port = forward_sock.getsockname()
            update_mitm_process(client_address, port)
            print("local socket is at port ", port)
            forward_sock.connect(original_dest)
            forward_sock.sendall(packet)
            response = read_http_request(forward_sock)
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
                data = read_http_request(client_sock) # Read the HTTP packet

                if not data:
                    continue
                    # Retrieve original destination from connection table (stub for now)
                original_dest = find_destination(cli_ip, cli_port)  # This should query your sysfs device


                if original_dest:
                    # Forward to the original destination
                    print("forwarding to: {}", original_dest)
                    response = forward_to_destination(client_addr, original_dest, data)

                    if response:
                        verdict, reason = inspect_packet(response)
                        # Send the response back to the client
                        if verdict:
                            client_sock.sendall(response)
                        else:
                            print("HTTP Response Did Not Pass Inspection: \n", reason)
                            client_sock.sendall(get_error_respons(reason).encode())
                    else:
                        print("Failed to receive response from the original destination.")
                else:
                    print("Original destination not found.")
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
