import socket
import threading

# Placeholder function to communicate with kernel drivers
def communicate_with_kernel(port_command):
    print("[Kernel Driver] Received PORT command: ",port_command)

# Handle client commands
def handle_client(client_socket):
    client_socket.send(b"220 Simple FTP Server\r\n")

    while True:
        command = client_socket.recv(1024).decode('utf-8').strip()

        if command.startswith("USER"):
            client_socket.send(b"331 Password required\r\n")

        elif command.startswith("PASS"):
            client_socket.send(b"230 Login successful\r\n")

        elif command.startswith("PORT"):
            # Extract and print the PORT command details
            communicate_with_kernel(command)
            client_socket.send(b"200 Command okay\r\n")

        elif command.startswith("QUIT"):
            client_socket.send(b"221 Goodbye\r\n")
            break

        else:
            client_socket.send(b"502 Command not implemented\r\n")

    client_socket.close()

# Main FTP server
def start_ftp_server(host='0.0.0.0', port=210):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print("[INFO] FTP Server running on {}:{}".format(host, port))

    while True:
        client_socket, client_address = server.accept()
        print("[INFO] New connection from {}".format(client_address))

        # Handle client in a separate thread
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_ftp_server()
