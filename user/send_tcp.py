import socket

# Target host and port
target_ip = "10.1.1.1"
target_port = 80  # Replace with the desired target port

# Create a TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Connect to the target
    sock.connect((target_ip, target_port))
    print(f"Connected to {target_ip}:{target_port}")

    # Send some data (e.g., an HTTP GET request or any custom data)
    message = "Hello, this is a test TCP packet!\n"
    sock.sendall(message.encode())
    print(f"Sent message: {message}")

    # Optionally receive a response
    response = sock.recv(1024)
    print(f"Received response: {response.decode()}")
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    # Close the socket
    sock.close()
    print("Connection closed.")
