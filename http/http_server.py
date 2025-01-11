import http.server
import socketserver

# Define the port to serve on
PORT = 8000

# Handler for HTTP requests
Handler = http.server.SimpleHTTPRequestHandler

# Create a server
httpd = socketserver.TCPServer(("", PORT), Handler)

print(f"Serving HTTP on port {PORT}")
try:
    # Serve forever
    httpd.serve_forever()
except KeyboardInterrupt:
    print("\nShutting down server.")
    httpd.server_close()