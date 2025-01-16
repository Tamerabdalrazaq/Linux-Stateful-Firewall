from http.server import SimpleHTTPRequestHandler, HTTPServer

class GzipHTTPRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        """Add the Content-Encoding: gzip header before finishing headers."""
        self.send_header("Content-Encoding", "gzip")
        super().end_headers()

# Start the server
def run(server_class=HTTPServer, handler_class=GzipHTTPRequestHandler, port=8000):
    server_address = ("", port)
    httpd = server_class(server_address, handler_class)
    print(f"Serving on port {port} with Content-Encoding: gzip")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
