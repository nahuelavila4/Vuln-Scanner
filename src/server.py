from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl

class HttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.path = "/index.html"
        try:
            file_to_open = open(self.path[1:]).read()
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(bytes(file_to_open, 'utf-8'))
        except Exception as e:
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'404 - Not Found')
        # self.wfile.write(b"Hello, world!")

httpd = HTTPServer(('localhost', 8080), HttpHandler)
print("The server is running...")
httpd.serve_forever()