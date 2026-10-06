#!/usr/bin/env python3
import http.server
import socketserver
import sys


PORT = 8080

class PacketLoggerHandler(http.server.SimpleHTTPRequestHandler):
    def handle_request(self, method):
        print(f"[PACKET / REQUEST RECEIVED]")
        print(f"Client IP:     {self.client_address[0]}")
        print(f"Client Port:   {self.client_address[1]}")
        print(f"Request Line:  {method} {self.path}")
        print("\nHeaders:")
        for header, value in self.headers.items():
            print(f"  {header}: {value}")
        

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            body = self.rfile.read(content_length)
            print(f"\nBody:\n  {body.decode('utf-8', errors='ignore')}")
 


        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Packet received successfully!\n")


    def do_GET(self):    self.handle_request("GET")
    def do_POST(self):   self.handle_request("POST")
    def do_PUT(self):    self.handle_request("PUT")
    def do_DELETE(self): self.handle_request("DELETE")

   
    def log_message(self, format, *args):
        return

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    
   
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("0.0.0.0", port), PacketLoggerHandler) as httpd:
        print(f"Server listening on all interfaces (0.0.0.0:{port})...")
        print("Press Ctrl+C to stop.\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer shutting down.")