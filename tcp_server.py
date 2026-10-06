#!/usr/bin/env python3
import socket
import threading
import argparse

HOST = '0.0.0.0'
PORT = 8080
 
 
def handle_client(client_socket, client_address):
    """Serve one client until it disconnects."""
    client = f"{client_address[0]}:{client_address[1]}"
    with client_socket:
        print(f"\n[+] Connection established from {client}")
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:  
                    break
                print(f"    Raw bytes: {data}")
                print(f"    Text content: {data.decode('utf-8', errors='replace').strip()}")
                client_socket.sendall(b"PONG\n")
        except ConnectionError:
            pass  # client reset the connection abruptly
    print(f"[-] {client} disconnected")
 
 
def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"TCP Server listening on {HOST}:{PORT}...")
        while True:
            client_socket, client_address = server_socket.accept()
            threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True,
            ).start()
 
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p", "--port", 
        type=int,            
        default=8080,
    )
    args = parser.parse_args()
    PORT = args.port
    try:
        start_server()
    except KeyboardInterrupt:
        print("\nServer stopped.")
