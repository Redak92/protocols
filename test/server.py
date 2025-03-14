import socket
import struct

def print_packet(packet: bytes):
    # Here, we'll simply display the raw packet in hexadecimal format
    print("Received packet:")
    print(" ".join(f"{byte:02x}" for byte in packet))

def tcp_server(host: str, port: int):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"Server listening on {host}:{port}...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")

        # Receive the data in chunks
        while True:
            packet = client_socket.recv(4096)
            if not packet:
                break
            print_packet(packet)

        client_socket.close()

if __name__ == "__main__":
    tcp_server("127.0.0.1", 12345)
