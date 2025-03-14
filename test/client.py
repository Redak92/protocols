import socket
import struct

def print_packet(packet: bytes):
    # Here, we'll simply display the raw packet in hexadecimal format
    print("Sent packet:")
    print(" ".join(f"{byte:02x}" for byte in packet))

def tcp_client(host: str, port: int):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    message = "Hello, this is a test message from the client!"
    client_socket.send(message.encode())

    print_packet(message.encode())

    client_socket.close()

if __name__ == "__main__":
    tcp_client("127.0.0.1", 12345)
