import socket
from IP import SocketMain
def receive_packet():
    # Create a raw socket to capture incoming IP packets
    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    recv_socket.bind(("0.0.0.0", 0))  # Listen on all interfaces

    print("Listening for incoming packets...")
    
    while True:
        packet, addr = recv_socket.recvfrom(65535)  # Receive a packet
        print(f"Packet received from {addr}: {packet.hex()}")
        header = packet[:20]
        print(f"Header: {header.hex()}")
        # Extract the source and destination IP addresses from the IP header
        source_ip = ".".join(map(str, header[12:16]))
        destination_ip = ".".join(map(str, header[16:20]))
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        #show data
        data = packet[20:]
        print(f"Data: {data.decode()}")

        print(SocketMain.checksum(header))
if __name__ == "__main__":
    receive_packet()
