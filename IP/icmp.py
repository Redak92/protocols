import socket
from IP import BASE_IP, SocketIP
import time




class SocketICMP(SocketIP):
    def __init__(self, ip: str = BASE_IP):
        print(f" [ICMP] Binded on {ip} ")
        super().__init__(ip)
        self.protocol = 0x01 # ICMP protocol

    def build_icmp_header(self, icmp_type: int, icmp_code: int, data: str):
        icmp_type_bytes = icmp_type.to_bytes(1, byteorder='big')
        icmp_code_bytes = icmp_code.to_bytes(1, byteorder='big')
        checksum = 0
        checksum_bytes = checksum.to_bytes(2, byteorder='big')
        identifier = (1).to_bytes(2, byteorder='big')
        sequence_number = (1).to_bytes(2, byteorder='big')
        data_bytes = data.encode()
        packet = icmp_type_bytes + icmp_code_bytes + checksum_bytes + identifier + sequence_number + data_bytes
        packet = self.put_checksum(packet, 2, 2)
        return packet
    def send_icmp(self, target_address: tuple[str,int], data: str, icmp_type: int = 8, icmp_code: int = 0):
        icmp_header = self.build_icmp_header(icmp_type, icmp_code, data)
        self.sendall(target_address, icmp_header, self.protocol)
        
    def receive_icmp(self):
        # Create a raw socket to listen for ICMP packets
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
            s.bind((self.ip, 0))  # Bind to the IP address for listening

            print("Listening for ICMP packets...")
            while True:
                packet, addr = s.recvfrom(1024)  # Receive ICMP packets
                print(f"Received packet from {addr}")

                # Parse the ICMP header
                icmp_type = packet[20]  # ICMP type is at byte 20
                icmp_code = packet[21]  # ICMP code is at byte 21

                # If the packet is an Echo Request (Type 8), send an Echo Reply (Type 0)
                if icmp_type == 8:  # ICMP Echo Request
                    print("ICMP Echo Request received, sending Echo Reply...")
                    self.send_icmp(addr, "Pong", icmp_type=0, icmp_code=0)

                    
if __name__ == "__main__":
    s = SocketICMP()
    s.receive_icmp()