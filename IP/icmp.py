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
        
    
if __name__ == "__main__":
    icmp = SocketICMP()
    icmp.send_icmp(("8.8.8.8", 0), "Hello ICMP !")