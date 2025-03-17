from IP import SocketIP
from IP import BASE_IP

class SocketUDP(SocketIP):
    def __init__(self, ip: str = BASE_IP):
        print(f" [UDP] Binded on {ip} ")
        super().__init__(ip)
        self.protocol = 0x11
    def build_udp_header(self, source_port: int, destination_port: int, data: str):
        source_port_bytes = source_port.to_bytes(2, byteorder='big')
        destination_port_bytes = destination_port.to_bytes(2, byteorder='big')
        length = 8 + len(data)
        length_bytes = length.to_bytes(2, byteorder='big')
        checksum = 0
        checksum_bytes = checksum.to_bytes(2, byteorder='big')
        packet = source_port_bytes + destination_port_bytes + length_bytes + checksum_bytes + data.encode()
        packet = self.put_checksum(packet, 6, 2)
        return packet
    def send_udp(self, target_address: tuple[str,int], data: str, source_port: int = 12345):
        destination_port = target_address[1]
        udp_header = self.build_udp_header(source_port, destination_port, data)
        self.sendall(target_address, udp_header, self.protocol)

if __name__ == "__main__":
    s = SocketUDP()
    s.send_udp(("127.0.0.1", 8081), "Hello UDP !")
    s.send_udp(("127.0.0.1", 8081), "Hello UDP !")