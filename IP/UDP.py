from IP import SocketIP
from IP import BASE_IP


class SocketUDP(SocketIP):
    def __init__(self, ip: str = BASE_IP):
        print(f" [UDP] Binded on {ip} ")
        super().__init__(ip)
        self.protocol = 0x11
    def build_udp_header(self, source_port: int, destination_port: int, data: bytes):
        source_port_bytes = source_port.to_bytes(2, byteorder='big')
        destination_port_bytes = destination_port.to_bytes(2, byteorder='big')
        length = 8 + len(data)
        length_bytes = length.to_bytes(2, byteorder='big')
        checksum = 0
        checksum_bytes = checksum.to_bytes(2, byteorder='big')
        packet = source_port_bytes + destination_port_bytes + length_bytes + checksum_bytes + data
        packet = self.put_checksum(packet, 6, 2)
        return packet
    def send_udp(self, target_address: tuple[str,int], data: bytes, source_port: int = 12345):
        destination_port = target_address[1]
        udp_header = self.build_udp_header(source_port, destination_port, data)
        self.sendall(target_address, udp_header, self.protocol)
    def receive_udp(self, port: int = 53, max=65535, verbose = False):
        print("Listening for incoming packets...")
        while True:
            packet, _ = self.reicv_socket.recvfrom(max)
            source_ip, destination_ip, data = self.decapsulate_ip(packet)
            source_port = int.from_bytes(data[0:2], byteorder='big')
            destination_port = int.from_bytes(data[2:4], byteorder='big')
            length = int.from_bytes(data[4:6], byteorder='big')
            if length > max:
                print("Packet too large")
                continue
            #We ignore checksum
            data = data[8:]
            if destination_port == port:
                if verbose:
                    print("Listening for incoming packets...")
                    print("Destination ip : ", destination_ip)
                    print(f"Packet received from {source_ip} on port {source_port} : {data}")
                    print(f"Destination port : {destination_port}")
            

if __name__ == "__main__":
    s = SocketUDP("127.0.0.1")
    s.receive_udp(8081, 65000, True)
