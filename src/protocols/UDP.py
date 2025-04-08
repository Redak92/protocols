from scapy.all import UDP, Raw, send, IP
from IP import IPSocket

class UDPSocket(IPSocket):
    def __init__(self, src_ip=None, src_port=0):
        super().__init__(src_ip)
        self.src_port = src_port
        self.protocol = 17

    def encapsulate_udp(self, destination: str, dest_port: int, data: bytes):
        total_length = len(data) + 8
        packet = UDP(
            sport=self.src_port,
            dport=dest_port,
            len=total_length,
            chksum=0
        ) / Raw(load=data)
        
        #Pseudo header calculation
        pseudo_header = self.pseudo_header(self.src_ip, destination, self.protocol, total_length)
        checksum_value = self.checksum(pseudo_header + bytes(packet))
        packet.chksum = checksum_value
        return packet
    

    

    def send_udp(self, destination: str, dest_port: int, data: bytes):
        packet = self.encapsulate_udp(destination, dest_port, data)
        self.send_ip(destination, bytes(packet), self.protocol)

    def receive_udp(self, interface: str = "lo"):
        self.start_receiver(interface)

        while True:
            if interface == "lo":
                self.packet_queue.get()
            packet = self.packet_queue.get()
            if UDP in packet and packet[UDP].dport == self.src_port:
                data = bytes(packet[UDP].payload)
                yield data, (packet[UDP].sport, packet[IP].src)


if __name__ == "__main__":
    if input("Start receiver? (y/n): ").lower() == 'y':
        s = UDPSocket("127.0.0.1", 12345)
        for data, addr in s.receive_udp("lo"):
            print(f"Received from {addr}: {data}")
    else:
        s = UDPSocket("127.0.0.1", 8081)
        s.send_udp("127.0.0.1", 12345, b"Hello, UDP!")