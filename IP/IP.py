import socket
import struct


class SocketMain():
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.mtu = 1500
        self.ip = self.get_own_ip()
        self.packet_number = 0
        self.ttl = 8
    def encapsulate_ip(self, destination: str, data: str, protocol: int):
        #collecting different informations about the ip header
        ip_version = 0x4
        ihl = 0x5 # For now, we ignore options
        dscp = 0x0  # Low priority DSCP 
        total_length = len(data) + 4 * ihl
        total_length_bytes = total_length.to_bytes(2, byteorder='big')
        identification = self.packet_number.to_bytes(2, byteorder='big')
        self.packet_number = self.packet_number % 65535 + 1
        self.packet_number += 1
        if self.packet_number > 65535:
            self.packet_number = 0
        number_of_packets = (total_length + self.mtu - 1) // self.mtu
        protocol = protocol.to_bytes(1, byteorder='big')
        source_ip = self.sparse_ip(self.ip)
        destination_ip = self.sparse_ip(destination)
        #Building the ip header
        ip_header = [(ip_version << 4 | ihl).to_bytes(1, byteorder='big')]
        ip_header.append((dscp << 2 | 0b00).to_bytes(1, byteorder='big'))
        ip_header.append(total_length_bytes)
        ip_header.append(identification)
        #Here it changes
        if number_of_packets == 1:
            flags = 0x2
            frag_offset = 0x0
            fpluso = (flags << 13 | frag_offset).to_bytes(2, byteorder='big')
            ip_header.append(fpluso)
            ip_header.append(self.ttl.to_bytes(1, byteorder='big'))
            ip_header.append(protocol)
            #Adding void checksum
            ip_header.append(b'\x00\x00')
            ip_header.append(source_ip)
            ip_header.append(destination_ip)
            ip_header = b''.join(ip_header)
            ip_header = self.put_checksum(ip_header)
            return ip_header + data.encode()
        else:
            raise NotImplementedError("Fragmentation is not implemented yet")
        
    def send_packet(self, address: tuple[str, int], packet: bytes):
        self.socket.sendto(packet, address)
        print("Packet sent : ", packet.hex())
    @staticmethod
    def checksum(header: bytes) -> int:
        if len(header) % 2 == 1:
            header += b'\x00'
        
        total = 0
        for i in range(0, len(header), 2):
            word = struct.unpack("!H", header[i:i+2])[0]
            total += word
        while total > 0xFFFF:
            total = (total & 0xFFFF) + (total >> 16)
        return ~total & 0xFFFF
    def put_checksum(self, header: bytes) -> bytes:
        checksum = self.checksum(header)
        return header[:10] + checksum.to_bytes(2, byteorder='big') + header[12:]
    def print_hex(self, data: bytes):
        print(" ".join(f"{byte:02x}" for byte in data))
    def sparse_ip(self, ip: str) -> bytes:
        return b''.join(map(lambda x: int(x).to_bytes(1, "big"), ip.split('.')))
    def get_own_ip(self):
        return "127.0.0.1"
        hostname = socket.gethostname()
        own_ip = socket.gethostbyname(hostname)
        return own_ip
    
    

if __name__ == "__main__":
    s = SocketMain()
    s.send_packet(("127.0.0.1", 12345), s.encapsulate_ip("127.0.0.1", "Hell", 255))
 


