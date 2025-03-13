import socket


class Socket():
    def __init__(self):
        #self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.mtu = 1500
        self.ip = self.get_own_ip()
        self.packet_number = 0
        self.ttl = 8
    def encapsulate_ip(self, destination: str, data: str, protocol: int):
        #collecting different informations about the ip header
        ip_version = 0x4
        ihl = 0x5 # For now, we ignore options
        dscp = 0x0  # Low priority DSCP 
        data = data.encode()
        total_length = len(data) + 4 * ihl
        total_length_bytes = total_length.to_bytes(2, byteorder='big')
        identification = self.packet_number.to_bytes(2, byteorder='big')
        self.packet_number += 1
        if self.packet_number > 65535:
            self.packet_number = 0
        number_of_packets = (total_length + self.mtu - 1) // self.mtu
        protocol = protocol.to_bytes(1, byteorder='big')
        source_ip = self.sparse_ip(self.ip)
        destination_ip = self.sparse_ip(destination)
        #Building the ip header
        ip_header = [(ip_version << 4 | ihl).to_bytes(1, byteorder='big')]
        ip_header.append((dscp << 2).to_bytes(1, byteorder='big'))
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
    @staticmethod
    def set_checksum(header: bytes)
    def print_hex(self, data: bytes):
        print(" ".join(f"{byte:02x}" for byte in data))
    def sparse_ip(self, ip: str) -> bytes:
        return b''.join(map(lambda x: int(x).to_bytes(1, "big"), ip.split('.')))
    def get_own_ip(self):
        hostname = socket.gethostname()
        own_ip = socket.gethostbyname(hostname)
        return own_ip
    

if __name__ == "__main__":
    s = Socket()
    s.encapsulate_ip("192.168.0.1", "Hell", 6)



    