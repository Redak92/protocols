import socket


class Socket():
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.mtu = 1500
        self.ip = self.get_own_ip()
        self.packet_number = 0
        self.ttl = 8
    def encapsulate_ip(self, destination: str, data: str, protocol: int):
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
        
    def get_own_ip(self):
        hostname = socket.gethostname()
        own_ip = socket.gethostbyname(hostname)
        return own_ip
    

if __name__ == "__main__":
    s = Socket()
    print(s.get_own_ip())