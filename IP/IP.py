import socket


class Socket():
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.mtu = 1500
        self.ip = self.get_own_ip()
    def encapsulate_ip(self, destination: str, data: str):
        ip_version = 0x4
        ihl = 0x5 # For now, we ignore options
        

    def get_own_ip(self):
        hostname = socket.gethostname()
        own_ip = socket.gethostbyname(hostname)
        return own_ip
    

if __name__ == "__main__":
    s = Socket()
    print(s.get_own_ip())