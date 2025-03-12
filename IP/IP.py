import socket


class Socket():
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    def encapsulate_ip(self):
        pass

    def get_own_ip(self):
        hostname = socket.gethostname()
        own_ip = socket.gethostbyname(hostname)
        return own_ip
    

if __name__ == "__main__":
    s = Socket()
    print(s.get_own_ip())