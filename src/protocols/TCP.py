from IP import IPSocket
from scapy.all import TCP, Raw, send, IP
import time
import random

class TCPSocket(IPSocket):
    def __init__(self, src_ip=None, src_port=0):
        super().__init__(src_ip)
        self.src_port = src_port
        self.protocol = 6
        self.seq_num = 0
        self.ack_num = 0
        self.window_size = 65160

    def encapsulate_tcp(self, dest_port: int, sequence_number: int, ack: int, flags: str, data: bytes, options: list = None):
        source_port = self.src_port
        dest_port = dest_port
        sequence_number = sequence_number
        ack_number = ack
        reserved = 0
        flags = flags
        window_size = self.window_size
        urgent_pointer = 0
        packet = TCP(
            sport=source_port,
            dport=dest_port,
            seq=sequence_number,
            ack=ack_number,
            reserved=reserved,
            flags=flags,
            window=window_size,
            urgptr=urgent_pointer,
            options=options
        ) / Raw(load=data)

        return packet
    
    def send_tcp(self, destination: str, dest_port: int, sequence_number:int, ack_number:int,  data: bytes, flags: str, options: list = None):
        packet = self.encapsulate_tcp(dest_port, sequence_number, ack_number, flags, data, options)
        send(IP(dst=destination, src = self.src_ip) / packet, verbose=False)
        return
    
    def handshake(self, ip: str, port: int, handshake_options = None):
        if handshake_options is None:
            handshake_options = [
                ('MSS', 1460),
                ('SAckOK', b''),
                ('Timestamp', (self.get_time(),0)),
                ('NOP', None),
                ('WScale', 7)
            ]
        seq = random.randint(0, 34000)
        ack = 0
        data = b""
        flags = "S"
        
        self.start_receiver("veth0", filtre=f"tcp and port {self.src_port}", lfilter= lambda packet: packet[TCP].flags == "SA", number_of_packets=1)
        self.send_tcp(ip, port, seq, ack, data, flags, handshake_options)
        synack = self.get_packet()[TCP]
        while synack is None:
        
            synack = self.get_packet()[TCP]
           
        synack.show()
        if synack.ack != seq + 1:
            print("No good ack from SYNACK")
            return
        ack_options = [('NOP', None),('NOP', None), ('Timestamp', (self.get_time(), self.get_ts(synack.options)[0]))]
        self.send_tcp(ip, port, seq + 1, synack.seq + 1, b"", "A", options=ack_options)

    def get_time(self):
        return int(time.time())
    def get_ts(self, tuple):
        for i in tuple:
            if i[0] == "Timestamp":
                return i[1]
        return 0
if __name__ == "__main__":
    if input("Want to start listening ?") == "y":
        s = TCPSocket("192.168.10.2", 8080)
        s.listen_tcp("veth1")
    else:
        s = TCPSocket("192.168.10.1", 12345)
        s.handshake("192.168.10.2", 8080)


        

        
    