import random
from IP import IPSocket
from scapy.all import TCP, Raw, send, IP
import time


class TCPSocket(IPSocket):
    def __init__(self, src_ip=None, src_port=0):
        super().__init__(src_ip)
        self.src_port = src_port
        self.protocol = 6
        self.seq_num = 0
        self.ack_num = 0
        self.window_size = 65495

    def encapsulate_tcp(self, dest_port: int, sequence_number: int, ack: int, flags: str, data: bytes):
        source_port = self.src_port
        dest_port = dest_port
        sequence_number = sequence_number
        ack_number = ack
        reserved = 0
        flags = flags
        window_size = self.window_size
        urgent_pointer = 0
        options = [
            ('MSS', 65495),
            ('SAckOK', b''),
            ('Timestamp', (int(time.time() / 10),0)),
            ('NOP', None),
            ('WScale', 7)
        ]
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
    
    def send_tcp(self, destination: str, dest_port: int, sequence_number:int, ack_number:int,  data: bytes, flags: str):
        packet = self.encapsulate_tcp(dest_port, sequence_number, ack_number, flags, data)
        send(IP(dst=destination, src = self.src_ip) / packet, verbose=False) # We bypass the checksum calculation
        return

if __name__ == "__main__":
    s = TCPSocket("127.0.0.1", 12345)
    s.send_tcp("127.0.0.1", 8080, random.randint(1,10000000), 0, b"", "S") 

        

        
    