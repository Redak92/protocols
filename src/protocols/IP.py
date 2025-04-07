import struct
import threading
import queue
import scapy
from scapy.all import IP, send, sniff, Raw


class IPSocket:
    def __init__(self, src_ip=None):
        self.src_ip = src_ip
        self.packet_number = 540
        self.ttl = 64
        self.mtu = 1500
        self.packet_queue = queue.Queue()
        self.running = False
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
    
    @staticmethod
    def sparse_ip(ip: str) -> bytes:
        return b''.join(map(lambda x: int(x).to_bytes(1, "big"), ip.split('.')))
    
    def encapsulate_ip(self, destination: str, data: bytes, protocol: int):
        ip_version = 4
        ihl = 5
        dscp = 0
        total_length = ihl * 4 + len(data)
        identification = self.packet_number
        self.packet_number = (self.packet_number + 1) % 65536

        fragment_size = self.mtu - (ihl * 4)
        number_of_fragments = len(data) // fragment_size
        if len(data) % fragment_size != 0:
            number_of_fragments += 1

        if len(data) < fragment_size:
            packet = IP(
                version=ip_version,
                ihl=ihl,
                tos=dscp,
                len=total_length,
                id=identification,
                flags=0,
                frag=0,
                ttl=self.ttl,
                proto=protocol,
                src=self.src_ip,
                dst=destination
            )
            checksum_value = self.checksum(bytes(packet))
            packet.chksum = checksum_value
            packet /= Raw(load=data)
            return [packet]
        else:
            fragments = []
            for i in range(number_of_fragments):
                start = i * fragment_size
                end = start + fragment_size
                if end > len(data):
                    end = len(data)
                fragment_data = data[start:end]
                flags = 2 if i == number_of_fragments - 1 else 1
                frag_offset = i * fragment_size // 8
                fragments.append(IP(
                    version=ip_version,
                    ihl=ihl,
                    tos=dscp,
                    len=total_length,
                    id=identification,
                    flags=flags,
                    frag=frag_offset,
                    ttl=self.ttl,
                    proto=protocol,
                    src=self.src_ip,
                    dst=destination
                ) / Raw(load=fragment_data))
            return fragments

    def send_ip(self, destination: str, data: bytes, protocol: int, verbose = False):
        fragments = self.encapsulate_ip(destination, data, protocol)
        for fragment in fragments:
            send(fragment)
            if verbose:
                fragment.show()

    def _packet_handler(self, packet):
        if IP in packet and Raw in packet:
            self.packet_queue.put(packet)

    def start_receiver(self, interface="lo", filtre="ip"):
        self.running = True
        self.ip_thread = threading.Thread(target=self._receive_loop, args=(interface, filtre,), daemon=True)
        self.ip_thread.start()

    def _receive_loop(self, interface, filtre):
        sniff(iface=interface, prn=self._packet_handler, filter=filtre, store=0, stop_filter=lambda x: not self.running)

    def get_packet(self, timeout=None):
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
        


if __name__ == "__main__":
    s = IPSocket("127.0.0.1")
    s.start_receiver("lo")
    while True:
        packet = s.get_packet(timeout=1)
        if packet:
            print(packet.show())
        else:
            print("No packet received.")