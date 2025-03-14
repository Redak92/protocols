import socket
import struct


class SocketMain():
    def __init__(self, ip: str = "127.0.0.1"):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.mtu = 1500  # Maximum Transmission Unit, we will fragment if necessary
        self.ip = ip
        self.packet_number = 4000
        self.ttl = 8

    def encapsulate_ip(self, destination: str, data: str, protocol: int):
        ip_version = 0x4
        ihl = 0x5  # For now, we ignore options
        dscp = 0x0  # Low priority DSCP
        total_length = len(data) + 4 * ihl
        total_length_bytes = total_length.to_bytes(2, byteorder='big')
        identification = self.packet_number.to_bytes(2, byteorder='big')
        source_ip = self.sparse_ip(self.ip)
        destination_ip = self.sparse_ip(destination)
        protocol = protocol.to_bytes(1, byteorder='big')

        data_bytes = data.encode()

        # Check if fragmentation is needed (if the data is large)
        fragment_size = self.mtu - (4 * ihl)  # IP header is 20 bytes for IPv4, can be more for options
        if len(data_bytes) > fragment_size:
            return self.fragment_data(identification, source_ip, destination_ip, protocol, data_bytes)
        else:
            # No fragmentation needed, return the full packet
            ip_header = self.build_ip_header(identification, 0, source_ip, destination_ip, protocol, len(data_bytes))
            return [ip_header + data_bytes]

    def fragment_data(self, identification: bytes, source_ip: bytes, destination_ip: bytes, protocol: bytes, data_bytes: bytes):
        print("Fragging")
        # Calculate how many fragments are required
        fragment_size = self.mtu - 20  # IPv4 header size
        num_fragments = (len(data_bytes) + fragment_size - 1) // fragment_size  # round up division

        fragments = []
        offset = 0

        for i in range(num_fragments):
            # Determine if this is the last fragment
            is_last_fragment = (i == num_fragments - 1)
            flags = 0x1 if not is_last_fragment else 0x0  # Set "More Fragments" (MF) for all except the last
            frag_offset = offset // 8  # Fragment offset is in 8-byte units
            fragment_data = data_bytes[offset:offset + fragment_size]

            # Build IP header for this fragment
            ip_header = self.build_ip_header(identification, frag_offset, source_ip, destination_ip, protocol, len(fragment_data), flags)
            fragments.append(ip_header + fragment_data)

            # Update offset for next fragment
            offset += len(fragment_data)

        return fragments

    def build_ip_header(self, identification: bytes, frag_offset: int, source_ip: bytes, destination_ip: bytes, protocol: bytes, data_length: int, flags: int = 0x2):
        ip_version = 0x4
        ihl = 0x5  # For now, we ignore options
        dscp = 0x0  # Low priority DSCP
        total_length = data_length + 20  # 20 bytes for the IP header
        total_length_bytes = total_length.to_bytes(2, byteorder='big')

        # Building the IP header
        ip_header = [(ip_version << 4 | ihl).to_bytes(1, byteorder='big')]
        ip_header.append((dscp << 2 | 0b00).to_bytes(1, byteorder='big'))
        ip_header.append(total_length_bytes)
        ip_header.append(identification)
        fpluso = (flags << 13 | frag_offset).to_bytes(2, byteorder='big')
        ip_header.append(fpluso)
        ip_header.append(self.ttl.to_bytes(1, byteorder='big'))
        ip_header.append(protocol)
        ip_header.append(b'\x00\x00')  # Initial checksum (will be calculated)
        ip_header.append(source_ip)
        ip_header.append(destination_ip)
        ip_header = b''.join(ip_header)
        return self.put_checksum(ip_header)

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

    def sparse_ip(self, ip: str) -> bytes:
        return b''.join(map(lambda x: int(x).to_bytes(1, "big"), ip.split('.')))

    def send_packet(self, address: tuple[str, int], packet: bytes):
        self.socket.sendto(packet, address)
        print("Packet sent : ", packet.hex())
    def get_own_ip(self):
        return self.ip

    def sendall(self, address: tuple[str, int], data: str, protocol: int):
        packets = self.encapsulate_ip(address[0], data, protocol)
        for packet in packets:
            self.send_packet(address, packet)
        self.packet_number = self.packet_number % 65535 + 1

if __name__ == "__main__":
    s = SocketMain("127.0.0.1")
    data = "Hello" * 3000  # Large data to test fragmentation
    s.sendall(("127.0.0.1", 12345), data, 255)
    s.sendall(("127.0.0.1", 12345), "tu vas bien ?", 255)