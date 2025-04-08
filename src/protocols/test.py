import socket
import struct
from scapy.all import IP, TCP, Raw

def compute_checksum(data: bytes) -> int:
    """
    Compute checksum over the given bytes.
    This is the standard Internet checksum (ones' complement sum of 16-bit words).
    """
    if len(data) % 2:
        data += b'\x00'  # pad to even length if needed

    s = 0
    # Sum every 16-bit word (big-endian)
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w

    # Wrap around carry bits
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    
    # One's complement and mask to 16 bits
    checksum = ~s & 0xffff
    return checksum

def calc_tcp_checksum(packet) -> int:
    """
    Given a Scapy packet with an IP and a TCP layer, compute the TCP checksum.
    
    NOTE: This function computes the checksum for the TCP header and payload,
    using the pseudo header (which comes from the IP layer).
    """
    # Ensure packet has both IP and TCP layers
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        raise ValueError("Packet must contain both IP and TCP layers.")

    # Extract IP and TCP layers
    ip_layer = packet[IP]
    tcp_layer = packet[TCP]
    
    # Extract any TCP payload
    tcp_payload = bytes(tcp_layer.payload)
    
    # Zero out the checksum field in the TCP header for calculation
    tcp_layer.chksum = 0
    
    # Obtain the raw TCP header bytes (this includes options)
    tcp_header = bytes(tcp_layer)
    
    # Calculate the total length of TCP header and payload in bytes
    tcp_length = len(tcp_header) + len(tcp_payload)
    
    # Build the pseudo header.
    # For IPv4, the pseudo header consists of:
    #   - Source IP (4 bytes)
    #   - Destination IP (4 bytes)
    #   - Reserved field (1 byte, value 0)
    #   - Protocol (1 byte, for TCP this is 6)
    #   - TCP Length (2 bytes)
    pseudo_header = (
        socket.inet_aton(ip_layer.src) +
        socket.inet_aton(ip_layer.dst) +
        struct.pack('!BBH', 0, ip_layer.proto, tcp_length)
    )
    
    # Combine pseudo header with TCP header and payload for checksum calculation
    checksum_data = pseudo_header + tcp_header + tcp_payload
    
    # Compute the checksum using the helper function
    checksum = compute_checksum(checksum_data)
    return checksum

# Example usage:

# Create a sample packet (TCP SYN from localhost to localhost)
packet = IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=12345, dport=80, flags="S", seq=5963999)/Raw(load="Hello, world!")

# At this point the TCP checksum might be 0 (or invalid) as seen:
print("Before computation, TCP checksum:", hex(packet[TCP].chksum))

# Calculate the TCP checksum for the packet
tcp_chk = calc_tcp_checksum(packet)
print("Computed TCP checksum:", hex(tcp_chk))

# Set the checksum into the packet's TCP layer (if desired)
packet[TCP].chksum = tcp_chk

# Verify (showing the packet now prints the computed checksum)
packet.show()
