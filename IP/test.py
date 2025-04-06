from UDP import SocketUDP


s = SocketUDP("127.0.0.1")
s.send_udp(("127.0.0.1", 8081), b"Hello from UDP client!")