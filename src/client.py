import cv2
from protocols.UDP import UDPSocket
import math
import pickle
import time

# Configuration
max_length = 65000
host = "127.0.0.1"
port = 5000
video_path = "video.mp4"  # Change to your file path

# Setup socket
sock = UDPSocket(src_ip="127.0.0.1", src_port=5001)

# Open video file
cap = cv2.VideoCapture(video_path)
if not cap.isOpened():
    print(f"[ERROR] Could not open video file: {video_path}")
    exit()

fps = cap.get(cv2.CAP_PROP_FPS)
delay = 1 / fps if fps > 0 else 0.033

ret, frame = cap.read()

while ret:
    # Compress frame to JPEG
    retval, buffer = cv2.imencode(".jpg", frame)
    if not retval:
        print("[WARNING] Failed to encode frame")
        ret, frame = cap.read()
        continue

    buffer = buffer.tobytes()
    buffer_size = len(buffer)

    # Chunk frame if too big
    num_of_packs = math.ceil(buffer_size / max_length)
    frame_info = {"packs": num_of_packs}

    # Send metadata first
    sock.send_udp(host, port,pickle.dumps(frame_info))

    # Send each chunk
    for i in range(num_of_packs):
        start = i * max_length
        end = start + max_length
        chunk = buffer[start:end]
        sock.send_udp(host, port, chunk)

    # Wait for the next frame
    time.sleep(delay)
    ret, frame = cap.read()

cap.release()
print("[INFO] Video transmission complete.")
