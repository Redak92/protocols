import cv2
import time
from protocols.UDP import UDPSocket  # Adjust the import path as needed

def video_client(video_path: str, dest_ip: str = "127.0.0.1", dest_port: int = 12345, src_ip: str = "127.0.0.1", src_port: int = 54321):
    udp_socket = UDPSocket(src_ip=src_ip, src_port=src_port)

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        print(f"[ERROR] Cannot open video file: {video_path}")
        return

    fps = cap.get(cv2.CAP_PROP_FPS)
    delay = 1 / fps if fps > 0 else 0.033  # Default to ~30 fps if unknown

    print(f"[INFO] Streaming video '{video_path}' to {dest_ip}:{dest_port} at {fps:.2f} FPS")

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                print("[INFO] End of video.")
                break

            ret, buffer = cv2.imencode('.jpg', frame)
            if not ret:
                print("[WARNING] Failed to encode frame")
                continue

            data = buffer.tobytes()
            udp_socket.send_udp(dest_ip, dest_port, data)

            time.sleep(delay)  # Wait between frames to mimic original FPS

    finally:
        cap.release()
        print("[INFO] Video client stopped.")


if __name__ == "__main__":
    video_path = "video.mp4"  # Replace with your video file path
    video_client(video_path)