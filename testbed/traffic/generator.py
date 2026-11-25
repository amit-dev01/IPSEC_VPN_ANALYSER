"""
Multi-Class IPsec Traffic Generator.
Generates realistic live network traffic for containerized/live environments
supporting VoIP (UDP RTP simulation), Video streaming, Web traffic, Messaging, and ICMP.
"""

import sys
import time
import socket
import random
import argparse


def generate_voip_stream(target_ip: str, target_port: int = 5004, duration: int = 10):
    """Generates continuous 20ms audio packets (e.g. G.711 / Opus simulation)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[*] Generating VoIP stream to {target_ip}:{target_port} for {duration}s...")
    start_time = time.time()
    packet_seq = 0

    while time.time() - start_time < duration:
        # RTP simulation: 12-byte header + 160 bytes payload
        rtp_header = b"\x80\x00" + packet_seq.to_bytes(2, "big") + int(time.time()*1000).to_bytes(4, "big") + b"\x12\x34\x56\x78"
        payload = rtp_header + random.randbytes(160)
        sock.sendto(payload, (target_ip, target_port))
        packet_seq = (packet_seq + 1) % 65535
        time.sleep(0.02)  # 20ms interval


def generate_video_stream(target_ip: str, target_port: int = 8080, duration: int = 10):
    """Generates variable-bitrate high-throughput video packet bursts."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[*] Generating Video stream to {target_ip}:{target_port} for {duration}s...")
    start_time = time.time()

    while time.time() - start_time < duration:
        burst_size = random.randint(8, 25)
        for _ in range(burst_size):
            packet_len = random.choice([1360, 1400, 1420])
            sock.sendto(random.randbytes(packet_len), (target_ip, target_port))
        time.sleep(random.uniform(0.005, 0.025))


def generate_web_traffic(target_ip: str, target_port: int = 80, duration: int = 10):
    """Generates request-response burst patterns characteristic of HTTPS/HTTP browsing."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[*] Generating Web traffic patterns to {target_ip}:{target_port} for {duration}s...")
    start_time = time.time()

    while time.time() - start_time < duration:
        # Client request (small)
        sock.sendto(random.randbytes(random.randint(150, 450)), (target_ip, target_port))
        time.sleep(random.uniform(0.05, 0.15))
        # Server response burst (multiple large segments)
        for _ in range(random.randint(4, 12)):
            sock.sendto(random.randbytes(random.randint(1200, 1420)), (target_ip, target_port))
        time.sleep(random.uniform(0.5, 2.0))


def generate_messaging_traffic(target_ip: str, target_port: int = 5222, duration: int = 10):
    """Generates sporadic small packet exchanges with long idle keep-alives."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[*] Generating Messaging traffic to {target_ip}:{target_port} for {duration}s...")
    start_time = time.time()

    while time.time() - start_time < duration:
        sock.sendto(random.randbytes(random.randint(60, 200)), (target_ip, target_port))
        time.sleep(random.uniform(1.0, 3.5))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Class Traffic Generator for IPsec Testbed")
    parser.add_argument("--type", choices=["voip", "video", "web", "messaging"], default="web")
    parser.add_argument("--target", default="192.168.100.20")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--duration", type=int, default=10)
    args = parser.parse_args()

    if args.type == "voip":
        generate_voip_stream(args.target, args.port, args.duration)
    elif args.type == "video":
        generate_video_stream(args.target, args.port, args.duration)
    elif args.type == "web":
        generate_web_traffic(args.target, args.port, args.duration)
    elif args.type == "messaging":
        generate_messaging_traffic(args.target, args.port, args.duration)
