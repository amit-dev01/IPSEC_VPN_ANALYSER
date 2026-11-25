"""
Live Docker StrongSwan Testbed Orchestrator.
Verifies Docker availability, boots ipsec-peer-a and ipsec-peer-b containers,
initiates a real StrongSwan IKEv2 tunnel, drives traffic with generator.py,
and captures authentic kernel XFRM IPsec packets into datasets/real_captures/.
"""

import os
import subprocess
import sys
import time


def run_cmd(cmd, check=True):
    print(f"[cmd] {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def main():
    # 1. Check Docker Daemon
    res = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if res.returncode != 0:
        print("[!] Docker Desktop Linux engine is not running.")
        print("    Start Docker Desktop on Windows and re-run this script to capture live kernel XFRM IPsec PCAPs.")
        sys.exit(1)

    os.makedirs(os.path.join("datasets", "real_captures"), exist_ok=True)
    os.makedirs(os.path.join("testbed", "captures"), exist_ok=True)

    print("[*] Bringing up StrongSwan testbed containers (peer-a & peer-b)...")
    run_cmd(["docker", "compose", "-f", "testbed/docker-compose.yml", "up", "-d"])
    time.sleep(8)

    # 2. Start tcpdump inside peer-a
    print("[*] Starting tcpdump capture inside ipsec-peer-a...")
    tcpdump_proc = subprocess.Popen([
        "docker", "exec", "ipsec-peer-a",
        "tcpdump", "-i", "eth0", "-w", "/captures/live_strongswan_ikev2.pcap",
        "udp port 500 or udp port 4500 or proto 50 or proto 51"
    ])
    time.sleep(1.5)

    try:
        # 3. Initiate IPsec Child SA
        print("[*] Initiating IPsec SA via swanctl...")
        init_res = run_cmd([
            "docker", "exec", "ipsec-peer-a",
            "swanctl", "--initiate", "--child", "hardened-child"
        ], check=False)
        print(init_res.stdout)

        # 4. Inspect kernel XFRM state & drive traffic
        xfrm_res = run_cmd(["docker", "exec", "ipsec-peer-a", "ip", "xfrm", "state"], check=False)
        print("[*] Kernel XFRM State:\n", xfrm_res.stdout)

        print("[*] Sending ICMP and synthetic application traffic across the encrypted tunnel...")
        run_cmd(["docker", "exec", "ipsec-peer-a", "ping", "-c", "10", "192.168.100.20"], check=False)
        run_cmd([
            "docker", "exec", "ipsec-peer-a",
            "python3", "/traffic/generator.py", "--type", "web", "--target", "192.168.100.20", "--duration", "5"
        ], check=False)
    finally:
        tcpdump_proc.terminate()
        time.sleep(1)

    src_cap = os.path.join("testbed", "captures", "live_strongswan_ikev2.pcap")
    dst_cap = os.path.join("datasets", "real_captures", "live_strongswan_ikev2.pcap")
    if os.path.exists(src_cap):
        import shutil
        shutil.copy2(src_cap, dst_cap)
        print(f"[✓] Real kernel capture saved to {dst_cap}")
    else:
        print("[!] Capture file was not produced; check docker logs ipsec-peer-a.")


if __name__ == "__main__":
    main()
