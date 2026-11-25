"""
Automated Dataset Generator for IPsec VPN Framework.
Produces 6 rich reference sample PCAPs (covering IPv4/IPv6, NAT-T, IKEv1/v2, Downgrade, AH)
and a 70-trace balanced training corpus across 7 application categories & both operating modes.
"""

import os
import json
import random
from pathlib import Path
from testbed.traffic.pcap_builder import SyntheticIPsecPCAPGenerator


def generate_all_datasets(base_dir: str = "datasets"):
    Path(base_dir).mkdir(parents=True, exist_ok=True)
    train_dir = os.path.join(base_dir, "training")
    samples_dir = os.path.join(base_dir, "samples")
    Path(train_dir).mkdir(parents=True, exist_ok=True)
    Path(samples_dir).mkdir(parents=True, exist_ok=True)

    # Clear old samples/training files so corpus stays clean
    for folder in (train_dir, samples_dir):
        for old in os.listdir(folder):
            if old.endswith(".pcap"):
                os.remove(os.path.join(folder, old))

    gen = SyntheticIPsecPCAPGenerator()
    manifest = []

    print("[*] Generating 6 reference sample PCAPs...")

    samples_spec = [
        ("hardened_ikev2_tunnel_web.pcap", dict(ike_version=2, profile="hardened", traffic_type="WEB", mode="TUNNEL", packet_count=150)),
        ("vulnerable_ikev1_transport_msg.pcap", dict(ike_version=1, hardened=False, traffic_type="MESSAGING", mode="TRANSPORT", packet_count=120)),
        ("enterprise_ikev2_tunnel_video.pcap", dict(ike_version=2, profile="enterprise", traffic_type="VIDEO", mode="TUNNEL", packet_count=180)),
        ("hardened_ikev2_tunnel_voip.pcap", dict(ike_version=2, profile="hardened", traffic_type="VOIP", mode="TUNNEL", packet_count=160)),
        ("ipv6_natt_whatsapp_tunnel.pcap", dict(ike_version=2, profile="hardened", traffic_type="WHATSAPP", mode="TUNNEL", packet_count=140, use_ipv6=True, use_natt=True)),
        ("cbc_downgrade_email_audit.pcap", dict(ike_version=2, profile="downgrade", traffic_type="EMAIL", mode="TUNNEL", packet_count=130)),
    ]

    for fname, kwargs in samples_spec:
        fpath = os.path.join(samples_dir, fname)
        gen.generate_full_session_pcap(output_path=fpath, **kwargs)
        manifest.append({
            "filename": fname,
            "path": fpath,
            "mode": kwargs.get("mode", "TUNNEL"),
            "traffic_type": kwargs.get("traffic_type", "WEB"),
            "split": "sample",
        })

    print("[*] Generating 70-trace ML training corpus across 7 traffic classes & 2 modes...")
    traffic_classes = ["VOIP", "VIDEO", "WEB", "MESSAGING", "WHATSAPP", "EMAIL", "ICMP"]
    modes = ["TUNNEL", "TRANSPORT"]

    for t_class in traffic_classes:
        for mode in modes:
            for rep in range(5):  # 7 * 2 * 5 = 70 PCAPs
                filename = f"train_{t_class.lower()}_{mode.lower()}_{rep + 1}.pcap"
                filepath = os.path.join(train_dir, filename)
                gen.generate_full_session_pcap(
                    output_path=filepath,
                    ike_version=random.choice([1, 2]),
                    hardened=random.choice([True, False]),
                    traffic_type=t_class,
                    mode=mode,
                    packet_count=random.randint(110, 200),
                    use_ipv6=(rep == 4),
                    use_natt=(rep == 3),
                )
                manifest.append({
                    "filename": filename,
                    "path": filepath,
                    "mode": mode,
                    "traffic_type": t_class,
                    "split": "train",
                })

    manifest_path = os.path.join(base_dir, "dataset_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"[✓] Generated {len(manifest)} PCAP files. Manifest saved to {manifest_path}")
    return manifest_path


if __name__ == "__main__":
    generate_all_datasets()
