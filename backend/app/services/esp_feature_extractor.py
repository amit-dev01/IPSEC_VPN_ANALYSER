"""
Encrypted ESP/AH Flow Feature Extraction Engine.
Extracts 14 statistical flow dynamics, percentile distributions, size histograms,
inter-arrival times, padding uniformity, covert channel anomalies, and entropy metrics
from opaque IPsec ESP/AH streams without requiring payload decryption.
"""

import math
from typing import List, Dict, Tuple
import numpy as np
from scapy.all import Packet, IP, IPv6, UDP
from scapy.layers.ipsec import ESP, AH
from backend.app.schemas.models import ESPFlowStatistics, SizeBin


def shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def _build_size_histogram(sizes: List[int]) -> List[SizeBin]:
    buckets = [
        ("<128B", lambda s: s < 128),
        ("128-256B", lambda s: 128 <= s < 256),
        ("256-512B", lambda s: 256 <= s < 512),
        ("512-1024B", lambda s: 512 <= s < 1024),
        ("1024-1280B", lambda s: 1024 <= s < 1280),
        (">1280B", lambda s: s >= 1280),
    ]
    return [
        SizeBin(bucket=label, count=sum(1 for s in sizes if pred(s)))
        for label, pred in buckets
    ]


class ESPFeatureExtractor:
    """Extracts 14-dimensional ML flow features and anomaly flags from ESP/AH traffic."""

    FEATURE_NAMES = [
        "mean_packet_size",
        "std_packet_size",
        "min_packet_size",
        "max_packet_size",
        "p25_packet_size",
        "p50_packet_size",
        "p75_packet_size",
        "iat_mean_ms",
        "iat_std_ms",
        "iat_p50_ms",
        "packet_rate_pps",
        "byte_rate_bps",
        "burst_ratio",
        "entropy_score",
    ]

    def extract_flows(self, esp_packets: List[Packet]) -> List[ESPFlowStatistics]:
        """
        Groups ESP/AH packets into bidirectional tunnel flows by (endpoint_pair, SPI)
        and computes statistical distributions, size histograms, and covert anomalies.
        """
        if not esp_packets:
            return []

        flows_map: Dict[str, List[Tuple[Packet, str, str, str]]] = {}

        for pkt in esp_packets:
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            ip_ver = "IPv4"
            spi = None
            proto = "ESP"

            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                ip_ver = "IPv4"
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                ip_ver = "IPv6"

            if ESP in pkt:
                spi = hex(pkt[ESP].spi)
            elif AH in pkt or (IP in pkt and pkt[IP].proto == 51) or (IPv6 in pkt and pkt[IPv6].nh == 51):
                proto = "AH"
                spi = hex(pkt[AH].spi) if AH in pkt else "0xah00"
            elif UDP in pkt and (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500):
                raw = bytes(pkt[UDP].payload)
                # Strict NAT-T ESP check: skip 0x00000000 Non-ESP IKE markers
                if len(raw) >= 8 and raw[:4] != b"\x00\x00\x00\x00":
                    spi = hex(int.from_bytes(raw[:4], "big"))
                    proto = "ESP-NATT"

            if spi is None:
                continue  # Ignore non-ESP packets

            ep_a, ep_b = sorted([src_ip, dst_ip])
            flow_key = f"{ep_a}<->{ep_b}_{spi}"
            if flow_key not in flows_map:
                flows_map[flow_key] = []
            flows_map[flow_key].append((pkt, src_ip, ip_ver, proto))

        flow_statistics: List[ESPFlowStatistics] = []

        for flow_key, items in flows_map.items():
            if not items:
                continue

            ep_pair, spi = flow_key.rsplit("_", 1)
            ep_a, ep_b = ep_pair.split("<->")
            pkts = [it[0] for it in items]
            ip_ver = items[0][2]
            proto = items[0][3]

            # Forward direction = packets originating from ep_a
            fwd_count = sum(1 for it in items if it[1] == ep_a)
            direction_ratio = round(fwd_count / len(items), 3)

            packet_count = len(pkts)
            sizes = [len(p) for p in pkts]
            sizes_np = np.array(sizes, dtype=float)
            total_bytes = int(np.sum(sizes_np))
            mean_size = float(np.mean(sizes_np))
            std_size = float(np.std(sizes_np))
            p25_size, p50_size, p75_size = [float(x) for x in np.percentile(sizes_np, [25, 50, 75])]

            # Uniformity of packet lengths (1.0 = identical length every packet)
            unique_ratio = len(set(sizes)) / max(1, packet_count)
            padding_uniformity = round(1.0 - unique_ratio, 3)

            timestamps = sorted([float(p.time) for p in pkts])
            duration = max(0.001, timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else 0.001

            iats = []
            burst_count = 0
            for i in range(1, len(timestamps)):
                diff_ms = (timestamps[i] - timestamps[i - 1]) * 1000.0
                iats.append(diff_ms)
                if diff_ms < 15.0:
                    burst_count += 1

            if iats:
                iats_np = np.array(iats, dtype=float)
                iat_mean = float(np.mean(iats_np))
                iat_std = float(np.std(iats_np))
                iat_p50 = float(np.median(iats_np))
            else:
                iat_mean = 0.0
                iat_std = 0.0
                iat_p50 = 0.0

            # Sample ESP/AH payload bytes for entropy
            sample_data = b""
            for p in pkts[:15]:
                if ESP in p and hasattr(p[ESP], "data"):
                    sample_data += bytes(p[ESP].data)
                elif AH in p:
                    sample_data += bytes(p[AH].payload)
            entropy = shannon_entropy(sample_data) if sample_data else 7.85

            # Covert channel / side-channel anomaly detection
            anomalies: List[str] = []
            if entropy > 0 and entropy < 7.2:
                anomalies.append("COVERT_LOW_ENTROPY")
            if (
                packet_count >= 15
                and mean_size < 220
                and iat_mean > 400
                and abs(iat_mean - 1000.0) > 120.0
                and (iat_std / max(1.0, iat_mean)) < 0.08
            ):
                anomalies.append("C2_BEACON_SUSPECTED")
            if packet_count >= 20 and (direction_ratio > 0.90 or direction_ratio < 0.10) and mean_size > 1100:
                anomalies.append("EXFILTRATION_BURST_SKEW")

            flow_statistics.append(ESPFlowStatistics(
                flow_id=flow_key,
                src_ip=ep_a,
                dst_ip=ep_b,
                spi=spi,
                protocol=proto,
                ip_version=ip_ver,
                packet_count=packet_count,
                total_bytes=total_bytes,
                duration_seconds=round(duration, 3),
                packet_rate_pps=round(packet_count / duration, 2),
                byte_rate_bps=round((total_bytes * 8) / duration, 2),
                mean_packet_size=round(mean_size, 2),
                std_packet_size=round(std_size, 2),
                min_packet_size=int(np.min(sizes_np)),
                max_packet_size=int(np.max(sizes_np)),
                p25_packet_size=round(p25_size, 2),
                p50_packet_size=round(p50_size, 2),
                p75_packet_size=round(p75_size, 2),
                iat_mean_ms=round(iat_mean, 2),
                iat_std_ms=round(iat_std, 2),
                iat_p50_ms=round(iat_p50, 2),
                burst_count=burst_count,
                entropy_score=entropy,
                padding_uniformity=padding_uniformity,
                direction_ratio=direction_ratio,
                size_histogram=_build_size_histogram(sizes),
                anomaly_flags=anomalies,
            ))

        return flow_statistics

    def extract_features_vector(self, stats: ESPFlowStatistics) -> List[float]:
        """Converts flow statistics into the 14-element numeric feature vector for ML inference."""
        return [
            float(stats.mean_packet_size),
            float(stats.std_packet_size),
            float(stats.min_packet_size),
            float(stats.max_packet_size),
            float(stats.p25_packet_size),
            float(stats.p50_packet_size),
            float(stats.p75_packet_size),
            float(stats.iat_mean_ms),
            float(stats.iat_std_ms),
            float(stats.iat_p50_ms),
            float(stats.packet_rate_pps),
            float(stats.byte_rate_bps),
            float(stats.burst_count) / max(1, stats.packet_count),
            float(stats.entropy_score),
        ]
