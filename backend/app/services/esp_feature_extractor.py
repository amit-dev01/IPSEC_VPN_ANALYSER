"""
Encrypted ESP/AH Flow Feature Extraction Engine.
Extracts 14 statistical packet-shape flow features, 23 ISCXFlowMeter-compatible
time-based microsecond features, 6-bin packet size histograms, sliding-window splits,
and covert channel anomalies from opaque IPsec ESP/AH streams.
"""

import math
from typing import List, Dict, Tuple
import numpy as np
from scapy.all import Packet, IP, IPv6, UDP
from scapy.layers.ipsec import ESP, AH
from backend.app.schemas.models import ESPFlowStatistics, SizeBin


ISCX_FEATURE_NAMES = [
    "duration", "total_fiat", "total_biat", "min_fiat", "min_biat",
    "max_fiat", "max_biat", "mean_fiat", "mean_biat",
    "flowPktsPerSecond", "flowBytesPerSecond",
    "min_flowiat", "max_flowiat", "mean_flowiat", "std_flowiat",
    "min_active", "mean_active", "max_active", "std_active",
    "min_idle", "mean_idle", "max_idle", "std_idle",
]


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


def _iat_summary_us(timestamps_sec: List[float]) -> Tuple[float, float, float, float]:
    """Returns (total_us, min_us, max_us, mean_us) matching ISCXFlowMeter sentinel conventions."""
    if len(timestamps_sec) < 2:
        return 0.0, -1.0, -1.0, 0.0
    iats_us = np.diff(np.sort(np.array(timestamps_sec, dtype=float))) * 1_000_000.0
    return (
        float(np.sum(iats_us)),
        float(np.min(iats_us)),
        float(np.max(iats_us)),
        float(np.mean(iats_us)),
    )


def _compute_iscx_23_features(
    timestamps_sec: List[float],
    fwd_timestamps_sec: List[float],
    bwd_timestamps_sec: List[float],
    total_bytes: int,
) -> List[float]:
    """Computes the exact 23 ISCXFlowMeter time-based microsecond features for cross-benchmark inference."""
    if not timestamps_sec:
        return [0.0] * 23

    ts_sorted = np.sort(np.array(timestamps_sec, dtype=float))
    duration_sec = max(1e-6, float(ts_sorted[-1] - ts_sorted[0])) if len(ts_sorted) > 1 else 1e-6
    duration_us = duration_sec * 1_000_000.0

    total_fiat, min_fiat, max_fiat, mean_fiat = _iat_summary_us(fwd_timestamps_sec)
    total_biat, min_biat, max_biat, mean_biat = _iat_summary_us(bwd_timestamps_sec)

    flow_pkts_per_sec = len(ts_sorted) / duration_sec
    flow_bytes_per_sec = total_bytes / duration_sec

    if len(ts_sorted) >= 2:
        flow_iats_us = np.diff(ts_sorted) * 1_000_000.0
        min_flowiat = float(np.min(flow_iats_us))
        max_flowiat = float(np.max(flow_iats_us))
        mean_flowiat = float(np.mean(flow_iats_us))
        std_flowiat = float(np.std(flow_iats_us))
    else:
        flow_iats_us = np.array([], dtype=float)
        min_flowiat, max_flowiat, mean_flowiat, std_flowiat = -1.0, -1.0, 0.0, 0.0

    # Active/Idle bursts using standard 5,000,000 us (5s) idle threshold
    idle_threshold_us = 5_000_000.0
    active_durations = []
    idle_durations = []
    if len(ts_sorted) >= 2:
        active_start = ts_sorted[0] * 1_000_000.0
        last_t = active_start
        for t_sec in ts_sorted[1:]:
            t_us = t_sec * 1_000_000.0
            gap = t_us - last_t
            if gap > idle_threshold_us:
                active_durations.append(max(0.0, last_t - active_start))
                idle_durations.append(gap)
                active_start = t_us
            last_t = t_us
        if idle_durations:
            active_durations.append(max(0.0, last_t - active_start))

    if active_durations:
        a_np = np.array(active_durations, dtype=float)
        min_active, mean_active, max_active, std_active = (
            float(np.min(a_np)), float(np.mean(a_np)), float(np.max(a_np)), float(np.std(a_np))
        )
    else:
        min_active, mean_active, max_active, std_active = -1.0, 0.0, -1.0, 0.0

    if idle_durations:
        i_np = np.array(idle_durations, dtype=float)
        min_idle, mean_idle, max_idle, std_idle = (
            float(np.min(i_np)), float(np.mean(i_np)), float(np.max(i_np)), float(np.std(i_np))
        )
    else:
        min_idle, mean_idle, max_idle, std_idle = -1.0, 0.0, -1.0, 0.0

    return [
        duration_us, total_fiat, total_biat, min_fiat, min_biat,
        max_fiat, max_biat, mean_fiat, mean_biat,
        flow_pkts_per_sec, flow_bytes_per_sec,
        min_flowiat, max_flowiat, mean_flowiat, std_flowiat,
        min_active, mean_active, max_active, std_active,
        min_idle, mean_idle, max_idle, std_idle,
    ]


class ESPFeatureExtractor:
    """Extracts 14-dimensional ML flow features, ISCX 23-features, and anomaly flags from ESP/AH traffic."""

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
        """Groups ESP/AH packets into bidirectional flows and extracts all statistical metrics."""
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
                if len(raw) >= 8 and raw[:4] != b"\x00\x00\x00\x00":
                    spi = hex(int.from_bytes(raw[:4], "big"))
                    proto = "ESP-NATT"

            if spi is None:
                continue

            ep_a, ep_b = sorted([src_ip, dst_ip])
            flow_key = f"{ep_a}<->{ep_b}_{spi}"
            if flow_key not in flows_map:
                flows_map[flow_key] = []
            flows_map[flow_key].append((pkt, src_ip, ip_ver, proto))

        flow_statistics: List[ESPFlowStatistics] = []
        for flow_key, items in flows_map.items():
            if not items:
                continue
            flow_statistics.append(self._compute_flow_stats(flow_key, items))

        return flow_statistics

    def extract_windowed_flows(
        self,
        esp_packets: List[Packet],
        window_size: int = 25,
        stride: int = 20,
    ) -> List[ESPFlowStatistics]:
        """Slices long ESP sessions into realistic overlapping flow windows for ML training & robustness."""
        flows_map: Dict[str, List[Tuple[Packet, str, str, str]]] = {}
        for pkt in esp_packets:
            src_ip = pkt[IP].src if IP in pkt else (pkt[IPv6].src if IPv6 in pkt else "0.0.0.0")
            dst_ip = pkt[IP].dst if IP in pkt else (pkt[IPv6].dst if IPv6 in pkt else "0.0.0.0")
            ip_ver = "IPv6" if IPv6 in pkt else "IPv4"
            spi = None
            proto = "ESP"
            if ESP in pkt:
                spi = hex(pkt[ESP].spi)
            elif AH in pkt:
                spi, proto = hex(pkt[AH].spi), "AH"
            elif UDP in pkt and (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500):
                raw = bytes(pkt[UDP].payload)
                if len(raw) >= 8 and raw[:4] != b"\x00\x00\x00\x00":
                    spi, proto = hex(int.from_bytes(raw[:4], "big")), "ESP-NATT"
            if spi is None:
                continue
            ep_a, ep_b = sorted([src_ip, dst_ip])
            key = f"{ep_a}<->{ep_b}_{spi}"
            flows_map.setdefault(key, []).append((pkt, src_ip, ip_ver, proto))

        windowed: List[ESPFlowStatistics] = []
        for flow_key, items in flows_map.items():
            if len(items) < window_size:
                windowed.append(self._compute_flow_stats(flow_key, items))
                continue
            for start in range(0, len(items) - window_size + 1, stride):
                chunk = items[start : start + window_size]
                windowed.append(self._compute_flow_stats(f"{flow_key}#w{start}", chunk))
        return windowed

    def _compute_flow_stats(
        self,
        flow_key: str,
        items: List[Tuple[Packet, str, str, str]],
    ) -> ESPFlowStatistics:
        ep_pair, spi_part = flow_key.rsplit("_", 1)
        spi = spi_part.split("#")[0]
        ep_a, ep_b = ep_pair.split("<->")
        pkts = [it[0] for it in items]
        ip_ver = items[0][2]
        proto = items[0][3]

        fwd_ts = [float(it[0].time) for it in items if it[1] == ep_a]
        bwd_ts = [float(it[0].time) for it in items if it[1] != ep_a]
        direction_ratio = round(len(fwd_ts) / len(items), 3)

        packet_count = len(pkts)
        sizes = [len(p) for p in pkts]
        sizes_np = np.array(sizes, dtype=float)
        total_bytes = int(np.sum(sizes_np))
        mean_size = float(np.mean(sizes_np))
        std_size = float(np.std(sizes_np))
        p25_size, p50_size, p75_size = [float(x) for x in np.percentile(sizes_np, [25, 50, 75])]
        padding_uniformity = round(1.0 - (len(set(sizes)) / max(1, packet_count)), 3)

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
            iat_mean = iat_std = iat_p50 = 0.0

        sample_data = b""
        for p in pkts[:15]:
            if ESP in p and hasattr(p[ESP], "data"):
                sample_data += bytes(p[ESP].data)
            elif AH in p:
                sample_data += bytes(p[AH].payload)
        entropy = shannon_entropy(sample_data) if sample_data else 7.85

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

        iscx_vec = _compute_iscx_23_features(timestamps, fwd_ts, bwd_ts, total_bytes)

        return ESPFlowStatistics(
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
            iscx_features=iscx_vec,
            anomaly_flags=anomalies,
        )

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
