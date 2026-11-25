"""
Synthetic PCAP Generator for IPsec VPN Framework.
Constructs standard-compliant IKEv1, IKEv2, ESP, NAT-T, and AH packet streams
across IPv4 and IPv6 for all test matrix combinations (Hardened, Vulnerable,
Enterprise, Downgrade Fallback, Tunnel, Transport) with realistic statistical profiles
for VoIP, Video, Web, Messaging, WhatsApp, Email, ICMP, and C2 Beacon anomaly traces.
"""

import time
import random
from typing import List
from scapy.all import IP, IPv6, UDP, Raw, wrpcap, Packet
from scapy.layers.ipsec import ESP, AH
from scapy.layers.isakmp import ISAKMP


class SyntheticIPsecPCAPGenerator:
    """Generates reference PCAP traces covering diverse IKE, ESP, AH, and IPv6 profiles."""

    def __init__(self, src_ip: str = "192.168.100.10", dst_ip: str = "192.168.100.20"):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_ipv6 = "fd00:100::10"
        self.dst_ipv6 = "fd00:100::20"

    def _ip_layer(self, src: str, dst: str, use_ipv6: bool = False):
        return IPv6(src=src, dst=dst) if use_ipv6 else IP(src=src, dst=dst)

    def build_ikev2_sa_init(
        self,
        profile: str = "hardened",
        mode: str = "TUNNEL",
        use_ipv6: bool = False,
        use_natt: bool = False,
    ) -> List[Packet]:
        """
        Builds simulated IKEv2 IKE_SA_INIT and optional IKE_AUTH packets.
        Profiles: 'hardened', 'enterprise', 'downgrade', 'vulnerable'
        """
        packets = []
        initiator_spi = random.randbytes(8)
        responder_spi = random.randbytes(8)
        src = self.src_ipv6 if use_ipv6 else self.src_ip
        dst = self.dst_ipv6 if use_ipv6 else self.dst_ip
        port = 4500 if use_natt else 500
        natt_prefix = b"\x00\x00\x00\x00" if use_natt else b""

        def _make_prop(prop_num: int, is_last: bool, transforms: list) -> bytes:
            t_bytes = b"".join(transforms)
            last_flag = b"\x00\x00" if is_last else b"\x02\x00"
            return last_flag + (8 + len(t_bytes)).to_bytes(2, "big") + bytes([prop_num, 1, 0, len(transforms)]) + t_bytes

        if profile == "hardened":
            # Proposal 1: AES-256-GCM (20, 256b), PRF-SHA384 (4), DH Group 19 (19), ESN (1)
            p1 = _make_prop(1, True, [
                b"\x03\x00\x00\x0c\x01\x00\x00\x14\x80\x0e\x01\x00",
                b"\x03\x00\x00\x08\x02\x00\x00\x04",
                b"\x03\x00\x00\x08\x04\x00\x00\x13",
                b"\x00\x00\x00\x08\x05\x00\x00\x01",
            ])
            sa_payload = b"\x22\x00" + (4 + len(p1)).to_bytes(2, "big") + p1
            ke_payload = b"\x28\x00\x00\x48\x00\x13\x00\x00" + random.randbytes(64)
        elif profile == "enterprise":
            # Proposal 1: AES-128-CBC (12, 128b), PRF-SHA256 (3), INTEG-SHA256 (12), DH Group 14 (14)
            p1 = _make_prop(1, True, [
                b"\x03\x00\x00\x0c\x01\x00\x00\x0c\x80\x0e\x00\x80",
                b"\x03\x00\x00\x08\x02\x00\x00\x03",
                b"\x03\x00\x00\x08\x03\x00\x00\x0c",
                b"\x00\x00\x00\x08\x04\x00\x00\x0e",
            ])
            sa_payload = b"\x22\x00" + (4 + len(p1)).to_bytes(2, "big") + p1
            ke_payload = b"\x28\x00\x00\x88\x00\x0e\x00\x00" + random.randbytes(128)
        elif profile == "downgrade":
            # Proposal 1: AES-128-CBC + SHA256 + Group 14, PLUS Proposal 2 fallback: 3DES + MD5 + Group 2
            p1 = _make_prop(1, False, [
                b"\x03\x00\x00\x0c\x01\x00\x00\x0c\x80\x0e\x00\x80",
                b"\x03\x00\x00\x08\x02\x00\x00\x03",
                b"\x03\x00\x00\x08\x03\x00\x00\x0c",
                b"\x00\x00\x00\x08\x04\x00\x00\x0e",
            ])
            p2 = _make_prop(2, True, [
                b"\x03\x00\x00\x08\x01\x00\x00\x03",
                b"\x03\x00\x00\x08\x03\x00\x00\x01",
                b"\x00\x00\x00\x08\x04\x00\x00\x02",
            ])
            sa_payload = b"\x22\x00" + (4 + len(p1) + len(p2)).to_bytes(2, "big") + p1 + p2
            ke_payload = b"\x28\x00\x00\x88\x00\x0e\x00\x00" + random.randbytes(128)
        else:
            # Vulnerable IKEv2: 3DES, MD5, Group 2
            p1 = _make_prop(1, True, [
                b"\x03\x00\x00\x08\x01\x00\x00\x03",
                b"\x03\x00\x00\x08\x03\x00\x00\x01",
                b"\x00\x00\x00\x08\x04\x00\x00\x02",
            ])
            sa_payload = b"\x22\x00" + (4 + len(p1)).to_bytes(2, "big") + p1
            ke_payload = b"\x28\x00\x00\x88\x00\x02\x00\x00" + random.randbytes(128)

        # Optional Notify payload for USE_TRANSPORT_MODE (Type 41 -> 16391) or NAT_DETECTION
        if mode == "TRANSPORT":
            nonce_payload = b"\x29\x00\x00\x24" + random.randbytes(32)  # Next: Notify (41)
            notify_payload = b"\x00\x00\x00\x08\x00\x00\x40\x07"       # Notify Type 16391 (0x4007)
            init_body = sa_payload + ke_payload + nonce_payload + notify_payload
        else:
            nonce_payload = b"\x00\x00\x00\x24" + random.randbytes(32)
            init_body = sa_payload + ke_payload + nonce_payload

        req_hdr = initiator_spi + b"\x00" * 8 + b"\x21\x20\x22\x08\x00\x00\x00\x00"
        total_len = 28 + len(init_body)
        pkt1 = self._ip_layer(src, dst, use_ipv6) / UDP(sport=port, dport=port) / Raw(
            load=natt_prefix + req_hdr + total_len.to_bytes(4, "big") + init_body
        )
        packets.append(pkt1)

        resp_hdr = initiator_spi + responder_spi + b"\x21\x20\x22\x20\x00\x00\x00\x00"
        pkt2 = self._ip_layer(dst, src, use_ipv6) / UDP(sport=port, dport=port) / Raw(
            load=natt_prefix + resp_hdr + total_len.to_bytes(4, "big") + init_body
        )
        packets.append(pkt2)

        return packets

    def build_ikev1_main_mode(self, hardened: bool = False, use_ipv6: bool = False) -> List[Packet]:
        """Builds simulated IKEv1 Main Mode handshake packets."""
        packets = []
        icookie = random.randbytes(8)
        rcookie = random.randbytes(8)
        src = self.src_ipv6 if use_ipv6 else self.src_ip
        dst = self.dst_ipv6 if use_ipv6 else self.dst_ip

        hdr1 = icookie + b"\x00" * 8 + b"\x01\x10\x02\x00\x00\x00\x00\x00"
        if not hardened:
            trans = (
                b"\x00\x00\x00\x28\x01\x01\x00\x00"
                b"\x80\x01\x00\x05"  # 3DES-CBC
                b"\x80\x02\x00\x01"  # HMAC-MD5
                b"\x80\x03\x00\x01"  # PSK
                b"\x80\x04\x00\x02"  # Group 2
                b"\x80\x0b\x00\x01"
                b"\x00\x0c\x00\x04\x00\x01\x51\x80"  # 86400s
            )
        else:
            trans = (
                b"\x00\x00\x00\x2c\x01\x01\x00\x00"
                b"\x80\x01\x00\x07"
                b"\x80\x0e\x01\x00"
                b"\x80\x02\x00\x04"
                b"\x80\x03\x00\x01"
                b"\x80\x04\x00\x0e"
                b"\x80\x0b\x00\x01"
                b"\x00\x0c\x00\x04\x00\x00\x0e\x10"
            )

        sa_payload = (
            b"\x00\x00\x00" + bytes([len(trans) + 12]) +
            b"\x00\x00\x00\x01\x00\x00\x00" + bytes([len(trans) + 4]) + trans
        )
        total_len = 28 + len(sa_payload)
        pkt1 = self._ip_layer(src, dst, use_ipv6) / UDP(sport=500, dport=500) / Raw(
            load=hdr1 + total_len.to_bytes(4, "big") + sa_payload
        )
        packets.append(pkt1)

        hdr2 = icookie + rcookie + b"\x01\x10\x02\x00\x00\x00\x00\x00"
        pkt2 = self._ip_layer(dst, src, use_ipv6) / UDP(sport=500, dport=500) / Raw(
            load=hdr2 + total_len.to_bytes(4, "big") + sa_payload
        )
        packets.append(pkt2)
        return packets

    def build_esp_stream(
        self,
        spi: int,
        traffic_type: str = "WEB",
        mode: str = "TUNNEL",
        packet_count: int = 120,
        use_ipv6: bool = False,
        use_natt: bool = False,
        include_ah: bool = False,
    ) -> List[Packet]:
        """Builds realistic ESP (or NAT-T / AH) packet sequences across 7 application classes + C2 anomalies."""
        packets = []
        seq = 1
        current_time = time.time()
        src = self.src_ipv6 if use_ipv6 else self.src_ip
        dst = self.dst_ipv6 if use_ipv6 else self.dst_ip

        # Tunnel encapsulates inner IP header (+20B v4, +40B v6); Transport omits inner IP header
        mode_pad = (36 if use_ipv6 else 28) if mode == "TUNNEL" else 0

        for _ in range(packet_count):
            fwd_prob = 0.60
            if traffic_type == "VOIP":
                payload_len = random.choice([172, 184, 196, 208])
                current_time += max(0.014, random.gauss(0.020, 0.002))
            elif traffic_type == "VIDEO":
                payload_len = random.choices([1360, 1400, 1420, 1280, 420], weights=[55, 25, 10, 6, 4])[0]
                current_time += random.expovariate(1.0 / 0.0045)
                fwd_prob = 0.85
            elif traffic_type == "WEB":
                payload_len = random.choices([130, 260, 1340, 1400], weights=[30, 20, 25, 25])[0]
                current_time += random.choices([0.008, 0.060, 0.280], weights=[65, 25, 10])[0]
            elif traffic_type == "MESSAGING":
                payload_len = random.randint(90, 210)
                current_time += random.choice([0.900, 1.400, 2.200, 3.100])
            elif traffic_type == "WHATSAPP":
                # Mixed small chat acks + voice/image chunk bursts
                payload_len = random.choices([140, 480, 680, 920], weights=[25, 35, 25, 15])[0]
                current_time += random.choices([0.045, 0.160, 0.380], weights=[40, 40, 20])[0]
            elif traffic_type == "EMAIL":
                # SMTP/IMAP negotiation + medium/large attachment segments
                payload_len = random.choices([280, 740, 1120, 1360], weights=[20, 25, 35, 20])[0]
                current_time += random.choices([0.060, 0.220, 0.550], weights=[45, 35, 20])[0]
            elif traffic_type == "C2_BEACON":
                payload_len = random.randint(110, 125)
                current_time += random.gauss(0.650, 0.010)
            else:  # ICMP
                payload_len = 64
                current_time += random.gauss(1.0, 0.004)

            is_fwd = random.random() < fwd_prob
            p_src, p_dst = (src, dst) if is_fwd else (dst, src)

            if include_ah:
                pkt = self._ip_layer(p_src, p_dst, use_ipv6) / AH(spi=spi, seq=seq) / Raw(
                    load=random.randbytes(payload_len + mode_pad)
                )
            elif use_natt:
                esp_bytes = spi.to_bytes(4, "big") + seq.to_bytes(4, "big") + random.randbytes(payload_len + mode_pad)
                pkt = self._ip_layer(p_src, p_dst, use_ipv6) / UDP(sport=4500, dport=4500) / Raw(load=esp_bytes)
            else:
                pkt = self._ip_layer(p_src, p_dst, use_ipv6) / ESP(
                    spi=spi, seq=seq, data=random.randbytes(payload_len + mode_pad)
                )

            pkt.time = current_time
            packets.append(pkt)
            seq += 1

        return packets

    def generate_full_session_pcap(
        self,
        output_path: str,
        ike_version: int = 2,
        hardened: bool = True,
        profile: str = "",
        traffic_type: str = "WEB",
        mode: str = "TUNNEL",
        packet_count: int = 120,
        use_ipv6: bool = False,
        use_natt: bool = False,
        include_ah: bool = False,
    ):
        """Creates a complete PCAP with IKE negotiation followed by an ESP/AH stream."""
        chosen_profile = profile or ("hardened" if hardened else "vulnerable")

        if ike_version == 2:
            ike_pkts = self.build_ikev2_sa_init(
                profile=chosen_profile, mode=mode, use_ipv6=use_ipv6, use_natt=use_natt
            )
        else:
            ike_pkts = self.build_ikev1_main_mode(hardened=hardened, use_ipv6=use_ipv6)

        spi = random.randint(0x10000000, 0xFFFFFFFF)
        esp_pkts = self.build_esp_stream(
            spi=spi,
            traffic_type=traffic_type,
            mode=mode,
            packet_count=packet_count,
            use_ipv6=use_ipv6,
            use_natt=use_natt,
            include_ah=include_ah,
        )

        wrpcap(output_path, ike_pkts + esp_pkts)
        return output_path
