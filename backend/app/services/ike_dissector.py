"""
Deep Protocol Dissector for IKEv1, IKEv2, ESP, and AH.
Extracts complete cryptographic parameters, SA proposals, transforms,
Diffie-Hellman groups, key lifetimes, Notify payloads, IKE packet timeline,
replay sequence anomalies, and protocol modes from PCAP captures.
"""

import struct
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
from scapy.all import rdpcap, Packet, IP, IPv6, UDP
from scapy.layers.ipsec import ESP, AH
from backend.app.schemas.models import (
    ProtocolVersion, OperatingMode, DHGroupStatus,
    TransformInfo, IKEProposal, IKEPacketSummary, SecurityAssociation
)

# Standard IKEv2 Transform ID Mappings (IANA RFC 7296 / RFC 8221)
ENCR_TRANSFORMS = {
    1: "DES-IV64",
    2: "DES",
    3: "3DES-CBC",
    4: "RC5",
    5: "IDEA",
    6: "CAST",
    7: "BLOWFISH",
    11: "NULL",
    12: "AES-CBC",
    13: "AES-CTR",
    14: "AES-CCM-8",
    15: "AES-CCM-12",
    16: "AES-CCM-16",
    18: "AES-GCM-8",
    19: "AES-GCM-12",
    20: "AES-GCM-16",
    28: "CHACHA20-POLY1305"
}

PRF_TRANSFORMS = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    3: "PRF_HMAC_SHA2_256",
    4: "PRF_HMAC_SHA2_384",
    5: "PRF_HMAC_SHA2_512",
    6: "PRF_AES128_XCBC",
    7: "PRF_AES128_CMAC"
}

INTEG_TRANSFORMS = {
    1: "AUTH_HMAC_MD5_96",
    2: "AUTH_HMAC_SHA1_96",
    3: "AUTH_DES_MAC",
    4: "AUTH_KPDK_MD5",
    5: "AUTH_AES_XCBC_96",
    12: "AUTH_HMAC_SHA2_256_128",
    13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256"
}

DH_GROUPS = {
    1: ("Group 1 (768-bit MODP)", 768, DHGroupStatus.INSECURE),
    2: ("Group 2 (1024-bit MODP)", 1024, DHGroupStatus.INSECURE),
    5: ("Group 5 (1536-bit MODP)", 1536, DHGroupStatus.INSECURE),
    14: ("Group 14 (2048-bit MODP)", 2048, DHGroupStatus.LEGACY),
    15: ("Group 15 (3072-bit MODP)", 3072, DHGroupStatus.SECURE),
    16: ("Group 16 (4096-bit MODP)", 4096, DHGroupStatus.SECURE),
    19: ("Group 19 (256-bit ECP)", 256, DHGroupStatus.SECURE),
    20: ("Group 20 (384-bit ECP)", 384, DHGroupStatus.SECURE),
    21: ("Group 21 (521-bit ECP)", 521, DHGroupStatus.SECURE),
    31: ("Curve25519", 256, DHGroupStatus.SECURE),
    32: ("Curve448", 448, DHGroupStatus.SECURE),
    35: ("ML-KEM-768 / Kyber (Post-Quantum)", 768, DHGroupStatus.POST_QUANTUM)
}

IKEV2_EXCHANGE_TYPES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}

IKEV1_EXCHANGE_TYPES = {
    1: "Base Mode",
    2: "Main Mode (Identity Protection)",
    3: "Authentication Only",
    4: "Aggressive Mode",
    5: "Informational",
    32: "Quick Mode",
}

IKEV2_PAYLOAD_NAMES = {
    33: "SA",
    34: "KE",
    35: "IDi",
    36: "IDr",
    37: "CERT",
    38: "CERTREQ",
    39: "AUTH",
    40: "Ni/Nr",
    41: "N (Notify)",
    42: "D (Delete)",
    43: "V (Vendor)",
    44: "TSi",
    45: "TSr",
    46: "SK (Encrypted)",
}

IKEV1_PAYLOAD_NAMES = {
    1: "SA",
    2: "Proposal",
    3: "Transform",
    4: "KE",
    5: "ID",
    6: "CERT",
    8: "HASH",
    10: "Nonce",
    11: "Notify",
    13: "Vendor ID",
}

NOTIFY_TYPES = {
    16384: "INITIAL_CONTACT",
    16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE",
    16391: "USE_TRANSPORT_MODE",
    16430: "IKEV2_FRAGMENTATION_SUPPORTED",
}


@dataclass
class DetailedDissectionResult:
    sa: SecurityAssociation
    ike_packets: List[Packet]
    esp_packets: List[Packet]
    ah_packets: List[Packet]
    ike_timeline: List[IKEPacketSummary]


def _rate_transform(trans_type: str, trans_name: str, trans_id: int) -> str:
    upper = trans_name.upper()
    if trans_type == "ENCR":
        if any(w in upper for w in ("DES", "3DES", "NULL", "RC5", "BLOWFISH", "CAST", "IDEA")):
            return "INSECURE"
        if "GCM" in upper or "CHACHA20" in upper or "CCM" in upper:
            return "SECURE"
        if "CBC" in upper or "CTR" in upper:
            return "LEGACY"
    elif trans_type in ("PRF", "INTEG"):
        if "MD5" in upper or "SHA1" in upper or "SHA_1" in upper:
            return "INSECURE"
        if "SHA2_256" in upper or "SHA256" in upper or "SHA2_384" in upper or "SHA2_512" in upper:
            return "SECURE"
    elif trans_type == "D-H":
        if trans_id in DH_GROUPS:
            status = DH_GROUPS[trans_id][2]
            if status == DHGroupStatus.INSECURE:
                return "INSECURE"
            if status == DHGroupStatus.LEGACY:
                return "LEGACY"
            return "SECURE"
        return "INSECURE"
    elif trans_type == "ESN":
        return "SECURE" if trans_id == 1 else "LEGACY"
    return "LEGACY"


class IKEDissector:
    """Dissects IKEv1/IKEv2/ESP/AH packets from PCAP captures."""

    def parse_pcap(self, pcap_path: str) -> Tuple[SecurityAssociation, List[Packet], List[Packet]]:
        """Backwards-compatible tuple return for dissector tests."""
        detailed = self.parse_pcap_detailed(pcap_path)
        return detailed.sa, detailed.ike_packets, detailed.esp_packets

    def parse_pcap_detailed(self, pcap_path: str) -> DetailedDissectionResult:
        """Full dissection including AH packets, IKE timeline, IPv6, and replay analysis."""
        packets = rdpcap(pcap_path)
        ike_packets: List[Packet] = []
        esp_packets: List[Packet] = []
        ah_packets: List[Packet] = []
        ike_timeline: List[IKEPacketSummary] = []

        sa = SecurityAssociation(
            initiator_spi="0000000000000000",
            ike_version=ProtocolVersion.UNKNOWN,
            mode=OperatingMode.UNKNOWN,
        )

        peer_ips_set = set()
        ip_versions_seen = set()
        seen_esp_seqs: Dict[str, int] = {}
        replay_anomalies = 0

        for idx, pkt in enumerate(packets, start=1):
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                ip_versions_seen.add("IPv4")
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                ip_versions_seen.add("IPv6")

            # 1. Check for AH (Protocol 51)
            if AH in pkt or (IP in pkt and pkt[IP].proto == 51) or (IPv6 in pkt and pkt[IPv6].nh == 51):
                ah_packets.append(pkt)
                sa.ah_detected = True
                peer_ips_set.update([src_ip, dst_ip])
                continue

            # 2. Check for ESP (Protocol 50)
            if ESP in pkt or (IP in pkt and pkt[IP].proto == 50) or (IPv6 in pkt and pkt[IPv6].nh == 50):
                esp_packets.append(pkt)
                peer_ips_set.update([src_ip, dst_ip])
                if ESP in pkt:
                    spi_key = f"{src_ip}->{dst_ip}_{hex(pkt[ESP].spi)}"
                    seq = int(pkt[ESP].seq)
                    if seq == 0:
                        replay_anomalies += 1
                    elif spi_key in seen_esp_seqs and seq <= seen_esp_seqs[spi_key]:
                        replay_anomalies += 1
                    seen_esp_seqs[spi_key] = max(seen_esp_seqs.get(spi_key, 0), seq)
                continue

            # 3. Check for UDP port 500 or 4500 (IKE or NAT-T encapsulated ESP)
            if UDP in pkt and (pkt[UDP].sport in (500, 4500) or pkt[UDP].dport in (500, 4500)):
                raw_payload = bytes(pkt[UDP].payload)
                is_natt_port = (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500)

                if is_natt_port and len(raw_payload) >= 8:
                    sa.nat_traversal_detected = True
                    # Non-ESP Marker 0x00000000 indicates IKE over UDP 4500; otherwise it is NAT-T ESP
                    if raw_payload[:4] == b"\x00\x00\x00\x00":
                        raw_payload = raw_payload[4:]
                    else:
                        esp_packets.append(pkt)
                        peer_ips_set.update([src_ip, dst_ip])
                        spi_val = int.from_bytes(raw_payload[:4], "big")
                        seq_val = int.from_bytes(raw_payload[4:8], "big")
                        spi_key = f"{src_ip}->{dst_ip}_{hex(spi_val)}"
                        if seq_val == 0 or (spi_key in seen_esp_seqs and seq_val <= seen_esp_seqs[spi_key]):
                            replay_anomalies += 1
                        seen_esp_seqs[spi_key] = max(seen_esp_seqs.get(spi_key, 0), seq_val)
                        continue

                if len(raw_payload) >= 28:
                    ike_packets.append(pkt)
                    peer_ips_set.update([src_ip, dst_ip])
                    summary = self._parse_ike_header_and_payloads(
                        raw_payload, sa,
                        packet_index=idx,
                        timestamp=float(pkt.time),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=int(pkt[UDP].sport),
                        dst_port=int(pkt[UDP].dport),
                    )
                    if summary:
                        ike_timeline.append(summary)

        sa.peer_ips = sorted([p for p in peer_ips_set if p != "0.0.0.0"])
        if ip_versions_seen == {"IPv6"}:
            sa.ip_version = "IPv6"
        elif ip_versions_seen == {"IPv4", "IPv6"}:
            sa.ip_version = "IPv4 + IPv6"
        else:
            sa.ip_version = "IPv4"

        sa.replay_anomalies_detected = replay_anomalies
        if replay_anomalies > 0:
            sa.replay_protection_enabled = False

        # Detect downgrade risks across all offered proposals
        for prop in sa.proposals_offered:
            if prop.has_weak_transform:
                sa.downgrade_risk_detected = True
                break

        return DetailedDissectionResult(
            sa=sa,
            ike_packets=ike_packets,
            esp_packets=esp_packets,
            ah_packets=ah_packets,
            ike_timeline=ike_timeline,
        )

    def _parse_ike_header_and_payloads(
        self,
        raw_data: bytes,
        sa: SecurityAssociation,
        packet_index: int = 0,
        timestamp: float = 0.0,
        src_ip: str = "",
        dst_ip: str = "",
        src_port: int = 500,
        dst_port: int = 500,
    ) -> Optional[IKEPacketSummary]:
        if len(raw_data) < 28:
            return None

        initiator_spi = raw_data[0:8].hex()
        responder_spi = raw_data[8:16].hex()
        next_payload = raw_data[16]
        version_byte = raw_data[17]
        major_version = (version_byte >> 4) & 0x0F
        exchange_code = raw_data[18]
        flags = raw_data[19]
        msg_id = struct.unpack("!I", raw_data[20:24])[0]
        length = struct.unpack("!I", raw_data[24:28])[0]

        if sa.initiator_spi == "0000000000000000":
            sa.initiator_spi = initiator_spi
        if responder_spi != "0000000000000000" and not sa.responder_spi:
            sa.responder_spi = responder_spi

        payloads_seen: List[str] = []
        role = "Responder" if (flags & 0x20) or responder_spi != "0000000000000000" else "Initiator"

        if major_version == 1:
            sa.ike_version = ProtocolVersion.IKEV1
            exchange_name = IKEV1_EXCHANGE_TYPES.get(exchange_code, f"Exchange {exchange_code}")
            if exchange_code == 4:
                sa.aggressive_mode_detected = True
            self._parse_ikev1_payloads(raw_data[28:], next_payload, sa, payloads_seen)
        elif major_version == 2:
            sa.ike_version = ProtocolVersion.IKEV2
            exchange_name = IKEV2_EXCHANGE_TYPES.get(exchange_code, f"Exchange {exchange_code}")
            self._parse_ikev2_payloads(raw_data[28:], next_payload, sa, payloads_seen)
        else:
            exchange_name = f"Unknown v{major_version}"

        return IKEPacketSummary(
            packet_index=packet_index,
            timestamp=round(timestamp, 4),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            ike_version=sa.ike_version.value,
            exchange_type=exchange_name,
            role=role,
            message_id=msg_id,
            length_bytes=length if length > 0 else len(raw_data),
            initiator_spi=initiator_spi,
            responder_spi=responder_spi,
            payloads=payloads_seen,
        )

    def _parse_ikev2_payloads(
        self, data: bytes, next_payload: int, sa: SecurityAssociation, payloads_seen: List[str]
    ):
        offset = 0
        current_payload = next_payload

        while offset < len(data) and current_payload != 0:
            if offset + 4 > len(data):
                break
            nxt = data[offset]
            p_len = struct.unpack("!H", data[offset+2:offset+4])[0]
            if p_len < 4 or offset + p_len > len(data):
                p_len = len(data) - offset

            payloads_seen.append(IKEV2_PAYLOAD_NAMES.get(current_payload, f"Payload({current_payload})"))
            payload_body = data[offset+4:offset+p_len]

            if current_payload == 33:  # SA
                self._parse_ikev2_sa_payload(payload_body, sa)
            elif current_payload == 34:  # KE
                if len(payload_body) >= 2:
                    dh_num = struct.unpack("!H", payload_body[0:2])[0]
                    if dh_num in DH_GROUPS:
                        name, _, status = DH_GROUPS[dh_num]
                        sa.dh_group_number = dh_num
                        sa.dh_group = name
                        sa.dh_status = status
            elif current_payload == 41:  # Notify
                if len(payload_body) >= 4:
                    notify_type = struct.unpack("!H", payload_body[2:4])[0]
                    notify_name = NOTIFY_TYPES.get(notify_type, f"NOTIFY_{notify_type}")
                    if notify_name not in sa.notify_messages:
                        sa.notify_messages.append(notify_name)
                    if notify_type == 16391:  # USE_TRANSPORT_MODE
                        sa.mode = OperatingMode.TRANSPORT
                    elif notify_type in (16388, 16389):
                        sa.nat_traversal_detected = True

            offset += p_len
            current_payload = nxt

    def _parse_ikev2_sa_payload(self, body: bytes, sa: SecurityAssociation):
        prop_offset = 0

        while prop_offset < len(body):
            if prop_offset + 8 > len(body):
                break
            last_prop = body[prop_offset]
            prop_len = struct.unpack("!H", body[prop_offset+2:prop_offset+4])[0]
            if prop_len < 8 or prop_offset + prop_len > len(body):
                prop_len = len(body) - prop_offset

            prop_num = body[prop_offset+4]
            proto_id = body[prop_offset+5]
            spi_size = body[prop_offset+6]
            num_transforms = body[prop_offset+7]

            proto_str = "IKE" if proto_id == 1 else "AH" if proto_id == 2 else "ESP"
            proposal = IKEProposal(proposal_number=prop_num, protocol_id=proto_str)

            trans_offset = prop_offset + 8 + spi_size
            for _ in range(num_transforms):
                if trans_offset + 8 > prop_offset + prop_len:
                    break
                trans_len = struct.unpack("!H", body[trans_offset+2:trans_offset+4])[0]
                if trans_len < 8:
                    trans_len = 8

                trans_type_id = body[trans_offset+4]
                trans_id = struct.unpack("!H", body[trans_offset+6:trans_offset+8])[0]

                key_len = None
                if trans_len > 8 and trans_offset + 12 <= prop_offset + prop_len:
                    attr_type = struct.unpack("!H", body[trans_offset+8:trans_offset+10])[0]
                    if (attr_type & 0x7FFF) == 14:
                        key_len = struct.unpack("!H", body[trans_offset+10:trans_offset+12])[0]

                trans_type_name = "OTHER"
                trans_name = "Unknown"

                if trans_type_id == 1:
                    trans_type_name = "ENCR"
                    trans_name = ENCR_TRANSFORMS.get(trans_id, f"ENCR_{trans_id}")
                    if key_len:
                        trans_name += f"-{key_len}"
                    if sa.encryption_algorithm == "Unknown" or len(sa.proposals_offered) == 0:
                        sa.encryption_algorithm = trans_name
                        sa.key_length = key_len or (256 if "256" in trans_name else 128)
                elif trans_type_id == 2:
                    trans_type_name = "PRF"
                    trans_name = PRF_TRANSFORMS.get(trans_id, f"PRF_{trans_id}")
                    if not sa.prf_algorithm:
                        sa.prf_algorithm = trans_name
                elif trans_type_id == 3:
                    trans_type_name = "INTEG"
                    trans_name = INTEG_TRANSFORMS.get(trans_id, f"INTEG_{trans_id}")
                    if not sa.integrity_algorithm:
                        sa.integrity_algorithm = trans_name
                elif trans_type_id == 4:
                    trans_type_name = "D-H"
                    if trans_id in DH_GROUPS:
                        name, _, status = DH_GROUPS[trans_id]
                        trans_name = name
                        if sa.dh_group is None:
                            sa.dh_group = name
                            sa.dh_group_number = trans_id
                            sa.dh_status = status
                    else:
                        trans_name = f"Group_{trans_id}"
                        if sa.dh_group is None:
                            sa.dh_group = trans_name
                            sa.dh_group_number = trans_id
                            sa.dh_status = DHGroupStatus.INSECURE
                    sa.pfs_enabled = True
                elif trans_type_id == 5:
                    trans_type_name = "ESN"
                    trans_name = "ESN Enabled (64-bit)" if trans_id == 1 else "No ESN"
                    if trans_id == 1:
                        sa.esn_enabled = True

                rating = _rate_transform(trans_type_name, trans_name, trans_id)
                if rating == "INSECURE":
                    proposal.has_weak_transform = True

                proposal.transforms.append(
                    TransformInfo(
                        transform_type=trans_type_name,
                        transform_id=trans_id,
                        transform_name=trans_name,
                        key_length=key_len,
                        security_rating=rating,
                    )
                )
                trans_offset += trans_len

            # Store unique proposals
            sa.proposals_offered.append(proposal)
            if last_prop == 0:
                break
            prop_offset += prop_len

    def _parse_ikev1_payloads(
        self, data: bytes, next_payload: int, sa: SecurityAssociation, payloads_seen: List[str]
    ):
        offset = 0
        current_payload = next_payload

        while offset < len(data) and current_payload != 0:
            if offset + 4 > len(data):
                break
            nxt = data[offset]
            p_len = struct.unpack("!H", data[offset+2:offset+4])[0]
            if p_len < 4 or offset + p_len > len(data):
                p_len = len(data) - offset

            payloads_seen.append(IKEV1_PAYLOAD_NAMES.get(current_payload, f"Payload({current_payload})"))
            payload_body = data[offset+4:offset+p_len]

            if current_payload == 1:
                self._parse_ikev1_sa_payload(payload_body, sa)

            offset += p_len
            current_payload = nxt

    def _parse_ikev1_sa_payload(self, body: bytes, sa: SecurityAssociation):
        ikev1_ciphers = {1: "DES-CBC", 5: "3DES-CBC", 7: "AES-CBC"}
        ikev1_hashes = {1: "HMAC-MD5", 2: "HMAC-SHA1", 4: "HMAC-SHA256"}
        transforms_collected: List[TransformInfo] = []
        has_weak = False

        for i in range(len(body) - 3):
            if body[i:i+2] == b"\x80\x01":
                val = struct.unpack("!H", body[i+2:i+4])[0]
                if val in ikev1_ciphers:
                    cname = ikev1_ciphers[val]
                    sa.encryption_algorithm = cname
                    rating = _rate_transform("ENCR", cname, val)
                    if rating == "INSECURE":
                        has_weak = True
                    transforms_collected.append(TransformInfo(
                        transform_type="ENCR", transform_id=val, transform_name=cname, security_rating=rating
                    ))

            elif body[i:i+2] == b"\x80\x0e":
                klen = struct.unpack("!H", body[i+2:i+4])[0]
                if klen in (128, 192, 256):
                    sa.key_length = klen
                    if "AES" in sa.encryption_algorithm and f"-{klen}" not in sa.encryption_algorithm:
                        sa.encryption_algorithm = f"{sa.encryption_algorithm}-{klen}"

            elif body[i:i+2] == b"\x80\x02":
                val = struct.unpack("!H", body[i+2:i+4])[0]
                if val in ikev1_hashes:
                    hname = ikev1_hashes[val]
                    sa.integrity_algorithm = hname
                    rating = _rate_transform("INTEG", hname, val)
                    if rating == "INSECURE":
                        has_weak = True
                    transforms_collected.append(TransformInfo(
                        transform_type="INTEG", transform_id=val, transform_name=hname, security_rating=rating
                    ))

            elif body[i:i+2] == b"\x80\x04":
                val = struct.unpack("!H", body[i+2:i+4])[0]
                if val in DH_GROUPS:
                    name, _, status = DH_GROUPS[val]
                    sa.dh_group_number = val
                    sa.dh_group = name
                    sa.dh_status = status
                    rating = _rate_transform("D-H", name, val)
                    if rating == "INSECURE":
                        has_weak = True
                    transforms_collected.append(TransformInfo(
                        transform_type="D-H", transform_id=val, transform_name=name, security_rating=rating
                    ))

            elif body[i:i+2] == b"\x00\x0c" and i + 8 <= len(body):
                # TLV variable attribute: 0x000c <len=0x0004> <4-byte seconds>
                tlen = struct.unpack("!H", body[i+2:i+4])[0]
                if tlen == 4:
                    secs = struct.unpack("!I", body[i+4:i+8])[0]
                    if 60 <= secs <= 604800:
                        sa.sa_lifetime_seconds = secs

        if transforms_collected:
            sa.proposals_offered.append(IKEProposal(
                proposal_number=len(sa.proposals_offered) + 1,
                protocol_id="IKE",
                transforms=transforms_collected,
                has_weak_transform=has_weak,
            ))
