"""
Active IKE Gateway Scanner ("SSL Labs for IPsec").
Sends non-destructive IKEv2 IKE_SA_INIT and IKEv1 Main Mode proposal probes over UDP
to determine which cryptographic suites and DH groups a VPN gateway accepts or rejects.
Includes an ephemeral RFC-compliant local loopback responder for offline lab targets
('demo-hardened-gw', 'demo-vulnerable-gw').
"""

import os
import socket
import struct
import threading
import time
import uuid
from typing import List, Tuple, Optional
from backend.app.schemas.models import (
    ActiveScanRequest, ActiveScanResult, CipherProbeResult, SeverityLevel
)


PROBE_SUITES = [
    {
        "suite_name": "IKEv2 AEAD Hardened (AES-256-GCM / SHA-384 / ECP-256)",
        "ike_version": "IKEv2",
        "encryption": "AES-256-GCM-16",
        "integrity": "PRF_HMAC_SHA2_384",
        "dh_group": "Group 19 (256-bit ECP)",
        "grade": SeverityLevel.LOW,
        "encr_id": 20, "key_len": 256, "prf_id": 4, "integ_id": None, "dh_id": 19,
    },
    {
        "suite_name": "IKEv2 Enterprise Standard (AES-128-CBC / SHA-256 / MODP-2048)",
        "ike_version": "IKEv2",
        "encryption": "AES-128-CBC",
        "integrity": "AUTH_HMAC_SHA2_256_128",
        "dh_group": "Group 14 (2048-bit MODP)",
        "grade": SeverityLevel.LOW,
        "encr_id": 12, "key_len": 128, "prf_id": 3, "integ_id": 12, "dh_id": 14,
    },
    {
        "suite_name": "IKEv2 Legacy Weak (AES-128-CBC / SHA-1 / MODP-1536)",
        "ike_version": "IKEv2",
        "encryption": "AES-128-CBC",
        "integrity": "AUTH_HMAC_SHA1_96",
        "dh_group": "Group 5 (1536-bit MODP)",
        "grade": SeverityLevel.HIGH,
        "encr_id": 12, "key_len": 128, "prf_id": 2, "integ_id": 2, "dh_id": 5,
    },
    {
        "suite_name": "IKEv2 Critical Legacy (3DES-CBC / MD5 / MODP-1024)",
        "ike_version": "IKEv2",
        "encryption": "3DES-CBC",
        "integrity": "AUTH_HMAC_MD5_96",
        "dh_group": "Group 2 (1024-bit MODP)",
        "grade": SeverityLevel.CRITICAL,
        "encr_id": 3, "key_len": None, "prf_id": 1, "integ_id": 1, "dh_id": 2,
    },
    {
        "suite_name": "IKEv1 Deprecated (3DES-CBC / MD5 / MODP-1024)",
        "ike_version": "IKEv1",
        "encryption": "3DES-CBC",
        "integrity": "HMAC-MD5",
        "dh_group": "Group 2 (1024-bit MODP)",
        "grade": SeverityLevel.CRITICAL,
        "encr_id": 5, "key_len": None, "prf_id": None, "integ_id": 1, "dh_id": 2,
    },
]


def _build_ikev2_probe(suite: dict) -> bytes:
    """Crafts a valid IKEv2 IKE_SA_INIT probe packet for a specific transform suite."""
    spi_i = os.urandom(8)
    transforms = []

    # ENCR transform
    if suite["key_len"]:
        transforms.append(
            b"\x03\x00\x00\x0c\x01\x00" + struct.pack("!H", suite["encr_id"]) +
            b"\x80\x0e" + struct.pack("!H", suite["key_len"])
        )
    else:
        transforms.append(b"\x03\x00\x00\x08\x01\x00" + struct.pack("!H", suite["encr_id"]))

    # PRF transform
    transforms.append(b"\x03\x00\x00\x08\x02\x00" + struct.pack("!H", suite["prf_id"]))

    # Optional INTEG transform (non-AEAD)
    if suite["integ_id"] is not None:
        transforms.append(b"\x03\x00\x00\x08\x03\x00" + struct.pack("!H", suite["integ_id"]))

    # DH transform (last transform -> byte 0 = 0x00)
    transforms.append(b"\x00\x00\x00\x08\x04\x00" + struct.pack("!H", suite["dh_id"]))

    trans_bytes = b"".join(transforms)
    prop_len = 8 + len(trans_bytes)
    prop_bytes = b"\x00\x00" + struct.pack("!H", prop_len) + bytes([1, 1, 0, len(transforms)]) + trans_bytes
    sa_payload = b"\x22\x00" + struct.pack("!H", 4 + len(prop_bytes)) + prop_bytes

    ke_pub = os.urandom(64 if suite["dh_id"] == 19 else 128)
    ke_payload = b"\x28\x00" + struct.pack("!H", 8 + len(ke_pub)) + struct.pack("!HH", suite["dh_id"], 0) + ke_pub
    nonce_payload = b"\x00\x00\x00\x24" + os.urandom(32)

    body = sa_payload + ke_payload + nonce_payload
    total_len = 28 + len(body)
    header = spi_i + b"\x00" * 8 + b"\x21\x20\x22\x08\x00\x00\x00\x00" + struct.pack("!I", total_len)
    return header + body


def _build_ikev1_probe() -> bytes:
    """Crafts a legacy IKEv1 Main Mode probe offering 3DES + MD5 + Group 2."""
    icookie = os.urandom(8)
    trans = (
        b"\x00\x00\x00\x28\x01\x01\x00\x00"
        b"\x80\x01\x00\x05\x80\x02\x00\x01\x80\x03\x00\x01\x80\x04\x00\x02"
        b"\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x00\x0e\x10"
    )
    sa_payload = (
        b"\x00\x00\x00" + bytes([len(trans) + 12]) +
        b"\x00\x00\x00\x01\x00\x00\x00" + bytes([len(trans) + 4]) + trans
    )
    total_len = 28 + len(sa_payload)
    header = icookie + b"\x00" * 8 + b"\x01\x10\x02\x00\x00\x00\x00\x00" + struct.pack("!I", total_len)
    return header + sa_payload


class _EphemeralDemoResponder:
    """
    Spins up a local UDP socket responder on 127.0.0.1 for demo lab targets
    ('demo-hardened-gw' and 'demo-vulnerable-gw'), replying with genuine IKE packets.
    """

    def __init__(self, hardened: bool):
        self.hardened = hardened
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while self._running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            if len(data) < 28:
                continue

            spi_i = data[0:8]
            spi_r = os.urandom(8)
            major_ver = (data[17] >> 4) & 0x0F

            if major_ver == 1:
                # IKEv1: hardened rejects (empty/Notify), vulnerable echoes SA acceptance
                if self.hardened:
                    # Notify NO_PROPOSAL_CHOSEN (14)
                    notify = b"\x00\x00\x00\x0c\x00\x00\x00\x01\x01\x00\x00\x0e"
                    hdr = spi_i + spi_r + b"\x0b\x10\x05\x00\x00\x00\x00\x00" + struct.pack("!I", 28 + len(notify))
                    self.sock.sendto(hdr + notify, addr)
                else:
                    hdr = spi_i + spi_r + data[16:24] + data[24:]
                    self.sock.sendto(hdr, addr)
            elif major_ver == 2:
                # Inspect offered DH Group or Encryption ID
                has_weak = (
                    b"\x01\x00\x00\x03" in data or  # 3DES
                    b"\x04\x00\x00\x02" in data or  # Group 2
                    b"\x04\x00\x00\x05" in data     # Group 5
                )
                if self.hardened and has_weak:
                    # Respond with IKEv2 Notify Payload (41) -> NO_PROPOSAL_CHOSEN (14)
                    notify = b"\x00\x00\x00\x08\x00\x00\x00\x0e"
                    hdr = spi_i + spi_r + b"\x29\x20\x22\x20\x00\x00\x00\x00" + struct.pack("!I", 28 + len(notify))
                    self.sock.sendto(hdr + notify, addr)
                else:
                    # Accept proposal -> respond with SA + KE + Nonce
                    hdr = spi_i + spi_r + b"\x21\x20\x22\x20\x00\x00\x00\x00" + data[24:]
                    self.sock.sendto(hdr, addr)

    def stop(self):
        self._running = False
        try:
            self.sock.close()
        except OSError:
            pass


class ActiveIKEGatewayScanner:
    """Probes live IPsec VPN endpoints (or local demo gateways) to audit supported cipher suites."""

    def scan(self, req: ActiveScanRequest) -> ActiveScanResult:
        scan_id = str(uuid.uuid4())[:8]
        target = req.target_host.strip()
        responder: Optional[_EphemeralDemoResponder] = None
        probe_host = target
        probe_port = req.port

        if target.lower() in ("demo-hardened-gw", "demo-vulnerable-gw"):
            hardened_mode = target.lower() == "demo-hardened-gw"
            responder = _EphemeralDemoResponder(hardened=hardened_mode)
            probe_host = "127.0.0.1"
            probe_port = responder.port

        probes: List[CipherProbeResult] = []
        any_reachable = False

        try:
            for suite in PROBE_SUITES:
                pkt = _build_ikev1_probe() if suite["ike_version"] == "IKEv1" else _build_ikev2_probe(suite)
                accepted, rtt_ms, detail, responded = self._send_probe(probe_host, probe_port, pkt, req.timeout_seconds)
                if responded:
                    any_reachable = True
                probes.append(CipherProbeResult(
                    suite_name=suite["suite_name"],
                    ike_version=suite["ike_version"],
                    encryption=suite["encryption"],
                    integrity=suite["integrity"],
                    dh_group=suite["dh_group"],
                    accepted=accepted,
                    security_grade=suite["grade"],
                    response_time_ms=round(rtt_ms, 2),
                    details=detail,
                ))
        finally:
            if responder:
                responder.stop()

        accepted_probes = [p for p in probes if p.accepted]
        weak_accepted = [p for p in accepted_probes if p.security_grade in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)]

        if not any_reachable:
            grade = "UNREACHABLE"
            summary = f"No IKE response received on {target}:{req.port}/UDP within {req.timeout_seconds}s."
            recs = [
                f"Verify UDP ports 500/4500 are reachable on {target}.",
                "For local testing without an external VPN gateway, target 'demo-hardened-gw' or 'demo-vulnerable-gw'."
            ]
        elif weak_accepted:
            grade = "F" if any(p.security_grade == SeverityLevel.CRITICAL for p in weak_accepted) else "C"
            summary = f"Target {target} accepted {len(weak_accepted)} weak/deprecated suite(s) alongside {len(accepted_probes) - len(weak_accepted)} strong suite(s)."
            recs = [
                f"Disable {p.suite_name} immediately on gateway {target}."
                for p in weak_accepted
            ]
            recs.append("Enforce IKEv2 AEAD (AES-256-GCM) with ECDH Group 19+ only.")
        elif accepted_probes:
            has_cbc = any("CBC" in p.encryption for p in accepted_probes)
            grade = "A-" if has_cbc else "A+"
            summary = f"Gateway {target} rejected all weak/legacy IKEv1/3DES/DH<14 probes and only negotiates modern suites."
            recs = ["Gateway passes baseline NIST SP 800-77 cipher hygiene. Plan RFC 9370 ML-KEM hybrid PQC rollout."]
        else:
            grade = "B"
            summary = f"Target {target} responded to IKE probes but rejected all standard suites (custom/certificate-only policy)."
            recs = ["Inspect custom vendor transform requirements on target gateway."]

        return ActiveScanResult(
            scan_id=scan_id,
            target_host=target,
            port=req.port,
            reachable=any_reachable,
            overall_grade=grade,
            summary=summary,
            probes=probes,
            recommendations=recs,
        )

    def _send_probe(self, host: str, port: int, payload: bytes, timeout: float) -> Tuple[bool, float, str, bool]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start = time.perf_counter()
        try:
            sock.sendto(payload, (host, port))
            resp, _ = sock.recvfrom(4096)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            if len(resp) < 28:
                return False, elapsed_ms, "Malformed short IKE response", True

            next_payload = resp[16]
            # Check for Notify Payload (IKEv2=41/0x29, IKEv1=11/0x0b) carrying NO_PROPOSAL_CHOSEN (14)
            if next_payload in (41, 11):
                if len(resp) >= 36:
                    notify_code = struct.unpack("!H", resp[-2:])[0]
                    if notify_code == 14:
                        return False, elapsed_ms, "Rejected (NO_PROPOSAL_CHOSEN)", True
                return False, elapsed_ms, "Rejected with IKE Notify alert", True

            if next_payload in (33, 1):
                return True, elapsed_ms, "Accepted (Responder returned SA proposal)", True

            return False, elapsed_ms, f"Non-SA IKE response (next payload {next_payload})", True
        except socket.timeout:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return False, elapsed_ms, "Timed out (filtered or silent drop)", False
        except OSError as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return False, elapsed_ms, f"Socket error: {exc}", False
        finally:
            sock.close()
