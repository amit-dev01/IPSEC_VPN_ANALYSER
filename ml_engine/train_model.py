"""
AI Training and Model Evaluation Pipeline for IPsec Encrypted Flow Classification.
Strictly extracts ESP/AH/NAT-T-ESP flows (excluding port 500 IKE handshakes),
fits a 14-feature ExtraTrees traffic classifier across 7 application categories
and a RandomForest operating-mode classifier, evaluates held-out metrics, and persists weights.
"""

import os
import json
import pickle
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.metrics import classification_report, accuracy_score
from scapy.all import rdpcap, ESP, AH, IP, IPv6, UDP

from backend.app.services.esp_feature_extractor import ESPFeatureExtractor

TRAFFIC_CLASS_MAP = {
    "VOIP": 0,
    "VIDEO": 1,
    "WEB": 2,
    "MESSAGING": 3,
    "WHATSAPP": 4,
    "EMAIL": 5,
    "ICMP": 6,
}

TARGET_NAMES = ["VoIP", "Video", "Web", "Messaging", "WhatsApp", "Email", "ICMP"]


def _is_esp_or_ah(pkt) -> bool:
    """Strictly identifies ESP, AH, and NAT-T encapsulated ESP (filtering out IKE port 500/4500 markers)."""
    if ESP in pkt or AH in pkt:
        return True
    if IP in pkt and pkt[IP].proto in (50, 51):
        return True
    if IPv6 in pkt and pkt[IPv6].nh in (50, 51):
        return True
    if UDP in pkt and (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500):
        raw = bytes(pkt[UDP].payload)
        return len(raw) >= 8 and raw[:4] != b"\x00\x00\x00\x00"
    return False


def train_ipsec_models(dataset_manifest_path: str = "datasets/dataset_manifest.json"):
    if not os.path.exists(dataset_manifest_path):
        raise FileNotFoundError(f"Manifest not found: {dataset_manifest_path}")

    with open(dataset_manifest_path, "r") as f:
        manifest = json.load(f)

    extractor = ESPFeatureExtractor()
    X = []
    X_mode = []
    y_traffic = []
    y_mode = []

    print("[*] Extracting clean ESP/AH features from PCAP training corpus...")
    for item in manifest:
        if item.get("split") != "train":
            continue

        pcap_path = item["path"]
        if not os.path.exists(pcap_path):
            continue

        packets = rdpcap(pcap_path)
        esp_packets = [p for p in packets if _is_esp_or_ah(p)]

        flows = extractor.extract_flows(esp_packets)
        traffic_label = TRAFFIC_CLASS_MAP.get(item["traffic_type"].upper(), 2)
        mode_label = 1 if item.get("mode") == "TUNNEL" else 0

        for flow in flows:
            feats = extractor.extract_features_vector(flow)
            X.append(feats)
            X_mode.append([
                flow.min_packet_size,
                flow.p25_packet_size,
                flow.p50_packet_size,
                flow.mean_packet_size,
                flow.max_packet_size,
            ])
            y_traffic.append(traffic_label)
            y_mode.append(mode_label)

    X_arr = np.array(X)
    X_mode_arr = np.array(X_mode)
    y_traffic_arr = np.array(y_traffic)
    y_mode_arr = np.array(y_mode)

    print(f"[*] Total clean flow feature samples: {len(X_arr)}")

    # 1. Traffic Category Classifier
    X_train, X_test, y_tr_train, y_tr_test = train_test_split(
        X_arr, y_traffic_arr, test_size=0.25, random_state=42, stratify=y_traffic_arr
    )
    traffic_model = ExtraTreesClassifier(n_estimators=150, max_depth=16, random_state=42)
    traffic_model.fit(X_train, y_tr_train)
    y_tr_pred = traffic_model.predict(X_test)

    acc = accuracy_score(y_tr_test, y_tr_pred)
    print(f"[✓] 7-Class Traffic Classification Accuracy on Test Set: {acc * 100:.2f}%")
    print("\n--- Traffic Classification Report ---")
    print(classification_report(y_tr_test, y_tr_pred, target_names=TARGET_NAMES, zero_division=0))

    # 2. Operating Mode Classifier (Tunnel vs Transport)
    Xm_train, Xm_test, ym_train, ym_test = train_test_split(
        X_mode_arr, y_mode_arr, test_size=0.25, random_state=42, stratify=y_mode_arr
    )
    mode_model = RandomForestClassifier(n_estimators=80, random_state=42)
    mode_model.fit(Xm_train, ym_train)
    mode_acc = accuracy_score(ym_test, mode_model.predict(Xm_test))
    print(f"[✓] Mode Inference Accuracy (Tunnel vs Transport): {mode_acc * 100:.2f}%")

    # Refit final traffic model on full corpus or keep trained model
    out_dir = os.path.join("ml_engine", "models")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "esp_classifier.pkl")

    with open(out_file, "wb") as f:
        pickle.dump({
            "traffic_model": traffic_model,
            "mode_model": mode_model,
            "accuracy": acc,
            "mode_accuracy": mode_acc,
        }, f)

    print(f"[✓] Successfully trained and saved production model to {out_file}")
    return out_file


if __name__ == "__main__":
    train_ipsec_models()
