"""
Dual-Track AI Training, Benchmarking, and Evaluation Pipeline.
Track 1: Validates LightGBM, XGBoost, ExtraTrees, and Neural MLP via 5-Fold Stratified CV
         on the real-world UNB ISCX-VPN2016 dataset (9,793 VPN flows across 7 classes).
Track 2: Trains the IPsec Packet-Shape LightGBM Classifier + Tunnel/Transport Mode Classifier
         + Unsupervised IsolationForest Zero-Day Anomaly Detector on sliding-window ESP flows,
         computes SHAP global feature importance, and exports evaluation_metrics.json.
"""

import json
import os
import pickle
import time
import warnings
from typing import Dict, Any, List
import numpy as np
import pandas as pd
from scipy.io import arff
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, classification_report
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier, IsolationForest
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import make_pipeline
from lightgbm import LGBMClassifier
from xgboost import XGBClassifier
import shap
from scapy.all import rdpcap, ESP, AH, IP, IPv6, UDP

from backend.app.services.esp_feature_extractor import ESPFeatureExtractor, ISCX_FEATURE_NAMES

warnings.filterwarnings("ignore", category=UserWarning)

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


def _benchmark_models(X: np.ndarray, y: np.ndarray, class_names: List[str], n_splits: int = 5) -> Dict[str, Any]:
    """Runs 5-Fold Stratified CV across 4 distinct ML architectures and returns detailed metrics."""
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    models = {
        "LightGBM": LGBMClassifier(n_estimators=180, learning_rate=0.08, num_leaves=31, random_state=42, verbose=-1),
        "XGBoost": XGBClassifier(n_estimators=160, learning_rate=0.08, max_depth=6, random_state=42, eval_metric="mlogloss"),
        "ExtraTrees": ExtraTreesClassifier(n_estimators=180, max_depth=18, random_state=42),
        "Neural MLP": make_pipeline(StandardScaler(), MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=300, random_state=42)),
    }

    leaderboard = []
    best_preds = None
    best_model_name = "LightGBM"
    best_f1 = -1.0

    for name, clf in models.items():
        t0 = time.perf_counter()
        preds = cross_val_predict(clf, X, y, cv=skf)
        elapsed = time.perf_counter() - t0
        acc = float(accuracy_score(y, preds))
        macro_f1 = float(f1_score(y, preds, average="macro", zero_division=0))
        weighted_f1 = float(f1_score(y, preds, average="weighted", zero_division=0))
        leaderboard.append({
            "model": name,
            "cv_accuracy": round(acc * 100, 2),
            "macro_f1": round(macro_f1 * 100, 2),
            "weighted_f1": round(weighted_f1 * 100, 2),
            "cv_time_sec": round(elapsed, 2),
        })
        if weighted_f1 > best_f1:
            best_f1 = weighted_f1
            best_preds = preds
            best_model_name = name

    cm = confusion_matrix(y, best_preds).tolist()
    report_dict = classification_report(y, best_preds, target_names=class_names, output_dict=True, zero_division=0)
    per_class = [
        {
            "label": cls_name,
            "precision": round(report_dict[cls_name]["precision"] * 100, 1),
            "recall": round(report_dict[cls_name]["recall"] * 100, 1),
            "f1_score": round(report_dict[cls_name]["f1-score"] * 100, 1),
            "support": int(report_dict[cls_name]["support"]),
        }
        for cls_name in class_names
        if cls_name in report_dict
    ]

    return {
        "best_model": best_model_name,
        "leaderboard": sorted(leaderboard, key=lambda x: x["cv_accuracy"], reverse=True),
        "confusion_matrix": cm,
        "class_names": class_names,
        "per_class_metrics": per_class,
        "total_samples": int(len(y)),
        "cv_folds": n_splits,
    }


def benchmark_iscx_vpn2016(arff_path: str = "datasets/external/iscx_a2_vpn_15s.arff") -> Dict[str, Any]:
    """Benchmarks real-world UNB ISCX-VPN2016 (9,793 flows) and trains production LightGBM cross-validator."""
    if not os.path.exists(arff_path):
        print(f"[!] External ISCX dataset not found at {arff_path}; skipping real-world benchmark.")
        return {}

    print(f"[*] Loading UNB ISCX-VPN2016 dataset from {arff_path}...")
    raw_data, _ = arff.loadarff(arff_path)
    df = pd.DataFrame(raw_data)
    df["label"] = df["class1"].apply(lambda v: v.decode("utf-8") if isinstance(v, bytes) else str(v))
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    X = df[ISCX_FEATURE_NAMES].values.astype(float)
    le = LabelEncoder()
    y = le.fit_transform(df["label"].values)
    class_names = [str(c) for c in le.classes_]

    print(f"[*] Benchmarking 4 ML models on {len(X)} real-world VPN flows ({len(class_names)} classes) via 5-Fold CV...")
    metrics = _benchmark_models(X, y, class_names, n_splits=5)
    for row in metrics["leaderboard"]:
        print(f"    - {row['model']:12s}: CV Acc={row['cv_accuracy']}% | Macro-F1={row['macro_f1']}% | {row['cv_time_sec']}s")

    # Fit production ISCX LightGBM model on full dataset
    iscx_lgbm = LGBMClassifier(n_estimators=220, learning_rate=0.08, num_leaves=45, random_state=42, verbose=-1)
    iscx_lgbm.fit(X, y)

    return {
        "metrics": metrics,
        "model": iscx_lgbm,
        "label_encoder": le,
    }


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

    print("[*] Extracting sliding-window ESP/AH flow samples from IPsec PCAP corpus...")
    for item in manifest:
        if item.get("split") != "train":
            continue
        pcap_path = item["path"]
        if not os.path.exists(pcap_path):
            continue

        packets = rdpcap(pcap_path)
        esp_packets = [p for p in packets if _is_esp_or_ah(p)]
        windowed_flows = extractor.extract_windowed_flows(esp_packets, window_size=25, stride=20)
        traffic_label = TRAFFIC_CLASS_MAP.get(item["traffic_type"].upper(), 2)
        mode_label = 1 if item.get("mode") == "TUNNEL" else 0

        for flow in windowed_flows:
            X.append(extractor.extract_features_vector(flow))
            X_mode.append([
                flow.min_packet_size,
                flow.p25_packet_size,
                flow.p50_packet_size,
                flow.mean_packet_size,
                flow.max_packet_size,
            ])
            y_traffic.append(traffic_label)
            y_mode.append(mode_label)

    X_arr = np.array(X, dtype=float)
    X_mode_arr = np.array(X_mode, dtype=float)
    y_traffic_arr = np.array(y_traffic, dtype=int)
    y_mode_arr = np.array(y_mode, dtype=int)

    print(f"[*] Extracted {len(X_arr)} windowed IPsec flow samples across 7 classes.")
    ipsec_metrics = _benchmark_models(X_arr, y_traffic_arr, TARGET_NAMES, n_splits=5)
    for row in ipsec_metrics["leaderboard"]:
        print(f"    - {row['model']:12s}: CV Acc={row['cv_accuracy']}% | Macro-F1={row['macro_f1']}%")

    # Fit primary LightGBM IPsec Classifier
    traffic_model = LGBMClassifier(n_estimators=180, learning_rate=0.08, num_leaves=31, random_state=42, verbose=-1)
    traffic_model.fit(X_arr, y_traffic_arr)

    # Compute Global SHAP Feature Importance via TreeExplainer
    print("[*] Computing SHAP global feature attributions...")
    explainer = shap.TreeExplainer(traffic_model)
    sample_idx = np.linspace(0, len(X_arr) - 1, min(120, len(X_arr)), dtype=int)
    sv = explainer.shap_values(X_arr[sample_idx])
    if isinstance(sv, list):
        mean_abs_shap = np.mean([np.mean(np.abs(cls_sv), axis=0) for cls_sv in sv], axis=0)
    elif isinstance(sv, np.ndarray) and sv.ndim == 3:
        mean_abs_shap = np.mean(np.abs(sv), axis=(0, 2))
    else:
        mean_abs_shap = np.mean(np.abs(sv), axis=0)

    shap_global = sorted(
        [
            {"feature": fname, "mean_abs_shap": round(float(val), 4)}
            for fname, val in zip(ESPFeatureExtractor.FEATURE_NAMES, mean_abs_shap)
        ],
        key=lambda d: d["mean_abs_shap"],
        reverse=True,
    )

    # Fit Mode Classifier (5-Fold CV check + fit)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    mode_model = RandomForestClassifier(n_estimators=100, random_state=42)
    mode_cv_preds = cross_val_predict(mode_model, X_mode_arr, y_mode_arr, cv=skf)
    mode_acc = float(accuracy_score(y_mode_arr, mode_cv_preds))
    mode_model.fit(X_mode_arr, y_mode_arr)
    print(f"[✓] Mode Classifier 5-Fold CV Accuracy (Tunnel vs Transport): {mode_acc * 100:.2f}%")

    # Fit Unsupervised IsolationForest Zero-Day Anomaly Detector on normal IPsec flows
    anomaly_detector = IsolationForest(n_estimators=150, contamination=0.04, random_state=42)
    anomaly_detector.fit(X_arr)
    print("[✓] Fitted IsolationForest zero-day flow anomaly detector.")

    # Track 1: Real-world UNB ISCX-VPN2016 Benchmark
    iscx_bundle = benchmark_iscx_vpn2016()

    out_dir = os.path.join("ml_engine", "models")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "esp_classifier.pkl")

    with open(out_file, "wb") as f:
        pickle.dump({
            "traffic_model": traffic_model,
            "mode_model": mode_model,
            "anomaly_detector": anomaly_detector,
            "iscx_model": iscx_bundle.get("model"),
            "iscx_label_encoder": iscx_bundle.get("label_encoder"),
            "accuracy": ipsec_metrics["leaderboard"][0]["cv_accuracy"] / 100.0,
            "mode_accuracy": mode_acc,
        }, f)

    metrics_payload = {
        "ipsec_windowed_benchmark": ipsec_metrics,
        "mode_cv_accuracy": round(mode_acc * 100, 2),
        "global_shap_importance": shap_global,
        "iscx_vpn2016_benchmark": iscx_bundle.get("metrics", {}),
        "anomaly_detector": {
            "algorithm": "IsolationForest",
            "n_estimators": 150,
            "contamination": 0.04,
            "training_flows": int(len(X_arr)),
        },
    }
    metrics_path = os.path.join(out_dir, "evaluation_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics_payload, f, indent=2)

    print(f"[✓] Saved production models to {out_file} and metrics to {metrics_path}")
    return out_file


if __name__ == "__main__":
    train_ipsec_models()
