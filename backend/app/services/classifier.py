"""
Encrypted IPsec Traffic Classification & Mode Inference Engine.
Uses a 14-feature ExtraTrees/RandomForest ensemble to identify 7 encapsulated application
categories (VoIP, Video, Web, Messaging, WhatsApp, Email, ICMP), predict Tunnel vs Transport
mode, emit full class probabilities, and provide explainable feature attribution.
"""

import os
import pickle
from typing import Dict, Optional
import numpy as np
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from backend.app.schemas.models import (
    ESPFlowStatistics, TrafficPrediction, TrafficCategory, OperatingMode
)
from backend.app.services.esp_feature_extractor import ESPFeatureExtractor


TRAFFIC_CLASS_MAP: Dict[int, TrafficCategory] = {
    0: TrafficCategory.VOIP,
    1: TrafficCategory.VIDEO,
    2: TrafficCategory.WEB,
    3: TrafficCategory.MESSAGING,
    4: TrafficCategory.WHATSAPP,
    5: TrafficCategory.EMAIL,
    6: TrafficCategory.ICMP,
}

CLASS_TO_INT = {v: k for k, v in TRAFFIC_CLASS_MAP.items()}


class IPsecTrafficClassifier:
    """Classifies encrypted ESP/AH traffic flows and infers IPsec operating mode."""

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or os.path.join(
            os.path.dirname(__file__), "..", "..", "..", "ml_engine", "models", "esp_classifier.pkl"
        )
        self.traffic_model: Optional[ExtraTreesClassifier] = None
        self.mode_model: Optional[RandomForestClassifier] = None
        self.extractor = ESPFeatureExtractor()
        self._initialize_or_load()

    def _initialize_or_load(self):
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    bundle = pickle.load(f)
                    tm = bundle.get("traffic_model")
                    mm = bundle.get("mode_model")
                    # Ensure schema matches 14 features & 7 classes
                    if (
                        tm is not None
                        and mm is not None
                        and getattr(tm, "n_features_in_", 0) == 14
                        and len(getattr(tm, "classes_", [])) == 7
                    ):
                        self.traffic_model = tm
                        self.mode_model = mm
                        return
            except Exception as e:
                print(f"[!] Warning loading saved model: {e}. Re-training baseline models.")

        self._train_baseline_models()

    def _train_baseline_models(self):
        """Trains fallback models across all 7 traffic categories on realistic distributions."""
        rng = np.random.default_rng(42)
        X_train = []
        y_traffic = []

        for _ in range(250):
            # 0. VoIP: 200-260B steady 20ms
            m = rng.normal(225, 14)
            X_train.append([m, rng.uniform(8, 22), 195, 270, m - 10, m, m + 10, rng.normal(20, 2), rng.uniform(1, 4), 20.0, rng.uniform(45, 55), 50 * m * 8, rng.uniform(0.01, 0.08), rng.uniform(7.8, 7.98)])
            y_traffic.append(0)

            # 1. Video: 1250-1460B rapid bursts
            m = rng.normal(1360, 45)
            X_train.append([m, rng.uniform(90, 220), 280, 1470, 1300, 1410, 1450, rng.uniform(3, 9), rng.uniform(2, 8), 5.0, rng.uniform(150, 450), 250 * m * 8, rng.uniform(0.65, 0.95), rng.uniform(7.88, 7.99)])
            y_traffic.append(1)

            # 2. Web: bimodal ~750B mean, wide std 450-600B
            m = rng.normal(760, 110)
            X_train.append([m, rng.uniform(430, 590), 170, 1470, 210, 820, 1420, rng.uniform(40, 150), rng.uniform(60, 220), 40.0, rng.uniform(10, 40), 25 * m * 8, rng.uniform(0.25, 0.55), rng.uniform(7.85, 7.99)])
            y_traffic.append(2)

            # 3. Messaging: small 120-250B, long gaps 800-3500ms
            m = rng.normal(180, 25)
            X_train.append([m, rng.uniform(20, 45), 115, 270, 145, 180, 215, rng.uniform(900, 2800), rng.uniform(450, 1400), 1100.0, rng.uniform(0.3, 1.5), 0.8 * m * 8, rng.uniform(0.0, 0.04), rng.uniform(7.75, 7.95)])
            y_traffic.append(3)

            # 4. WhatsApp: dual-mode media chunks + voice/typing keepalives (~420-580B mean, ~120-280ms IAT)
            m = rng.normal(490, 55)
            X_train.append([m, rng.uniform(180, 290), 120, 1020, 160, 480, 780, rng.uniform(110, 320), rng.uniform(80, 240), 160.0, rng.uniform(3, 12), 6 * m * 8, rng.uniform(0.10, 0.30), rng.uniform(7.8, 7.98)])
            y_traffic.append(4)

            # 5. Email (SMTP/IMAP): medium-large bursts (~880-1080B mean, pauses 150-500ms)
            m = rng.normal(960, 70)
            X_train.append([m, rng.uniform(260, 380), 260, 1460, 620, 1040, 1360, rng.uniform(140, 480), rng.uniform(120, 380), 180.0, rng.uniform(2, 9), 5 * m * 8, rng.uniform(0.15, 0.40), rng.uniform(7.85, 7.99)])
            y_traffic.append(5)

            # 6. ICMP: fixed ~100-130B, 1000ms steady
            m = rng.normal(110, 8)
            X_train.append([m, rng.uniform(0, 3), m - 2, m + 2, m, m, m, rng.normal(1000, 12), rng.uniform(0.5, 6), 1000.0, 1.0, m * 8, 0.0, rng.uniform(7.4, 7.9)])
            y_traffic.append(6)

        self.traffic_model = ExtraTreesClassifier(n_estimators=150, random_state=42)
        self.traffic_model.fit(np.array(X_train), np.array(y_traffic))

        # Mode classifier uses [min_packet_size, p25_packet_size, p50_packet_size, mean_packet_size, max_packet_size]
        X_mode = []
        y_mode = []
        for _ in range(300):
            # Tunnel mode includes +20/+40B inner IP header shift
            base_min = rng.uniform(115, 220)
            X_mode.append([base_min, base_min + 30, rng.uniform(300, 1100), rng.uniform(400, 1400), rng.uniform(1350, 1490)])
            y_mode.append(1)  # TUNNEL
            t_min = rng.uniform(80, 112)
            X_mode.append([t_min, t_min + 25, rng.uniform(250, 1050), rng.uniform(350, 1350), rng.uniform(1300, 1450)])
            y_mode.append(0)  # TRANSPORT

        self.mode_model = RandomForestClassifier(n_estimators=60, random_state=42)
        self.mode_model.fit(np.array(X_mode), np.array(y_mode))

    def predict_flow(self, flow_stats: ESPFlowStatistics) -> TrafficPrediction:
        """Classifies a single ESP/AH flow into traffic category and operating mode."""
        features = self.extractor.extract_features_vector(flow_stats)
        X = np.array([features])

        # 1. Traffic Category Prediction & Full Probability Distribution
        probs = self.traffic_model.predict_proba(X)[0]
        top_idx = int(np.argmax(probs))
        confidence = float(probs[top_idx])
        predicted_cat = TRAFFIC_CLASS_MAP.get(top_idx, TrafficCategory.UNKNOWN)

        class_probs = {
            TRAFFIC_CLASS_MAP[int(cls_id)].value: round(float(prob), 3)
            for cls_id, prob in zip(self.traffic_model.classes_, probs)
            if int(cls_id) in TRAFFIC_CLASS_MAP
        }

        # 2. Operating Mode Prediction (Tunnel vs Transport)
        mode_feats = np.array([[
            flow_stats.min_packet_size,
            flow_stats.p25_packet_size,
            flow_stats.p50_packet_size,
            flow_stats.mean_packet_size,
            flow_stats.max_packet_size,
        ]])
        mode_probs = self.mode_model.predict_proba(mode_feats)[0]
        mode_idx = int(np.argmax(mode_probs))
        inferred_mode = OperatingMode.TUNNEL if mode_idx == 1 else OperatingMode.TRANSPORT
        mode_conf = float(mode_probs[mode_idx])

        # 3. Top Contributing Features (XAI Attribution)
        importances = self.traffic_model.feature_importances_
        top_indices = np.argsort(importances)[::-1][:5]
        contributions = {
            ESPFeatureExtractor.FEATURE_NAMES[i]: round(float(features[i]), 2)
            for i in top_indices
        }

        return TrafficPrediction(
            flow_id=flow_stats.flow_id,
            predicted_category=predicted_cat,
            confidence_score=round(confidence, 3),
            inferred_mode=inferred_mode,
            mode_confidence=round(mode_conf, 3),
            top_contributing_features=contributions,
            class_probabilities=class_probs,
            anomaly_flags=flow_stats.anomaly_flags,
        )
