"""
Encrypted IPsec Traffic Classification, Zero-Day Anomaly Scoring & SHAP Explainability Engine.
Uses LightGBM (7-class traffic classification), RandomForest (Tunnel vs Transport mode inference),
IsolationForest (unsupervised zero-day anomaly scoring), UNB ISCX-VPN2016 secondary cross-validation,
and exact per-flow Shapley values via shap.TreeExplainer.
"""

import os
import pickle
import warnings
from typing import Dict, Optional, Any
import numpy as np
import shap
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from backend.app.schemas.models import (
    ESPFlowStatistics, TrafficPrediction, TrafficCategory, OperatingMode
)
from backend.app.services.esp_feature_extractor import ESPFeatureExtractor

warnings.filterwarnings("ignore", category=UserWarning)

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
    """Classifies encrypted ESP/AH traffic flows with LightGBM + SHAP + IsolationForest."""

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or os.path.join(
            os.path.dirname(__file__), "..", "..", "..", "ml_engine", "models", "esp_classifier.pkl"
        )
        self.traffic_model: Optional[Any] = None
        self.mode_model: Optional[RandomForestClassifier] = None
        self.anomaly_detector: Optional[IsolationForest] = None
        self.iscx_model: Optional[Any] = None
        self.iscx_label_encoder: Optional[Any] = None
        self.shap_explainer: Optional[shap.TreeExplainer] = None
        self.extractor = ESPFeatureExtractor()
        self._initialize_or_load()

    def _initialize_or_load(self):
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    bundle = pickle.load(f)
                    tm = bundle.get("traffic_model")
                    mm = bundle.get("mode_model")
                    if (
                        tm is not None
                        and mm is not None
                        and getattr(tm, "n_features_in_", 0) == 14
                        and len(getattr(tm, "classes_", [])) == 7
                    ):
                        self.traffic_model = tm
                        self.mode_model = mm
                        self.anomaly_detector = bundle.get("anomaly_detector")
                        self.iscx_model = bundle.get("iscx_model")
                        self.iscx_label_encoder = bundle.get("iscx_label_encoder")
                        self.shap_explainer = shap.TreeExplainer(self.traffic_model)
                        return
            except Exception as e:
                print(f"[!] Warning loading saved model: {e}. Re-training baseline models.")

        self._train_baseline_models()

    def _train_baseline_models(self):
        """Trains LightGBM + IsolationForest fallback models if pre-trained bundle is missing."""
        rng = np.random.default_rng(42)
        X_train = []
        y_traffic = []

        for _ in range(200):
            m = rng.normal(225, 14)
            X_train.append([m, rng.uniform(8, 22), 195, 270, m - 10, m, m + 10, rng.normal(20, 2), rng.uniform(1, 4), 20.0, rng.uniform(45, 55), 50 * m * 8, rng.uniform(0.01, 0.08), rng.uniform(7.8, 7.98)])
            y_traffic.append(0)
            m = rng.normal(1360, 45)
            X_train.append([m, rng.uniform(90, 220), 280, 1470, 1300, 1410, 1450, rng.uniform(3, 9), rng.uniform(2, 8), 5.0, rng.uniform(150, 450), 250 * m * 8, rng.uniform(0.65, 0.95), rng.uniform(7.88, 7.99)])
            y_traffic.append(1)
            m = rng.normal(760, 110)
            X_train.append([m, rng.uniform(430, 590), 170, 1470, 210, 820, 1420, rng.uniform(40, 150), rng.uniform(60, 220), 40.0, rng.uniform(10, 40), 25 * m * 8, rng.uniform(0.25, 0.55), rng.uniform(7.85, 7.99)])
            y_traffic.append(2)
            m = rng.normal(180, 25)
            X_train.append([m, rng.uniform(20, 45), 115, 270, 145, 180, 215, rng.uniform(900, 2800), rng.uniform(450, 1400), 1100.0, rng.uniform(0.3, 1.5), 0.8 * m * 8, rng.uniform(0.0, 0.04), rng.uniform(7.75, 7.95)])
            y_traffic.append(3)
            m = rng.normal(490, 55)
            X_train.append([m, rng.uniform(180, 290), 120, 1020, 160, 480, 780, rng.uniform(110, 320), rng.uniform(80, 240), 160.0, rng.uniform(3, 12), 6 * m * 8, rng.uniform(0.10, 0.30), rng.uniform(7.8, 7.98)])
            y_traffic.append(4)
            m = rng.normal(960, 70)
            X_train.append([m, rng.uniform(260, 380), 260, 1460, 620, 1040, 1360, rng.uniform(140, 480), rng.uniform(120, 380), 180.0, rng.uniform(2, 9), 5 * m * 8, rng.uniform(0.15, 0.40), rng.uniform(7.85, 7.99)])
            y_traffic.append(5)
            m = rng.normal(110, 8)
            X_train.append([m, rng.uniform(0, 3), m - 2, m + 2, m, m, m, rng.normal(1000, 12), rng.uniform(0.5, 6), 1000.0, 1.0, m * 8, 0.0, rng.uniform(7.4, 7.9)])
            y_traffic.append(6)

        X_mat = np.array(X_train, dtype=float)
        self.traffic_model = LGBMClassifier(n_estimators=120, learning_rate=0.08, random_state=42, verbose=-1)
        self.traffic_model.fit(X_mat, np.array(y_traffic))
        self.shap_explainer = shap.TreeExplainer(self.traffic_model)
        self.anomaly_detector = IsolationForest(n_estimators=100, contamination=0.04, random_state=42)
        self.anomaly_detector.fit(X_mat)

        X_mode, y_mode = [], []
        for _ in range(250):
            base_min = rng.uniform(115, 220)
            X_mode.append([base_min, base_min + 30, rng.uniform(300, 1100), rng.uniform(400, 1400), rng.uniform(1350, 1490)])
            y_mode.append(1)
            t_min = rng.uniform(80, 112)
            X_mode.append([t_min, t_min + 25, rng.uniform(250, 1050), rng.uniform(350, 1350), rng.uniform(1300, 1450)])
            y_mode.append(0)

        self.mode_model = RandomForestClassifier(n_estimators=60, random_state=42)
        self.mode_model.fit(np.array(X_mode), np.array(y_mode))

    def _compute_per_flow_shap(self, X: np.ndarray, class_idx: int) -> Dict[str, float]:
        """Computes exact per-flow Shapley feature contributions via shap.TreeExplainer."""
        if self.shap_explainer is None:
            return {}
        sv = self.shap_explainer.shap_values(X)
        if isinstance(sv, list):
            vec = np.asarray(sv[class_idx][0], dtype=float)
        elif isinstance(sv, np.ndarray) and sv.ndim == 3:
            vec = np.asarray(sv[0, :, class_idx], dtype=float)
        else:
            vec = np.asarray(sv[0], dtype=float)

        ranked_idx = np.argsort(np.abs(vec))[::-1][:6]
        return {
            ESPFeatureExtractor.FEATURE_NAMES[i]: round(float(vec[i]), 3)
            for i in ranked_idx
        }

    def predict_flow(self, flow_stats: ESPFlowStatistics) -> TrafficPrediction:
        """Classifies a single ESP/AH flow with LightGBM, SHAP, Mode RF, IsolationForest, and ISCX."""
        features = self.extractor.extract_features_vector(flow_stats)
        X = np.array([features], dtype=float)

        # 1. Traffic Category Prediction & Probabilities
        probs = self.traffic_model.predict_proba(X)[0]
        top_idx = int(np.argmax(probs))
        confidence = float(probs[top_idx])
        predicted_cat = TRAFFIC_CLASS_MAP.get(int(self.traffic_model.classes_[top_idx]), TrafficCategory.UNKNOWN)

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

        # 3. True Per-Flow SHAP Explanations
        shap_explanations = self._compute_per_flow_shap(X, top_idx)
        top_features = {
            fname: round(float(features[ESPFeatureExtractor.FEATURE_NAMES.index(fname)]), 2)
            for fname in list(shap_explanations.keys())[:5]
        }

        # 4. Unsupervised Zero-Day Anomaly Scoring (IsolationForest)
        anomaly_flags = list(flow_stats.anomaly_flags)
        anomaly_score = 0.0
        if self.anomaly_detector is not None:
            raw_decision = float(self.anomaly_detector.decision_function(X)[0])
            # decision_function < 0 means outlier; sigmoid maps smoothly into [0, 1]
            anomaly_score = round(float(1.0 / (1.0 + np.exp(raw_decision * 8.0))), 3)
            if anomaly_score >= 0.70 and "ML_OUTLIER_ANOMALY" not in anomaly_flags:
                anomaly_flags.append("ML_OUTLIER_ANOMALY")

        # 5. Secondary Cross-Validation from UNB ISCX-VPN2016 LightGBM Model
        iscx_pred_str: Optional[str] = None
        if (
            self.iscx_model is not None
            and self.iscx_label_encoder is not None
            and len(flow_stats.iscx_features) == 23
        ):
            iscx_X = np.array([flow_stats.iscx_features], dtype=float)
            iscx_probs = self.iscx_model.predict_proba(iscx_X)[0]
            iscx_idx = int(np.argmax(iscx_probs))
            iscx_label = str(self.iscx_label_encoder.inverse_transform([iscx_idx])[0])
            iscx_conf = int(round(float(iscx_probs[iscx_idx]) * 100))
            iscx_pred_str = f"{iscx_label} ({iscx_conf}%)"

        return TrafficPrediction(
            flow_id=flow_stats.flow_id,
            predicted_category=predicted_cat,
            confidence_score=round(confidence, 3),
            inferred_mode=inferred_mode,
            mode_confidence=round(mode_conf, 3),
            top_contributing_features=top_features,
            shap_explanations=shap_explanations,
            class_probabilities=class_probs,
            anomaly_score=anomaly_score,
            iscx_secondary_prediction=iscx_pred_str,
            anomaly_flags=anomaly_flags,
        )
