# core/ml_detector.py  –  COGNITO XDR v3.0
# Multi-model ML anomaly detection: Isolation Forest + Local Outlier Factor ensemble

import threading
import numpy as np
from collections import deque

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler
    SK_AVAILABLE = True
except ImportError:
    SK_AVAILABLE = False
    print("[COGNITO] scikit-learn not available — ML detection disabled")


# ── Protocol encoding ─────────────────────────────────────────────────────────
PROTO_MAP = {"TCP": 1, "UDP": 2, "ICMP": 3, "ARP": 4, "OTHER": 0}

# ── Known malicious port patterns ─────────────────────────────────────────────
SUSPICIOUS_PORTS = {
    4444, 1337, 31337, 12345, 6666, 6667, 6668,  # common backdoors
    9001, 9030,                                    # Tor
    1080,                                          # SOCKS proxy
    8888, 9999,                                    # alt shells
}


class MLDetector:

    # Threshold for ensemble: if >= this many models vote anomaly → flag it
    VOTE_THRESHOLD = 1

    def __init__(self):
        self._lock        = threading.Lock()
        self.enabled      = SK_AVAILABLE
        self.anomaly_count = 0
        self.total_checks  = 0

        if not self.enabled:
            return

        # ── Seed training data: [size, proto_num, port_norm, port_risk, time_feature]
        seed = [
            [60,   1, 0.002, 0, 0.5],   # small TCP/HTTP
            [200,  1, 0.002, 0, 0.5],
            [500,  1, 0.006, 0, 0.5],
            [1400, 1, 0.012, 0, 0.5],
            [1500, 1, 0.006, 0, 0.5],
            [64,   2, 0.003, 0, 0.5],   # DNS UDP
            [200,  2, 0.003, 0, 0.5],
            [1400, 2, 0.003, 0, 0.5],
            [84,   3, 0.0,   0, 0.5],   # ICMP
            [300,  1, 0.005, 0, 0.5],
            [800,  1, 0.012, 0, 0.5],
            [100,  2, 0.0008,0, 0.5],
            [150,  1, 0.001, 0, 0.5],   # SMTP
        ]
        self._train_data  = seed.copy()
        self._live_buffer = []
        self._retrain_cnt = 0

        self.scaler = StandardScaler()
        self._X     = np.array(seed)
        self._X_s   = self.scaler.fit_transform(self._X)

        self.iso = IsolationForest(
            n_estimators=150,
            contamination=0.015,
            random_state=42,
            n_jobs=-1,
        )
        self.iso.fit(self._X_s)

        self.lof = LocalOutlierFactor(
            n_neighbors=20,
            contamination=0.015,
            novelty=True,
            n_jobs=-1,
        )
        self.lof.fit(self._X_s)

        print("[COGNITO] ML Detector: IsolationForest + LOF ensemble initialized")

    # ── Feature extraction ────────────────────────────────────────────────────

    def _features(self, packet: dict) -> list:
        size      = min(packet.get("size", 0), 9000)
        proto_num = PROTO_MAP.get(packet.get("protocol", "OTHER"), 0)
        port      = packet.get("dst_port", 0)
        port_norm = port / 65535.0
        port_risk = 1.0 if port in SUSPICIOUS_PORTS else 0.0

        import time
        hour_norm = (time.localtime().tm_hour) / 24.0   # off-hours = unusual
        return [size, proto_num, port_norm, port_risk, hour_norm]

    # ── Inference ─────────────────────────────────────────────────────────────

    def check(self, packet: dict) -> bool:
        if not self.enabled:
            return False

        try:
            feats = self._features(packet)
            with self._lock:
                x_s = self.scaler.transform([feats])

                votes = 0
                if self.iso.predict(x_s)[0] == -1:
                    votes += 1
                if self.lof.predict(x_s)[0] == -1:
                    votes += 1

                self.total_checks += 1
                is_anomaly = votes >= self.VOTE_THRESHOLD

                if is_anomaly:
                    self.anomaly_count += 1

                # Buffer for incremental retraining
                self._live_buffer.append(feats)
                if len(self._live_buffer) >= 300:
                    self._retrain()

            return is_anomaly

        except Exception as e:
            print(f"[COGNITO] ML check error: {e}")
            return False

    def _retrain(self):
        """Incremental retraining with live data (called under lock)."""
        combined   = self._train_data + self._live_buffer
        combined   = combined[-8000:]   # cap at 8000
        self._train_data  = combined
        self._live_buffer = []

        X_new = np.array(combined)
        X_s   = self.scaler.fit_transform(X_new)
        self._X_s = X_s

        self.iso.fit(X_s)
        self.lof.fit(X_s)
        self._retrain_cnt += 1
        print(f"[COGNITO] ML retrain #{self._retrain_cnt} on {len(combined)} samples")

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self):
        with self._lock:
            return {
                "enabled":       self.enabled,
                "total_checks":  self.total_checks,
                "anomaly_count": self.anomaly_count,
                "retrain_count": self._retrain_cnt,
                "train_samples": len(self._train_data),
            }
