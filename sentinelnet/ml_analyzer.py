import numpy as np
from sklearn.ensemble import IsolationForest
from config import SEVERITY_LEVELS


class BehavioralMLAnalyzer:
    """
    Uses an Isolation Forest model trained on baseline normal traffic features:
    [src_port, dst_port, packet_size, protocol_num, is_syn_only]
    """
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.08,
            random_state=42
        )
        self.is_trained = False
        self._train_default_baseline()

    def _train_default_baseline(self):
        """
        Pre-trains the Isolation Forest on representative benign network traffic
        (HTTPS/443, HTTP/80, DNS/53 with standard payload distributions).
        """
        rng = np.random.default_rng(42)
        n_samples = 400

        # Normal ephemeral source ports (49152 - 65535)
        src_ports = rng.integers(49152, 65535, size=n_samples)
        # Common destination ports (80, 443, 53, 8080)
        dst_ports = rng.choice([80, 443, 53, 8080], size=n_samples, p=[0.35, 0.45, 0.15, 0.05])
        # Normal packet sizes (64 to 1460 bytes)
        pkt_sizes = rng.normal(loc=520, scale=250, size=n_samples).clip(60, 1500)
        # Protocols: TCP (6) and UDP (17)
        protocols = np.where(dst_ports == 53, 17, 6)
        # Normal ratio of SYN-only packets vs established ACK/PSH packets
        syn_flags = rng.choice([0, 1], size=n_samples, p=[0.85, 0.15])

        X_baseline = np.column_stack([src_ports, dst_ports, pkt_sizes, protocols, syn_flags])
        self.model.fit(X_baseline)
        self.is_trained = True

    def _extract_vector(self, pkt_features: dict) -> np.ndarray:
        proto_map = {"TCP": 6, "UDP": 17, "ICMP": 1}
        proto_num = proto_map.get(pkt_features.get("protocol", "OTHER"), 0)
        is_syn = 1 if pkt_features.get("tcp_flags") == "S" else 0

        return np.array([[
            pkt_features.get("src_port", 0),
            pkt_features.get("dst_port", 0),
            pkt_features.get("packet_size", 0),
            proto_num,
            is_syn
        ]])

    def score_packet(self, pkt_features: dict) -> tuple[float, dict | None]:
        """
        Returns (anomaly_score, optional_ml_alert).
        Lower decision_function values indicate stronger anomalies.
        """
        if not self.is_trained:
            return 0.0, None

        vec = self._extract_vector(pkt_features)
        prediction = self.model.predict(vec)[0]          # -1 for anomaly, 1 for normal
        raw_score = float(self.model.decision_function(vec)[0])

        # Convert raw_score into an intuitive 0-100 anomaly metric
        normalized_score = round(max(0.0, min(100.0, (0.2 - raw_score) * 200)), 2)

        ml_alert = None
        if prediction == -1 and normalized_score >= 68.0:
            ml_alert = {
                "timestamp": pkt_features["timestamp"],
                "src_ip": pkt_features["src_ip"],
                "dst_ip": pkt_features["dst_ip"],
                "rule_id": "SN-ML-ISO",
                "alert_type": "ML Behavioral Traffic Anomaly",
                "severity": "MEDIUM" if normalized_score < 85 else "HIGH",
                "threat_score": SEVERITY_LEVELS["MEDIUM"] if normalized_score < 85 else SEVERITY_LEVELS["HIGH"],
                "description": (
                    f"Isolation Forest flagged anomalous packet structure "
                    f"(Size: {pkt_features['packet_size']}B, DstPort: {pkt_features['dst_port']}, "
                    f"Anomaly Score: {normalized_score}/100)."
                )
            }

        return normalized_score, ml_alert