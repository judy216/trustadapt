"""FR-06 Trust Score engine.

Every 10 s window:
    z_i       = (x_i - mean_i) / std_i
    penalty   = P_MAX * A ** GAMMA
    penalty_i = penalty * |z_i| / sum(|z_j|)    only for features with |z| >= 2
    if A > ANOMALY_THRESHOLD: score -= penalty
    else:                     score += RECOVERY_RATE      (kept within 0-100)
A is the anomaly severity in [0, 1] from the anomaly module (FR-05).
"""

import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from trustadapt.features.schema import IoTDeviceFeatureVector

# Initial values, to be tuned in the NFR-02 experiments
P_MAX = 30.0                  # max points lost in one window
GAMMA = 1.5                   # sensitivity exponent
ANOMALY_THRESHOLD = 0.3       # A above this: window counts as anomalous
RECOVERY_RATE = 2.0           # points regained per normal window
Z_DEVIATION_THRESHOLD = 2.0   # |z| >= this: feature is blamed
MIN_STD = 1.0                 # std floor for numeric features
MIN_STD_FLAG = 0.2            # std floor for the two 0/1 flags
LEARNING_INITIAL_SCORE = 65.0  # fixed score while the 50-window baseline is built

FLAG_FIELDS = ("traffic_spike_flag", "unusual_port_flag")
ML_FEATURES = IoTDeviceFeatureVector.ML_FEATURES

# (low, high, level, access); high is inclusive for whole numbers, so the
# lookup below uses `score < high + 1` and 79.5 still falls into Suspicious.
TRUST_LEVELS = [
    (80, 100, "Trusted", "Full access"),
    (50, 79, "Suspicious", "Limited access to essential services only"),
    (20, 49, "Quarantined", "Isolated in a separate network segment, re-verification required"),
    (0, 19, "Blocked", "Fully blocked until administrator review"),
]


def from_feature_vector(fv: IoTDeviceFeatureVector) -> Dict[str, float]:
    """The 12 ML values as {name: float}."""
    return dict(zip(ML_FEATURES, fv.to_ml_input_array()))


@dataclass
class TrustScoreEngine:
    """One instance per device; keeps the score and its full history."""

    device_id: str
    score: float = LEARNING_INITIAL_SCORE
    history: List[dict] = field(default_factory=list)

    def z_scores(self, features: Dict[str, float],
                 baseline: Dict[str, Tuple[float, float]]) -> Dict[str, float]:
        z = {}
        for name, value in features.items():
            mean, std = baseline.get(name, (value, MIN_STD))
            std = max(std, MIN_STD_FLAG if name in FLAG_FIELDS else MIN_STD)
            z[name] = (value - mean) / std
        return z

    def compute_penalty(self, severity: float) -> float:
        return P_MAX * (severity ** GAMMA)

    def distribute_penalty(self, penalty: float, z: Dict[str, float]) -> Dict[str, float]:
        blamed = {k: abs(v) for k, v in z.items() if abs(v) >= Z_DEVIATION_THRESHOLD}
        if not blamed:
            top = max(z, key=lambda k: abs(z[k]))
            blamed = {top: abs(z[top])}
        total = sum(blamed.values())
        return {k: round(penalty * v / total, 2) for k, v in blamed.items()}

    def update(self, features: Dict[str, float],
               baseline: Dict[str, Tuple[float, float]], severity: float) -> dict:
        """One scoring cycle. Returns the explanation record (FR-09, FR-14)."""
        z = self.z_scores(features, baseline)
        old = self.score

        if severity > ANOMALY_THRESHOLD:
            penalty = self.compute_penalty(severity)
            contributions = self.distribute_penalty(penalty, z)
            self.score = max(0.0, self.score - penalty)
            reason = "anomaly_detected"
        else:
            penalty = 0.0
            contributions = {}
            self.score = min(100.0, self.score + RECOVERY_RATE)
            reason = "normal_behavior_recovery"

        level, access = self.trust_level()
        record = {
            "device_id": self.device_id,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "old_score": round(old, 2),
            "new_score": round(self.score, 2),
            "anomaly_score": round(severity, 3),
            "penalty": round(penalty, 2),
            "contributions": contributions,   # feature -> points lost
            "reason": reason,
            "trust_level": level,
            "access_decision": access,
        }
        self.history.append(record)
        return record

    def trust_level(self) -> Tuple[str, str]:
        for low, high, level, access in TRUST_LEVELS:
            if low <= self.score < high + 1:
                return level, access
        return "Unknown", "Unknown"


if __name__ == "__main__":
    # Camera-02 example from the Week 8 report: 85 -> 42.4 in three windows.
    baseline = {
        "packet_rate_10s": (45, 6), "bytes_sent_rate": (25_000, 4_000),
        "connection_count": (3, 1), "new_destination_count": (0, 1),
        "activity_time": (10, 1), "mean_packet_size": (555, 40),
        "std_packet_size": (310, 30), "mean_inter_arrival": (22, 5),
        "std_inter_arrival": (15, 5), "traffic_spike_flag": (0, 0),
        "unusual_port_flag": (0, 0), "failed_conn_count": (0, 0),
    }
    window = dict(zip(ML_FEATURES, [250, 300000, 18, 4, 10, 1200, 420, 4, 3, 1, 1, 14]))
    engine = TrustScoreEngine("Camera-02", score=85.0)
    for a in (0.55, 0.65, 0.62):
        r = engine.update(window, baseline, a)
        print(r["old_score"], "->", r["new_score"], r["trust_level"])
