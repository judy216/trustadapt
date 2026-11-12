"""FR-05 per-device anomaly detection (Isolation Forest).

One model per device, trained on that device's own baseline windows (FR-04).
severity() returns A in [0, 1] (1 = most anomalous), the input of the
Trust Score engine (FR-06).
"""

from dataclasses import dataclass, field
from typing import Dict, List

import numpy as np
from sklearn.ensemble import IsolationForest


@dataclass
class DeviceAnomalyDetector:
    device_mac: str
    model: IsolationForest = field(default=None, repr=False)
    score_min: float = -0.5   # calibrated in train()
    score_max: float = 0.5

    def train(self, baseline_vectors: List, contamination: float = 0.02,
              n_estimators: int = 150, random_state: int = 42) -> None:
        """baseline_vectors: IoTDeviceFeatureVector objects from the 50
        LEARNING windows of this device."""
        X = np.array([fv.to_ml_input_array() for fv in baseline_vectors])
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
        )
        self.model.fit(X)
        # Scale A with the model's scores on its own baseline. The 1st/99th
        # percentile keeps one noisy window from stretching the scale.
        base = self.model.decision_function(X)
        self.score_min = float(np.percentile(base, 1))
        self.score_max = float(np.percentile(base, 99))

    def raw_score(self, vector) -> float:
        """decision_function output; LOWER means more anomalous."""
        if self.model is None:
            raise RuntimeError(f"Device {self.device_mac} has no trained model yet.")
        x = np.array([vector.to_ml_input_array()])
        return float(self.model.decision_function(x)[0])

    def severity(self, vector) -> float:
        """Anomaly severity A in [0, 1], 1 = most anomalous."""
        raw = self.raw_score(vector)
        if self.score_max == self.score_min:
            return 0.0
        a = (self.score_max - raw) / (self.score_max - self.score_min)
        return float(max(0.0, min(1.0, a)))


class AnomalyDetectorRegistry:
    """One DeviceAnomalyDetector per device_mac."""

    def __init__(self):
        self._detectors: Dict[str, DeviceAnomalyDetector] = {}

    def train_device(self, device_mac: str, baseline_vectors: List, **kwargs):
        detector = DeviceAnomalyDetector(device_mac=device_mac)
        detector.train(baseline_vectors, **kwargs)
        self._detectors[device_mac] = detector
        return detector

    def get(self, device_mac: str) -> DeviceAnomalyDetector:
        if device_mac not in self._detectors:
            raise KeyError(f"No trained model for device {device_mac} yet.")
        return self._detectors[device_mac]
