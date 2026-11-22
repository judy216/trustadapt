"""FR-05 per-device anomaly detection (Week 10: calibrated, Isolation Forest + z-scores).

The model is NOT trained here. baseline/baseline_profile.py is the only place a model is built
(one Isolation Forest per device on its first 50 windows, 12-value vector in ML_FEATURES order);
this module reads that BaselineProfile and turns a new window into a severity A in [0, 1],
the input of the Trust Score engine (FR-06).

    A_iforest = 0                                   if decision_function >= if_threshold
              = 0.3 + 0.7 * (1 - exp(-d / if_spread)) otherwise, d = if_threshold - decision_function
    A_z       = 0                                   if max|z| <= z_threshold
              = 0.3 + 0.7 * (1 - exp(-e / z_threshold)) otherwise, e = max|z| - z_threshold
    A         = max(A_iforest, A_z), and 0 if no feature has |z| >= 2

Both thresholds are learned out of fold in baseline_profile.py, so a normal window gets A = 0 and the
engine rule "A > 0.3 = anomalous" fires exactly when a window is beyond what held-out normal windows
reached. Isolation Forest catches unusual combinations; the z part catches a single feature far outside
its range, including features that were always 0 in the baseline (flags, failed_conn_count), which
Isolation Forest never splits on. A window with no feature at |z| >= 2 gets no penalty, because the
FR-06 penalty split and the FR-09 explanation need at least one blamed feature.
"""

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd

from trustadapt.baseline.baseline_profile import FEATURES, BaselineProfile, build_baseline

ANOMALY_LEVEL = 0.3        # A just above a threshold (= engine ANOMALY_THRESHOLD)
BLAME_Z = 2.0              # same as engine Z_DEVIATION_THRESHOLD


def _as_array(vector) -> np.ndarray:
    """IoTDeviceFeatureVector, dict {feature: value} or 12 values in FEATURES order -> array (12,)."""
    if hasattr(vector, "to_ml_input_array"):
        x = vector.to_ml_input_array()
    elif isinstance(vector, dict):
        x = [vector[f] for f in FEATURES]
    else:
        x = vector
    x = np.asarray(x, dtype=float)
    if x.shape != (len(FEATURES),):
        raise ValueError(f"expected {len(FEATURES)} values in ML_FEATURES order, got shape {x.shape}")
    return x


def _ramp(excess: float, spread: float) -> float:
    """0 at or below the threshold; ANOMALY_LEVEL just above it, rising smoothly towards 1."""
    if excess <= 0:
        return 0.0
    return ANOMALY_LEVEL + (1.0 - ANOMALY_LEVEL) * (1.0 - math.exp(-excess / max(spread, 1e-9)))


@dataclass
class DeviceAnomalyDetector:
    device_mac: str
    profile: BaselineProfile = field(default=None, repr=False)

    def train(self, baseline_vectors: List, allow_suspect: bool = False) -> None:
        """Kept for compatibility: builds the profile with baseline_profile.build_baseline()."""
        rows = pd.DataFrame([{"window_start": fv.window_start, **dict(zip(FEATURES, fv.to_ml_input_array()))}
                             for fv in baseline_vectors])
        self.profile = build_baseline(self.device_mac, rows, n_windows=len(rows), allow_suspect=allow_suspect)

    def _check(self):
        if self.profile is None:
            raise RuntimeError(f"Device {self.device_mac} has no baseline profile yet.")

    def raw_score(self, vector) -> float:
        """decision_function output; LOWER means more anomalous."""
        self._check()
        return float(self.profile.model.decision_function(_as_array(vector).reshape(1, -1))[0])

    def explain(self, vector) -> Dict:
        """Severity and its parts for one window (for the dashboard and the explanation record)."""
        self._check()
        p = self.profile
        x = _as_array(vector)
        raw = float(p.model.decision_function(x.reshape(1, -1))[0])
        z = p.z_scores(x)
        max_z = float(np.abs(z).max())
        a_if = _ramp(p.if_threshold - raw, p.if_spread)
        a_z = _ramp(max_z - p.z_threshold, p.z_threshold)
        if max_z < BLAME_Z:                     # nothing to blame -> no penalty
            a_if = a_z = 0.0
        sev = max(a_if, a_z)
        return {
            "severity": sev, "a_iforest": a_if, "a_zscore": a_z,
            "if_score": raw, "max_abs_z": max_z,
            "source": "" if sev == 0 else ("iforest" if a_if >= a_z else "zscore"),
            "z": dict(zip(FEATURES, (float(v) for v in z))),
        }

    def severity(self, vector) -> float:
        """Anomaly severity A in [0, 1]; 0 = normal, > 0.3 = anomalous."""
        return self.explain(vector)["severity"]

    def engine_baseline(self) -> Dict[str, tuple]:
        """{feature: (mean, std)} in the format TrustScoreEngine.update() expects (std already floored)."""
        self._check()
        return {f: (float(m), float(s)) for f, m, s in zip(FEATURES, self.profile.mean, self.profile.std)}

    def score_table(self, rows: pd.DataFrame) -> pd.DataFrame:
        """One output row per window of a feature table (one device)."""
        out = []
        for _, r in rows.sort_values("window_start").iterrows():
            e = self.explain([r[f] for f in FEATURES])
            out.append({"window_start": r["window_start"], "device_mac": self.device_mac,
                        **{k: v for k, v in e.items() if k != "z"},
                        **{f"z_{f}": v for f, v in e["z"].items()}})
        return pd.DataFrame(out)


class AnomalyDetectorRegistry:
    """One DeviceAnomalyDetector per device_mac."""

    def __init__(self):
        self._detectors: Dict[str, DeviceAnomalyDetector] = {}

    def add_profile(self, profile: BaselineProfile) -> DeviceAnomalyDetector:
        detector = DeviceAnomalyDetector(device_mac=profile.device_mac, profile=profile)
        self._detectors[profile.device_mac] = detector
        return detector

    def load_dir(self, directory) -> List[str]:
        """Load every saved profile (*.json written by BaselineProfile.save) from a folder."""
        loaded = []
        for meta in sorted(Path(directory).glob("*.json")):
            mac = meta.stem.replace("-", ":")
            self.add_profile(BaselineProfile.load(directory, mac))
            loaded.append(mac)
        return loaded

    def train_device(self, device_mac: str, baseline_vectors: List, **kwargs) -> DeviceAnomalyDetector:
        detector = DeviceAnomalyDetector(device_mac=device_mac)
        detector.train(baseline_vectors, **kwargs)
        self._detectors[device_mac] = detector
        return detector

    def get(self, device_mac: str) -> DeviceAnomalyDetector:
        if device_mac not in self._detectors:
            raise KeyError(f"No trained model for device {device_mac} yet.")
        return self._detectors[device_mac]

    def devices(self) -> List[str]:
        return list(self._detectors)
