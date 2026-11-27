"""SHAP groundwork for FR-09 (Week 10): explain WHY the Isolation Forest finds a window unusual.

One explainer per device, built on that device's own BaselineProfile model (FR-04).

What SHAP explains for an Isolation Forest
------------------------------------------
shap.TreeExplainer does not explain decision_function directly. It explains the AVERAGE PATH LENGTH h(x):
how many splits the trees need to isolate the window. Short path = easy to isolate = anomalous.

    h(x) = base_value + sum(shap_i)              (exact, checked in check_additivity)
    score_samples(x) = -2 ** (-h(x) / c(n))      n = model.max_samples_
    decision_function(x) = score_samples(x) - model.offset_

So a NEGATIVE shap_i means feature i shortened the path, i.e. pushed the window toward "anomalous".
That is the only direction we blame. Positive values (features that looked normal) are kept for the
dashboard but never take penalty points.

No background dataset is passed: the tree-path algorithm uses the training data stored in the trees
(each tree's sample of the device's 50 baseline windows, max_samples), so base_value is the expected path length of a normal window.

Usage:  python -m trustadapt.explain.shap_explainer normal_features.csv attack_features.csv
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Dict, List

import numpy as np
import shap

from trustadapt.baseline.baseline_profile import FEATURES, BaselineProfile

ADDITIVITY_TOL = 1e-6   # max allowed |base + sum(shap) - h(x)|
TOP_K = 3               # features listed in the short explanation


def _c(n: int) -> float:
    """Average path length of an unsuccessful search in a binary tree of n points (Isolation Forest paper)."""
    if n <= 1:
        return 1.0
    if n == 2:
        return 1.0
    return 2.0 * (np.log(n - 1) + np.euler_gamma) - 2.0 * (n - 1) / n


@dataclass
class WindowExplanation:
    """Explanation of one 10 s window for one device."""
    device_mac: str
    base_value: float                 # expected path length of a normal window
    path_length: float                # h(x) of this window
    decision_score: float             # same value as model.decision_function (lower = more anomalous)
    shap: Dict[str, float]            # feature -> SHAP value (path-length units)
    anomaly_share: Dict[str, float]   # feature -> share of the anomaly, only negative SHAP, sums to 1

    def top_features(self, k: int = TOP_K) -> List[str]:
        """Features that pushed most toward anomalous, strongest first."""
        return sorted(self.anomaly_share, key=self.anomaly_share.get, reverse=True)[:k]

    def to_points(self, penalty: float) -> Dict[str, float]:
        """Split a Trust Score penalty by SHAP share; same format as the engine's `contributions`."""
        return {f: round(penalty * s, 2) for f, s in self.anomaly_share.items() if s > 0}


class DeviceShapExplainer:
    """Wraps shap.TreeExplainer around one device's Isolation Forest."""

    def __init__(self, profile: BaselineProfile):
        self.device_mac = profile.device_mac
        self.model = profile.model
        self._explainer = shap.TreeExplainer(self.model)
        self.base_value = float(np.ravel(self._explainer.expected_value)[0])
        self._c = _c(int(self.model.max_samples_))

    # ---- core ----
    def shap_values(self, X) -> np.ndarray:
        """SHAP values, shape (n_windows, 12), columns in FEATURES order."""
        X = np.atleast_2d(np.asarray(X, dtype=float))
        if X.shape[1] != len(FEATURES):
            raise ValueError(f"expected {len(FEATURES)} columns in ML_FEATURES order, got {X.shape[1]}")
        return np.asarray(self._explainer.shap_values(X))

    def path_length_to_decision(self, h: np.ndarray) -> np.ndarray:
        """Convert path length to the decision_function value used by the anomaly module."""
        return -(2.0 ** (-np.asarray(h) / self._c)) - self.model.offset_

    def check_additivity(self, X) -> float:
        """Largest reconstruction error; raises if SHAP does not add up to the model output."""
        X = np.atleast_2d(np.asarray(X, dtype=float))
        h = self.shap_values(X).sum(axis=1) + self.base_value
        err = float(np.abs(self.path_length_to_decision(h) - self.model.decision_function(X)).max())
        if err > ADDITIVITY_TOL:
            raise AssertionError(f"{self.device_mac}: SHAP additivity error {err:.2e} > {ADDITIVITY_TOL}")
        return err

    def explain(self, x) -> WindowExplanation:
        """Explain one 12-value window (FEATURES order)."""
        sv = self.shap_values(x)[0]
        h = self.base_value + float(sv.sum())
        neg = np.clip(-sv, 0.0, None)            # only features that pushed toward anomalous
        total = float(neg.sum())
        share = {f: (float(v) / total if total > 0 else 0.0) for f, v in zip(FEATURES, neg)}
        return WindowExplanation(
            device_mac=self.device_mac, base_value=self.base_value, path_length=h,
            decision_score=float(self.path_length_to_decision(h)),
            shap={f: float(v) for f, v in zip(FEATURES, sv)}, anomaly_share=share,
        )


class ShapExplainerRegistry:
    """One explainer per device_mac; built once, reused every window."""

    def __init__(self):
        self._explainers: Dict[str, DeviceShapExplainer] = {}

    def add(self, profile: BaselineProfile) -> DeviceShapExplainer:
        exp = DeviceShapExplainer(profile)
        self._explainers[profile.device_mac] = exp
        return exp

    def get(self, device_mac: str) -> DeviceShapExplainer:
        if device_mac not in self._explainers:
            raise KeyError(f"No explainer for {device_mac}: its baseline is not built yet (LEARNING).")
        return self._explainers[device_mac]


def compare_with_zscores(normal_csv: str, attack_csv: str, k: int = TOP_K) -> None:
    """Week 10 check: on the attack capture, does SHAP blame the same features as the z-scores?"""
    import time
    import pandas as pd
    from trustadapt.baseline.baseline_profile import build_baseline

    normal, attack = pd.read_csv(normal_csv), pd.read_csv(attack_csv)
    for mac, g in normal.groupby("device_mac", sort=False):
        profile = build_baseline(mac, g, allow_suspect=True)
        exp = DeviceShapExplainer(profile)
        X = attack.loc[attack.device_mac == mac, list(FEATURES)].astype(float).to_numpy()
        err = exp.check_additivity(X)

        t0 = time.perf_counter()
        explanations = [exp.explain(x) for x in X]
        ms = (time.perf_counter() - t0) * 1000 / max(len(X), 1)

        # Windows the model ranks outside the edge of normal (5th percentile of baseline scores)
        unusual = [(e, x) for e, x in zip(explanations, X) if e.decision_score < profile.score_p05]
        agree = 0
        for e, x in unusual:
            z_top = [FEATURES[j] for j in np.argsort(-np.abs(profile.z_scores(x)))[:k]]
            agree += e.top_features(1)[0] in z_top
        print(f"{mac}: {len(X)} windows, {len(unusual)} unusual, additivity err {err:.1e}, {ms:.1f} ms/window")
        if unusual:
            print(f"  SHAP top-1 inside z-score top-{k}: {agree}/{len(unusual)}")
            worst = min(unusual, key=lambda t: t[0].decision_score)[0]
            print("  most unusual window:", ", ".join(
                f"{f} {worst.anomaly_share[f]:.0%}" for f in worst.top_features()))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    compare_with_zscores(sys.argv[1], sys.argv[2])
