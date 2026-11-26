"""Baseline profiling (FR-04), model-training side: what "normal" looks like for ONE device.

From the first 50 feature vectors (10 s windows, about 8 minutes) of a device this module builds:
  * the mean and standard deviation of each of the 12 ML features (std has a floor, see below),
  * one Isolation Forest trained on those same windows,
  * the Isolation Forest's decision_function on those windows: its minimum, 1st / 5th / 50th
    percentile and maximum (kept for reference and SHAP),
  * the thresholds the anomaly-detection step (FR-05) uses (Week 10): `if_threshold` and `z_threshold`,
    learned OUT OF FOLD. The 50 windows are split into 5 folds; a model trained on the other 4 folds
    scores each held-out fold, so the thresholds describe a normal window the model has NOT seen.
    (Week 9 scaled A from the model's scores on its own training windows, which put a typical normal
    window right at the anomaly threshold.)

Std floors (Week 10): max(ABS_FLOOR[feature], REL_FLOOR x |mean|). The old flat 1.0 floor was larger
than the real std of packet_rate_10s, activity_time, connection_count and new_destination_count on the
lab captures, so those features lost sensitivity. Without any floor, a feature that never changes in the
baseline (for example new_destination_count = 0) has std 0 and its z-score explodes the first time it moves.

Two checks protect the baseline from learning attack traffic (FR-11, baseline poisoning):
  1. Flag check. Both flags are 0 during LEARNING by definition (schema.py). A flag set inside the
     baseline windows means the data does not follow that rule, so the build is always refused.
  2. Data check. A window far outside the device's own normal range on any feature (beyond Tukey
     outer fences, see OUTLIER_FENCE_K) makes the build refuse, unless allow_suspect=True.
     The check cannot tell a rare legitimate burst from an attack: if a device is refused and
     the traffic is known to be normal, rebuild with allow_suspect=True. Suspect windows are
     always recorded in the profile. It also cannot see slow drift or an attack that fills most
     of the baseline.

Usage:  python3 baseline_profile.py features.csv baselines_dir
        Exit code 1 if any device in the file could not be built.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import KFold

from trustadapt.features.schema import BASELINE_WINDOWS, IoTDeviceFeatureVector

FEATURES: tuple[str, ...] = IoTDeviceFeatureVector.ML_FEATURES      # fixed column order, 12 values
FLAG_FEATURES = ("traffic_spike_flag", "unusual_port_flag")
# Smallest std allowed per feature (units as in DATA_DICTIONARY.md). Each value is below the real baseline std
# measured on the 2026-11-19 lab captures (Week 9 report 4.2), so no feature loses sensitivity.
ABS_FLOOR = {
    "packet_rate_10s": 0.1,         # pkt/s   (real std 0.22-0.64)
    "bytes_sent_rate": 10.0,        # B/s
    "connection_count": 0.5,        # count   (real std 0-0.46)
    "new_destination_count": 0.5,   # count   (real std 0-0.14)
    "activity_time": 0.25,          # s       (real std 0.54-0.71)
    "mean_packet_size": 5.0,        # B
    "std_packet_size": 5.0,         # B
    "mean_inter_arrival": 5.0,      # ms
    "std_inter_arrival": 5.0,       # ms
    "traffic_spike_flag": 0.2,      # flag    (as in the Week 8 design)
    "unusual_port_flag": 0.2,       # flag
    "failed_conn_count": 0.5,       # count
}
REL_FLOOR = 0.05                    # std is also at least 5 % of |mean|
FENCE_SPREAD_FLOOR = 1.0            # data check only (unchanged from Week 9): smallest spread for the Tukey fences
FENCE_SPREAD_FLOOR_FLAG = 0.2
OUTLIER_FENCE_K = 5.0          # a window is suspect beyond Q3 + k*spread or Q1 - k*spread
N_ESTIMATORS = 100
MAX_SAMPLES = 32               # fixed sub-sample: fold models (40 windows) and the final model (50) share one score scale
RANDOM_STATE = 42
CV_FOLDS = 5                   # out-of-fold calibration
THRESHOLD_QUANTILE = 0.99      # threshold = this quantile of the held-out baseline windows
Z_ALARM_MIN = 4.0              # the z threshold is never below this max|z|


class BaselineNotReady(ValueError):
    """Raised when a device has fewer than BASELINE_WINDOWS windows (it is still LEARNING)."""


class BaselineContaminated(ValueError):
    """Raised when the baseline windows look like they contain attack traffic (see module docstring)."""


def baseline_ready(n_windows_seen: int) -> bool:
    """True once the device has enough windows to build its baseline."""
    return n_windows_seen >= BASELINE_WINDOWS


def _std_floor(mean: np.ndarray) -> np.ndarray:
    """One floor value per feature: max(absolute floor, 5 % of |mean|)."""
    return np.maximum(np.array([ABS_FLOOR[f] for f in FEATURES]), REL_FLOOR * np.abs(mean))


def _fence_floor() -> np.ndarray:
    # Data check only: 0.2 for the flags, 1.0 for everything else (same behaviour as Week 9).
    return np.array([FENCE_SPREAD_FLOOR_FLAG if f in FLAG_FEATURES else FENCE_SPREAD_FLOOR for f in FEATURES])


def _new_model(random_state: int = RANDOM_STATE) -> IsolationForest:
    return IsolationForest(n_estimators=N_ESTIMATORS, max_samples=MAX_SAMPLES, random_state=random_state)


def _moments(X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    mean = X.mean(axis=0)
    return mean, np.maximum(X.std(axis=0, ddof=0), _std_floor(mean))


def _calibrate(X: np.ndarray, random_state: int = RANDOM_STATE) -> dict:
    """Out-of-fold thresholds: how a normal window the model has not seen scores.

    Returns if_threshold (decision_function; a window BELOW it is unusual for the model), if_spread
    (distance from the median held-out window to that threshold, used to scale A) and z_threshold
    (largest |z| a held-out normal window reached, never below Z_ALARM_MIN).
    """
    oof_if = np.empty(len(X))
    oof_z = np.empty(len(X))
    for train, held in KFold(CV_FOLDS, shuffle=True, random_state=random_state).split(X):
        oof_if[held] = _new_model(random_state).fit(X[train]).decision_function(X[held])
        mu, sd = _moments(X[train])
        oof_z[held] = np.abs((X[held] - mu) / sd).max(axis=1)
    if_threshold = float(np.quantile(oof_if, 1 - THRESHOLD_QUANTILE))     # low tail: lower = more anomalous
    return {
        "if_threshold": if_threshold,
        "if_spread": float(max(np.median(oof_if) - if_threshold, 1e-3)),
        "z_threshold": float(max(Z_ALARM_MIN, np.quantile(oof_z, THRESHOLD_QUANTILE))),
    }


def _suspect_mask(X: np.ndarray) -> np.ndarray:
    """Boolean (n_windows, 12): value beyond the Tukey outer fences of its own column.

    The spread is the interquartile range, never below the std floor, so a column that is constant
    (or nearly so) does not make every small change look extreme, and a device with two normal modes
    (busy and quiet windows) is not refused.
    """
    # Q1 and Q3 = the values 25% and 75% of the windows fall below, for each feature (column).
    q1, q3 = np.percentile(X, 25, axis=0), np.percentile(X, 75, axis=0)
    spread = np.maximum(q3 - q1, _fence_floor())  # typical variation of each feature, never below the floor
    # True where a value is far above or far below the normal range of its column.
    return (X > q3 + OUTLIER_FENCE_K * spread) | (X < q1 - OUTLIER_FENCE_K * spread)


@dataclass
class BaselineProfile:             # everything we remember about one device's normal behavior
    device_mac: str                # which device this baseline belongs to
    mean: np.ndarray               # shape (12,), in FEATURES order: the average of each feature
    std: np.ndarray                # shape (12,), already floored: how much each feature normally varies
    n_windows: int                 # no. of windows the baseline was built from (50)
    score_min: float               # decision_function on the baseline windows (higher = more normal)
    score_p01: float               # 1% of baseline windows score below this
    score_p05: float               # 5% score below this: use it as the "edge of normal"
    score_p50: float               # the median baseline score
    score_max: float               # the most normal-looking baseline window
    if_threshold: float            # out of fold: decision_function below this = unusual for the model (FR-05)
    if_spread: float               # median held-out score minus if_threshold: scales the severity
    z_threshold: float             # out of fold: max|z| above this = unusual on some feature (FR-05)
    trained_at: str                # UTC, ISO 8601
    model: IsolationForest         # the trained model itself
    suspect_windows: list = field(default_factory=list)   # window_start of windows the data check flagged

    def z_scores(self, x) -> np.ndarray:
        """z_i = (x_i - mean_i) / std_i for one 12-value vector in FEATURES order."""
        x = np.asarray(x, dtype=float)      # make sure it is an array of numbers
        if x.shape != (len(FEATURES),):     # must be exactly 12 values
            raise ValueError(f"expected {len(FEATURES)} values in ML_FEATURES order, got shape {x.shape}")
        return (x - self.mean) / self.std   # how many "normal variations" each value is from average

    # ---- persistence: readable JSON for the baselines table, joblib for the model ----
    def save(self, directory) -> Path:
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)      # create the folder if it does not exist
        stem = self.device_mac.replace(":", "-")  # file name from the MAC (":" is not safe in file names)
      
        # the readable part: numbers and settings, saved as JSON
        meta = { 
            "device_mac": self.device_mac, "features": list(FEATURES),
            "mean": self.mean.tolist(), "std": self.std.tolist(), "n_windows": self.n_windows,
            "score_min": self.score_min, "score_p01": self.score_p01, "score_p05": self.score_p05,
            "score_p50": self.score_p50, "score_max": self.score_max,
            "if_threshold": self.if_threshold, "if_spread": self.if_spread, "z_threshold": self.z_threshold,
            "trained_at": self.trained_at, "suspect_windows": [float(w) for w in self.suspect_windows],
            "model_file": f"{stem}.joblib",
            "params": {"n_estimators": N_ESTIMATORS, "max_samples": MAX_SAMPLES, "random_state": RANDOM_STATE,
                       "abs_floor": ABS_FLOOR, "rel_floor": REL_FLOOR, "cv_folds": CV_FOLDS,
                       "threshold_quantile": THRESHOLD_QUANTILE, "z_alarm_min": Z_ALARM_MIN,
                       "outlier_fence_k": OUTLIER_FENCE_K},
        }
        (d / f"{stem}.json").write_text(json.dumps(meta, indent=2))  # write the readable file
        joblib.dump(self.model, d / f"{stem}.joblib")    # write the model file
        return d / f"{stem}.json"

    @classmethod
    def load(cls, directory, device_mac: str) -> "BaselineProfile":
        """Load a profile. Only load model files this system wrote: joblib files can run code."""
        d = Path(directory)
        stem = device_mac.replace(":", "-")
        meta = json.loads((d / f"{stem}.json").read_text())  # read the readable part
        if tuple(meta["features"]) != FEATURES:    # if saved with a different feature order -> unsafe to use
            raise ValueError("saved baseline uses a different feature order; rebuild it")
        if "if_threshold" not in meta:    # if file made by an older version of this code (before Week 10)
            raise ValueError("saved baseline has no out-of-fold thresholds (older format); rebuild it")
        # Rebuild the profile object from the saved numbers and the saved model.
        return cls(device_mac=meta["device_mac"], mean=np.array(meta["mean"]), std=np.array(meta["std"]),
                   n_windows=meta["n_windows"], score_min=meta["score_min"], score_p01=meta["score_p01"],
                   score_p05=meta["score_p05"], score_p50=meta["score_p50"], score_max=meta["score_max"],
                   if_threshold=meta["if_threshold"], if_spread=meta["if_spread"], z_threshold=meta["z_threshold"],
                   trained_at=meta["trained_at"], model=joblib.load(d / meta["model_file"]),
                   suspect_windows=meta.get("suspect_windows", []))


def build_baseline(device_mac: str, vectors: pd.DataFrame, n_windows: int = BASELINE_WINDOWS,
                   random_state: int = RANDOM_STATE, allow_suspect: bool = False) -> BaselineProfile:
    """Build one device's baseline from its feature vectors (one row per 10 s window).

    `vectors` needs a `window_start` column and the 12 ML feature columns. The first `n_windows`
    rows by time are used, so later windows can never leak into the baseline.
    Raises BaselineNotReady (too few windows) or BaselineContaminated (see module docstring).
    """
    # Step 1: check that the table has the columns we need.
    missing = [c for c in ("window_start",) + FEATURES if c not in vectors.columns]
    if missing:
        raise ValueError(f"missing columns: {missing}")
    # Step 2: take the first 50 windows in time order (later windows can never leak in).
    rows = vectors.sort_values("window_start").head(n_windows)
    if len(rows) < n_windows:
        raise BaselineNotReady(f"{device_mac}: {len(rows)} windows, need {n_windows}")
    X = rows[list(FEATURES)].astype(float).to_numpy()
    if not np.isfinite(X).all():
        raise ValueError(f"{device_mac}: baseline windows contain NaN or infinite values")

    # Step 3, check 1: flags must be 0 while learning. Any flag set means the data is wrong or already attacked.
    flagged = rows.loc[(rows[list(FLAG_FEATURES)].astype(float) > 0).any(axis=1), "window_start"]
    if len(flagged):
        raise BaselineContaminated(
            f"{device_mac}: {len(flagged)} of the first {n_windows} windows have a traffic_spike / "
            f"unusual_port flag set (first at window_start={flagged.iloc[0]:.0f}); refusing to learn from them")

    # Step 4, check 2: look for windows far outside the device's own normal range.
    mask = _suspect_mask(X)    # True where a value is extreme
    suspect = rows["window_start"].to_numpy()[mask.any(axis=1)]    # times of windows with any extreme value
    if len(suspect) and not allow_suspect:    # refuse, unless the caller says the traffic is known to be normal
        cols = [FEATURES[j] for j in np.where(mask.any(axis=0))[0]]  # which features looked extreme
        raise BaselineContaminated(
            f"{device_mac}: {len(suspect)} of the first {n_windows} windows are far outside the device's own "
            f"normal range (first at window_start={suspect[0]:.0f}; features: {', '.join(cols[:4])}"
            f"{'...' if len(cols) > 4 else ''}); refusing to learn from them. If this traffic is known to be "
            f"normal, rebuild with allow_suspect=True")

    # Step 5: the average and normal variation of each feature (std is never below its floor).
    mean, std = _moments(X)

    # Step 6: out-of-fold thresholds (models trained on 4/5 of the windows score the other 1/5).
    calib = _calibrate(X, random_state)

    # Step 7: train the final Isolation Forest on all 50 windows.
    model = _new_model(random_state).fit(X)
    scores = model.decision_function(X)           # higher = more normal (in-sample: reference only)
    p01, p05, p50 = np.percentile(scores, [1, 5, 50])
    # Step 8: pack everything into one BaselineProfile.
    return BaselineProfile(device_mac=device_mac, mean=mean, std=std, n_windows=len(rows),
                           score_min=float(scores.min()), score_p01=float(p01), score_p05=float(p05),
                           score_p50=float(p50), score_max=float(scores.max()), **calib,
                           trained_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                           model=model, suspect_windows=[float(w) for w in suspect])


def build_from_csv(csv_path, out_dir, skipped: dict | None = None,
                   allow_suspect: bool = False) -> dict[str, BaselineProfile]:
    """Build and save one baseline per device found in a feature-vector CSV.

    Devices that cannot be built are left out of the result. Pass a dict as `skipped` to receive
    {device_mac: reason} for them.
    """
    df = pd.read_csv(csv_path)    # read all feature vectors
    profiles = {}         # device MAC -> its baseline
    for mac, g in df.groupby("device_mac", sort=False):  # one device at a time
        try:
            profiles[mac] = build_baseline(mac, g, allow_suspect=allow_suspect)
        except BaselineNotReady as err:      # too few windows: skip and say why
            print(f"skipped (still LEARNING): {err}")
            if skipped is not None:
                skipped[mac] = str(err)
            continue
        except BaselineContaminated as err:    # attack-like data: skip and say why
            print(f"skipped (contaminated baseline): {err}")
            if skipped is not None:
                skipped[mac] = str(err)
            continue
        profiles[mac].save(out_dir)    # only built baselines get saved
    return profiles


if __name__ == "__main__":
    if len(sys.argv) != 3:  # needs: the CSV and the output folder
        sys.exit(__doc__)
    skipped_devices: dict = {}    # filled with devices that could not be built
    for mac, p in build_from_csv(sys.argv[1], sys.argv[2], skipped=skipped_devices).items():
        note = f", {len(p.suspect_windows)} suspect windows" if p.suspect_windows else ""  # mention suspect windows if any
        print(f"{mac}: {p.n_windows} windows, decision_function range [{p.score_min:.3f}, {p.score_max:.3f}]{note}")
    if skipped_devices:    # exit code 1 tells scripts that something was skipped
        sys.exit(f"{len(skipped_devices)} device(s) skipped: {', '.join(skipped_devices)}")
      
