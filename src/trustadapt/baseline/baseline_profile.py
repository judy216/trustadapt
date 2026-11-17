"""Baseline profiling (FR-04), model-training side: what "normal" looks like for ONE device.

From the first 50 feature vectors (10 s windows, about 8 minutes) of a device this module builds:
  * the mean and standard deviation of each of the 12 ML features (std has a floor, see below),
  * one Isolation Forest trained on those same windows,
  * the Isolation Forest's decision_function on those windows: its minimum, 1st / 5th / 50th
    percentile and maximum, which the anomaly-detection step (FR-05) uses to turn a score into a
    severity A between 0 and 1.

Std floors (from the Trust Score design): 1.0 for numeric features and 0.2 for the two flags.
Without a floor, a feature that never changes in the baseline (for example new_destination_count = 0)
has std 0 and its z-score explodes the first time it moves.

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

from schema import BASELINE_WINDOWS, IoTDeviceFeatureVector

FEATURES: tuple[str, ...] = IoTDeviceFeatureVector.ML_FEATURES      # fixed column order, 12 values
FLAG_FEATURES = ("traffic_spike_flag", "unusual_port_flag")
STD_FLOOR_NUMERIC = 1.0        # smallest std allowed for normal numbers (avoids dividing by ~0)
STD_FLOOR_FLAG = 0.2
OUTLIER_FENCE_K = 5.0          # a window is suspect beyond Q3 + k*spread or Q1 - k*spread (spread >= std floor)
N_ESTIMATORS = 100
RANDOM_STATE = 42


class BaselineNotReady(ValueError):
    """Raised when a device has fewer than BASELINE_WINDOWS windows (it is still LEARNING)."""


class BaselineContaminated(ValueError):
    """Raised when the baseline windows look like they contain attack traffic (see module docstring)."""


def baseline_ready(n_windows_seen: int) -> bool:
    """True once the device has enough windows to build its baseline."""
    return n_windows_seen >= BASELINE_WINDOWS


def _std_floor() -> np.ndarray:
    # One floor value per feature: 0.2 for the flags, 1.0 for everything else.
    return np.array([STD_FLOOR_FLAG if f in FLAG_FEATURES else STD_FLOOR_NUMERIC for f in FEATURES])


def _suspect_mask(X: np.ndarray) -> np.ndarray:
    """Boolean (n_windows, 12): value beyond the Tukey outer fences of its own column.

    The spread is the interquartile range, never below the std floor, so a column that is constant
    (or nearly so) does not make every small change look extreme, and a device with two normal modes
    (busy and quiet windows) is not refused.
    """
    # Q1 and Q3 = the values 25% and 75% of the windows fall below, for each feature (column).
    q1, q3 = np.percentile(X, 25, axis=0), np.percentile(X, 75, axis=0)
    spread = np.maximum(q3 - q1, _std_floor()) # typical variation of each feature, never below the floor
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
            "trained_at": self.trained_at, "suspect_windows": [float(w) for w in self.suspect_windows],
            "model_file": f"{stem}.joblib",
            "params": {"n_estimators": N_ESTIMATORS, "random_state": RANDOM_STATE,
                       "std_floor_numeric": STD_FLOOR_NUMERIC, "std_floor_flag": STD_FLOOR_FLAG,
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
        if "score_p05" not in meta:    # if file made by an older version of this code
            raise ValueError("saved baseline has no score percentiles (older format); rebuild it")
        # Rebuild the profile object from the saved numbers and the saved model.
        return cls(device_mac=meta["device_mac"], mean=np.array(meta["mean"]), std=np.array(meta["std"]),
                   n_windows=meta["n_windows"], score_min=meta["score_min"], score_p01=meta["score_p01"],
                   score_p05=meta["score_p05"], score_p50=meta["score_p50"], score_max=meta["score_max"],
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
    mean = X.mean(axis=0)
    std = np.maximum(X.std(axis=0, ddof=0), _std_floor())

    # Step 6: train the Isolation Forest on the same 50 windows.
    model = IsolationForest(n_estimators=N_ESTIMATORS, random_state=random_state).fit(X)
    scores = model.decision_function(X)           # higher = more normal
    p01, p05, p50 = np.percentile(scores, [1, 5, 50])     # reference points for "how normal is normal"
    # Step 7: pack everything into one BaselineProfile.
    return BaselineProfile(device_mac=device_mac, mean=mean, std=std, n_windows=len(rows),
                           score_min=float(scores.min()), score_p01=float(p01), score_p05=float(p05),
                           score_p50=float(p50), score_max=float(scores.max()),
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
      
