"""Data access for the dashboard: load + check Student 1's outputs, derive what the pages show.

Pure pandas, no Streamlit import, so every function here is unit-tested in tests/test_data.py.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

import pandas as pd

from .contract import BASELINE_WINDOWS, DISPLAY_TZ, FEATURE_COLUMNS

# Small synthetic files from the features module (data/ is git-ignored, so they live next to the code)
SAMPLE_DIR = Path(__file__).resolve().parent / "samples"
DEVICES_CSV = SAMPLE_DIR / "devices.csv"
SAMPLE_SCENARIOS = {
    "Synthetic - normal": "synthetic_normal_features.csv",
    "Synthetic - attack (flood / scan / exfil on cam-01)": "synthetic_attack_features.csv",
}
SAMPLE_BASELINE = "synthetic_normal_baseline.json"


class DataError(ValueError):
    """Input does not follow the FR-03 contract; message is shown to the user."""


@dataclass
class Dataset:
    features: pd.DataFrame                      # FR-03 rows + `time`, `device_name`, `device_type`
    baseline: dict = field(default_factory=dict)  # per-MAC baseline JSON (may be empty)
    devices: pd.DataFrame = field(default_factory=pd.DataFrame)
    source: str = ""


# --------------------------------------------------------------------------- loading
def load_features(src: str | Path | IO) -> pd.DataFrame:
    df = pd.read_csv(src)
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise DataError(f"Feature CSV is missing columns: {', '.join(missing)}")
    df = df[FEATURE_COLUMNS].copy()
    if df.empty:
        raise DataError("Feature CSV has no rows.")
    for c in ("device_mac", "ip_src", "ip_dst", "protocol_type", "app_protocol"):
        df[c] = df[c].fillna("").astype(str)
    df["device_mac"] = df["device_mac"].str.lower()
    df["time"] = pd.to_datetime(df["window_start"], unit="s", utc=True).dt.tz_convert(DISPLAY_TZ)
    return df.sort_values(["device_mac", "window_start"]).reset_index(drop=True)


def load_baseline(src: str | Path | IO | None) -> dict:
    if src is None:
        return {}
    raw = json.load(open(src) if isinstance(src, (str, Path)) else src)
    if not isinstance(raw, dict):
        raise DataError("Baseline JSON must be an object keyed by device MAC.")
    return {str(k).lower(): v for k, v in raw.items()}


def load_devices(src: str | Path | IO | None) -> pd.DataFrame:
    if src is None:
        return pd.DataFrame(columns=["mac", "name", "type"])
    d = pd.read_csv(src)
    if not {"mac", "name"} <= set(d.columns):
        raise DataError("devices.csv needs at least the columns mac,name")
    d["mac"] = d["mac"].str.lower()
    if "type" not in d.columns:
        d["type"] = ""
    return d[["mac", "name", "type"]]


def build_dataset(features, baseline=None, devices=None, source: str = "") -> Dataset:
    f = load_features(features)
    dev = load_devices(devices)
    names = dict(zip(dev["mac"], dev["name"]))
    types = dict(zip(dev["mac"], dev["type"]))
    f["device_name"] = f["device_mac"].map(names).fillna(f["device_mac"])
    f["device_type"] = f["device_mac"].map(types).fillna("unknown")
    return Dataset(features=f, baseline=load_baseline(baseline), devices=dev, source=source)


def load_sample(scenario: str) -> Dataset:
    return build_dataset(
        SAMPLE_DIR / SAMPLE_SCENARIOS[scenario],
        SAMPLE_DIR / SAMPLE_BASELINE,
        DEVICES_CSV,
        source=scenario,
    )


# --------------------------------------------------------------------------- derived views
def device_status(ds: Dataset, mac: str) -> str:
    """LEARNING until 50 windows are seen, unless an external baseline exists (Student 1 convention)."""
    b = ds.baseline.get(mac)
    if b and b.get("complete"):
        return "MONITORING"
    n = int((ds.features["device_mac"] == mac).sum())
    return "MONITORING" if n >= BASELINE_WINDOWS else "LEARNING"


def alert_reasons(row: pd.Series) -> list[str]:
    r = []
    if row["traffic_spike_flag"] == 1:
        r.append(f"Traffic spike ({row['packet_rate_10s']:.1f} pkt/s)")
    if row["unusual_port_flag"] == 1:
        r.append(f"Unusual port (dominant dst port {int(row['port_dst'])})")
    if row["failed_conn_count"] > 0:
        r.append(f"{int(row['failed_conn_count'])} failed connections in 60 s")
    if row["new_destination_count"] > 0:
        r.append(f"{int(row['new_destination_count'])} new destinations")
    return r


def alerts(ds: Dataset, include_new_destinations: bool = False) -> pd.DataFrame:
    """Rule-based alerts from Student 1's flags. Replaced/extended by FR-05 model output later."""
    f = ds.features
    mask = (f["traffic_spike_flag"] == 1) | (f["unusual_port_flag"] == 1) | (f["failed_conn_count"] > 0)
    if include_new_destinations:
        # In a fresh capture without a baseline the first window counts every destination as new.
        mask |= f["new_destination_count"] > 0
    a = f.loc[mask].copy()
    a["reasons"] = a.apply(lambda r: "; ".join(alert_reasons(r)), axis=1)
    a["severity"] = (
        2 * (a["traffic_spike_flag"] == 1).astype(int)
        + 2 * (a["failed_conn_count"] > 0).astype(int)
        + (a["unusual_port_flag"] == 1).astype(int)
        + (a["new_destination_count"] > 0).astype(int)
    )
    cols = ["time", "device_name", "device_mac", "severity", "reasons",
            "packet_rate_10s", "bytes_sent_rate", "port_dst", "ip_dst"]
    return a[cols].sort_values("time", ascending=False).reset_index(drop=True)


def device_summary(ds: Dataset) -> pd.DataFrame:
    f = ds.features
    al = alerts(ds)
    rows = []
    for mac, g in f.groupby("device_mac", sort=True):
        last = g.iloc[-1]
        base = ds.baseline.get(mac, {})
        rows.append({
            "device_mac": mac,
            "device_name": last["device_name"],
            "device_type": last["device_type"],
            "ip": next((ip for ip in g["ip_src"][::-1] if ip), ""),
            "status": device_status(ds, mac),
            "windows": len(g),
            "last_seen": g.loc[g["packet_rate_10s"] > 0, "time"].max(),
            "last_packet_rate": float(last["packet_rate_10s"]),
            "baseline_packet_rate": base.get("mean_packet_rate"),
            "alert_windows": int((al["device_mac"] == mac).sum()),
        })
    return pd.DataFrame(rows)
