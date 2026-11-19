"""Quality checks for the extractor output.

1. Schema check   - columns, types, ranges, contiguous 10 s windows (FR-03 acceptance:
                     "a complete feature row is produced for each device per time window").
2. Capture check  - exact per-packet recount with scapy and comparison with the CSV
                     (FR-02 acceptance: "all device flows are recorded and match what Wireshark captures").
                     Totals must match exactly; per-window deviation is reported for information
                     because flow pieces are attributed to the window in which they start.

CLI:
    python -m trustadapt.features.validate data/raw/normal.pcap data/processed/normal_features.csv \
        --devices lab/devices.csv
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict

import numpy as np
import pandas as pd
from scapy.all import IP, TCP, UDP, IPv6, PcapReader

from .schema import FEATURE_COLUMNS, WINDOW_S


# --------------------------------------------------------------------------- schema check
def check_schema(df: pd.DataFrame) -> list[str]:
    errs: list[str] = []
    if list(df.columns) != FEATURE_COLUMNS:
        errs.append(f"columns differ from schema: {list(df.columns)}")
        return errs
    num = [c for c in FEATURE_COLUMNS if c not in
           ("device_mac", "ip_src", "ip_dst", "protocol_type", "app_protocol")]
    if df[num].isna().any().any():
        errs.append("NaN in numeric columns")
    for c in ("traffic_spike_flag", "unusual_port_flag"):
        if not set(df[c].unique()) <= {0, 1}:
            errs.append(f"{c} must be 0/1")
    if ((df["activity_time"] < 0) | (df["activity_time"] > WINDOW_S)).any():
        errs.append("activity_time outside 0-10")
    for c in ("packet_rate_10s", "bytes_sent_rate", "connection_count", "new_destination_count",
              "mean_packet_size", "std_packet_size", "mean_inter_arrival", "std_inter_arrival",
              "failed_conn_count"):
        if (df[c] < 0).any():
            errs.append(f"{c} has negative values")
    if not set(df["protocol_type"].fillna("")) <= {"", "TCP", "UDP", "ICMP"}:
        errs.append("protocol_type has unexpected values")
    if not set(df["app_protocol"]) <= {"MQTT", "HTTP", "CoAP", "OTHER"}:
        errs.append("app_protocol has unexpected values")
    for mac, g in df.groupby("device_mac"):
        steps = np.diff(g["window_start"].to_numpy())
        if len(steps) and not np.allclose(steps, WINDOW_S):
            errs.append(f"{mac}: windows are not contiguous 10 s steps")
        empty = g[g["packet_rate_10s"] == 0]
        if (empty[["bytes_sent_rate", "connection_count", "activity_time"]] != 0).any().any():
            errs.append(f"{mac}: empty window with non-zero values")
    return errs


# --------------------------------------------------------------------------- capture check
def exact_counts(pcap: str, macs: set[str]) -> tuple[dict, pd.DataFrame]:
    """Per-packet recount (TCP/UDP/ICMP over IPv4/IPv6). Returns totals and per-window table."""
    tot = defaultdict(lambda: {"packets": 0, "sent_bytes": 0})
    win: dict[tuple[str, int], dict] = defaultdict(lambda: {"sizes": [], "times": []})
    with PcapReader(pcap) as rd:
        for p in rd:
            ip = p.getlayer(IP) or p.getlayer(IPv6)
            if ip is None:
                continue
            proto = ip.proto if isinstance(ip, IP) else ip.nh
            if proto not in (1, 6, 17, 58):
                continue
            src, dst = p.src.lower(), p.dst.lower()
            size = getattr(p, "wirelen", None) or len(p)     # original frame length (snaplen-safe)
            t = float(p.time)
            w = int(t // WINDOW_S)
            for mac in (src, dst):
                if mac in macs:
                    tot[mac]["packets"] += 1
                    win[(mac, w)]["sizes"].append(size)
                    win[(mac, w)]["times"].append(t)
            if src in macs:
                tot[src]["sent_bytes"] += size
    rows = []
    for (mac, w), d in win.items():
        ts = np.sort(np.array(d["times"]))
        gaps = np.diff(ts) * 1000
        rows.append({"device_mac": mac, "window_start": float(w * WINDOW_S),
                     "packets": len(d["sizes"]), "mean_ps": float(np.mean(d["sizes"])),
                     "active": len({int(x) for x in ts}),
                     "mean_ia": float(gaps.mean()) if len(gaps) else 0.0})
    return dict(tot), pd.DataFrame(rows)


def cross_check(pcap: str, df: pd.DataFrame) -> tuple[list[str], dict]:
    macs = set(df["device_mac"])
    exact_tot, exact_win = exact_counts(pcap, macs)
    errs, info = [], {}
    for mac in sorted(macs):
        g = df[df["device_mac"] == mac]
        pk = int(round(g["packet_rate_10s"].sum() * WINDOW_S))
        by = int(round(g["bytes_sent_rate"].sum() * WINDOW_S))
        ex = exact_tot.get(mac, {"packets": 0, "sent_bytes": 0})
        if pk != ex["packets"]:
            errs.append(f"{mac}: packets CSV={pk} pcap={ex['packets']}")
        if by != ex["sent_bytes"]:
            errs.append(f"{mac}: sent bytes CSV={by} pcap={ex['sent_bytes']}")
        # per-window deviation (information only)
        m = g.merge(exact_win[exact_win["device_mac"] == mac], on=["device_mac", "window_start"], how="left").fillna(0)
        ex_pk = m["packets"]
        denom = max(ex_pk.sum(), 1)
        info[mac] = {
            "windows": len(g),
            "packet_total": ex["packets"],
            "window_packet_abs_err_pct": round(100 * float((m["packet_rate_10s"] * WINDOW_S - ex_pk).abs().sum()) / float(denom), 2),
            "activity_time_mae_s": round(float((m["activity_time"] - m["active"]).abs().mean()), 3),
            "mean_packet_size_mae_B": round(float((m["mean_packet_size"] - m["mean_ps"]).abs().mean()), 3),
            "mean_inter_arrival_mae_ms": round(float((m["mean_inter_arrival"] - m["mean_ia"]).abs().mean()), 3),
        }
    return errs, info


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Validate feature CSV (schema + exact pcap recount)")
    ap.add_argument("pcap")
    ap.add_argument("features_csv")
    ap.add_argument("--devices", help="unused here; kept for symmetry with extract")
    a = ap.parse_args(argv)
    df = pd.read_csv(a.features_csv, keep_default_na=False, na_values=[])
    errs = check_schema(df)
    cerrs, info = cross_check(a.pcap, df)
    errs += cerrs
    print("== schema + totals ==")
    print("PASS" if not errs else "FAIL")
    for e in errs:
        print("  -", e)
    print("== per-window deviation vs exact recount (information) ==")
    for mac, d in info.items():
        print(f"  {mac}: {d}")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
