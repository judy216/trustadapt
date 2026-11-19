"""pcap -> one FR-03 feature vector per device per 10 s window.

Design follows Week 8 report, Section 10 (NFStream as the flow engine), with one refinement:
a small NFStream plugin records (time, size, direction) of every packet, so the window
statistics (rates, size and inter-arrival statistics, activity_time) are computed exactly
per packet and per window, not approximated from flow-level averages.

Privacy (FR-02 / NFR-05): nDPI is disabled (n_dissections=0); only packet metadata is read
(time, length, header fields). Payload bytes are never read; application protocol comes from
the destination port only.

CLI:
    python -m trustadapt.features.extract data/raw/normal.pcap -o data/processed/normal_features.csv \
        --devices lab/devices.csv
"""
from __future__ import annotations

import argparse
import ast
import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from nfstream import NFPlugin, NFStreamer

from .schema import (
    BASELINE_WINDOWS, FAILED_CONN_WINDOW_S, FEATURE_COLUMNS, IP_PROTO_TO_TRANSPORT,
    ML_FEATURES, SPIKE_FACTOR, WINDOW_S, app_from_port,
)

log = logging.getLogger("trustadapt.features.extract")

WINDOW_MS = WINDOW_S * 1000
_FAILED_SPAN = FAILED_CONN_WINDOW_S // WINDOW_S          # 6 windows = 60 s

_EMPTY_ROW = dict(ip_src="", ip_dst="", port_src=0, port_dst=0, protocol_type="",
                  app_protocol="OTHER", packet_rate_10s=0.0, bytes_sent_rate=0.0,
                  connection_count=0, new_destination_count=0, activity_time=0.0,
                  mean_packet_size=0.0, std_packet_size=0.0, mean_inter_arrival=0.0,
                  std_inter_arrival=0.0)


# --------------------------------------------------------------------------- flow extraction
class PacketTrace(NFPlugin):
    """Per flow piece: list of (time_ms, frame_length, direction) for every packet (metadata only)."""

    def on_init(self, packet, flow):
        flow.udps.trace = [(packet.time, packet.raw_size, packet.direction)]

    def on_update(self, packet, flow):
        flow.udps.trace.append((packet.time, packet.raw_size, packet.direction))


def extract_flows(pcap_path: str | Path) -> pd.DataFrame:
    """Read a pcap and return flows cut into <=10 s pieces (metadata only, no payload)."""
    flows = NFStreamer(
        source=str(pcap_path),
        statistical_analysis=True,   # TCP flag counters (SYN / SYN-ACK)
        n_dissections=0,             # nDPI off: no payload inspection (FR-02, NFR-05)
        active_timeout=WINDOW_S,     # split long flows every 10 s
        idle_timeout=WINDOW_S,
        accounting_mode=0,           # link-layer frame length = Wireshark's frame.len
        udps=PacketTrace(),
    ).to_pandas()
    flows.columns = [c.replace(".", "_") for c in flows.columns]   # udps.trace -> udps_trace
    return flows


# --------------------------------------------------------------------------- helpers
def _is_unicast(mac: str) -> bool:
    """False for broadcast / multicast MACs (group bit set)."""
    try:
        return (int(mac.split(":")[0], 16) & 1) == 0
    except ValueError:
        return False


def load_devices(path: str | Path | None) -> pd.DataFrame | None:
    """devices.csv: mac,name,type  (the devices table registered under FR-01)."""
    if path is None:
        return None
    df = pd.read_csv(path, dtype=str)
    df["mac"] = df["mac"].str.lower().str.strip()
    return df


def prepare_flows(flows: pd.DataFrame) -> pd.DataFrame:
    """Keep TCP/UDP/ICMP flows; add `initiated`, `failed` and the 10 s window of the first packet."""
    f = flows[flows["protocol"].isin(IP_PROTO_TO_TRANSPORT)].copy()
    if len(flows) - len(f):
        log.info("ignored %d flows with other IP protocols", len(flows) - len(f))
    f["src_mac"] = f["src_mac"].str.lower()
    f["dst_mac"] = f["dst_mac"].str.lower()
    f = f.sort_values("bidirectional_first_seen_ms", kind="stable").reset_index(drop=True)
    f["window"] = f["bidirectional_first_seen_ms"] // WINDOW_MS

    is_tcp = f["protocol"] == 6
    # TCP: a connection is "initiated" when the first piece carries the SYN.
    # Non-TCP: a new piece right after an active-timeout split (expiration_id == 1) is a continuation.
    key = ["src_mac", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
    continuation = f.groupby(key)["expiration_id"].shift(1) == 1
    f["initiated"] = np.where(is_tcp, f["src2dst_syn_packets"] > 0, ~continuation)
    # Failed connection (spec): SYN seen, no SYN-ACK back
    f["failed"] = is_tcp & (f["src2dst_syn_packets"] > 0) & (f["dst2src_syn_packets"] == 0)
    return f


def _packet_table(f: pd.DataFrame) -> pd.DataFrame:
    """One row per packet: flow index, time (ms), frame length, direction (0 = src->dst)."""
    fi, t, size, d = [], [], [], []
    for i, trace in zip(f.index, f["udps_trace"]):
        tr = ast.literal_eval(trace) if isinstance(trace, str) else trace
        for tt, ss, dd in tr:
            fi.append(i)
            t.append(tt)
            size.append(ss)
            d.append(dd)
    p = pd.DataFrame({"fi": fi, "t": t, "size": size, "dir": d})
    p["window"] = p["t"] // WINDOW_MS
    return p


def _std(x: np.ndarray) -> float:
    return float(np.std(x)) if len(x) > 1 else 0.0       # population std; 1 sample -> 0


def build_baseline(df: pd.DataFrame, ports: set[int], dsts: set[str]) -> dict:
    """Baseline from the first BASELINE_WINDOWS windows (FR-04). Consumed by Student 2."""
    base = df.iloc[:BASELINE_WINDOWS]
    ml = base[list(ML_FEATURES)].astype(float)
    return {
        "complete": bool(len(base) >= BASELINE_WINDOWS),
        "windows_used": int(len(base)),
        "mean_packet_rate": float(base["packet_rate_10s"].mean()) if len(base) else 0.0,
        "port_whitelist": sorted(int(p) for p in ports),
        "known_destinations": sorted(dsts),
        "ml_mean": {k: float(x) for k, x in ml.mean().items()},
        "ml_std": {k: float(x) for k, x in ml.std(ddof=0).items()},
    }


# --------------------------------------------------------------------------- main builder
def build_features(
    flows: pd.DataFrame,
    devices: pd.DataFrame | None = None,
    baselines: dict[str, dict] | None = None,
) -> tuple[pd.DataFrame, dict[str, dict]]:
    """Return (feature table, baseline per device).

    baselines: optional baseline.json content from a *normal* capture. When given, both flags are
    computed against it from the first window (no LEARNING state) - use this for attack captures.
    """
    f = prepare_flows(flows)
    if f.empty:
        return pd.DataFrame(columns=FEATURE_COLUMNS), {}
    pk = _packet_table(f)
    first_window, last_window = int(pk["window"].min()), int(pk["window"].max())

    if devices is not None:
        macs = list(devices["mac"])
    else:
        macs = sorted({m for m in f.loc[f["initiated"], "src_mac"] if _is_unicast(m)})

    rows: list[dict] = []
    out_baselines: dict[str, dict] = {}
    for mac in macs:
        src_idx = f.index[f["src_mac"] == mac]
        dst_idx = f.index[f["dst_mac"] == mac]
        if len(src_idx) + len(dst_idx) == 0:
            log.warning("device %s not seen in capture", mac)
            continue
        # this device's packets; `sent` = packet sent by the device
        dp = pk[pk["fi"].isin(src_idx.union(dst_idx))].copy()
        is_src_flow = dp["fi"].isin(src_idx)
        dp["sent"] = np.where(is_src_flow, dp["dir"] == 0, dp["dir"] == 1)
        dp = dp.sort_values("t", kind="stable")
        src_set = set(src_idx)
        dev_first = int(dp["window"].min())
        by_win = {int(w): g for w, g in dp.groupby("window")}

        ext = baselines.get(mac) if baselines else None
        seen_dst: set[str] = set(ext["known_destinations"]) if ext else set()
        learn_ports: set[int] = set()
        learn_dsts: set[str] = set()
        init_flows = f.loc[src_idx][f.loc[src_idx, "initiated"]]
        init_by_win = {int(w): g for w, g in init_flows.groupby("window")}
        failed_by_win = init_flows[init_flows["failed"]].groupby("window").size().to_dict()
        dev_rows: list[dict] = []

        for w in range(dev_first, last_window + 1):
            idx = w - dev_first
            row = {"window_start": float(w * WINDOW_S), "device_mac": mac, **_EMPTY_ROW}
            ports: set[int] = set()
            g = by_win.get(w)
            init = init_by_win.get(w)
            if init is not None:                       # connections initiated in this window
                new_dst = set(init["dst_ip"]) - seen_dst
                seen_dst |= new_dst
                learn_dsts |= set(init["dst_ip"])
                row["connection_count"] = int(len(init))
                row["new_destination_count"] = int(len(new_dst))
            if g is not None:
                t = g["t"].to_numpy(dtype=float)
                sz = g["size"].to_numpy(dtype=float)
                gaps = np.diff(t)                      # ms between consecutive packets (g sorted by t)
                row["packet_rate_10s"] = len(g) / WINDOW_S
                row["bytes_sent_rate"] = float(g.loc[g["sent"], "size"].sum() / WINDOW_S)
                row["activity_time"] = float(len(np.unique((t // 1000).astype(np.int64))))
                row["mean_packet_size"] = float(sz.mean())
                row["std_packet_size"] = _std(sz)
                row["mean_inter_arrival"] = float(gaps.mean()) if len(gaps) else 0.0
                row["std_inter_arrival"] = _std(gaps)
                # identifiers: the flow with most packets in this window (device's point of view)
                top_fi = g["fi"].value_counts().index[0]
                top = f.loc[top_fi]
                from_dev = top_fi in src_set
                row["ip_src"] = top["src_ip"] if from_dev else top["dst_ip"]
                row["ip_dst"] = top["dst_ip"] if from_dev else top["src_ip"]
                row["port_src"] = int(top["src_port"] if from_dev else top["dst_port"])
                row["port_dst"] = int(top["dst_port"] if from_dev else top["src_port"])
                row["protocol_type"] = IP_PROTO_TO_TRANSPORT[int(top["protocol"])].value
                row["app_protocol"] = app_from_port(row["port_dst"]).value
                # destination ports the device sent traffic to in this window (whitelist / flag)
                sent_fi = set(g.loc[g["sent"], "fi"]) & src_set
                ports = {int(p) for p in f.loc[list(sent_fi), "dst_port"]}
            row["_ports"], row["_idx"], row["_failed_here"] = ports, idx, int(failed_by_win.get(w, 0))
            if idx < BASELINE_WINDOWS:
                learn_ports |= ports
            dev_rows.append(row)

        # failed_conn_count over the trailing 60 s (current + previous 5 windows)
        failed = np.array([r["_failed_here"] for r in dev_rows])
        csum = np.concatenate([[0], np.cumsum(failed)])
        for i, r in enumerate(dev_rows):
            r["failed_conn_count"] = int(csum[i + 1] - csum[max(0, i + 1 - _FAILED_SPAN)])

        # ---- baseline + flags
        tmp = pd.DataFrame(dev_rows)
        tmp["traffic_spike_flag"] = 0
        tmp["unusual_port_flag"] = 0
        if ext is not None:                            # external baseline: no LEARNING state
            mean_rate = float(ext["mean_packet_rate"])
            whitelist = {int(p) for p in ext["port_whitelist"]}
            active_from = 0
        else:
            mean_rate = float(tmp["packet_rate_10s"].iloc[:BASELINE_WINDOWS].mean())
            whitelist = learn_ports
            active_from = BASELINE_WINDOWS if len(tmp) >= BASELINE_WINDOWS else len(tmp) + 1
        act = tmp["_idx"] >= active_from               # LEARNING windows keep both flags at 0
        if act.any():
            tmp.loc[act, "traffic_spike_flag"] = (
                tmp.loc[act, "packet_rate_10s"] > SPIKE_FACTOR * mean_rate).astype(int)
            tmp.loc[act, "unusual_port_flag"] = tmp.loc[act, "_ports"].apply(
                lambda p: int(len(p - whitelist) > 0)).astype(int)
        out_baselines[mac] = ext if ext is not None else build_baseline(tmp, learn_ports, learn_dsts)
        rows.extend(tmp.drop(columns=["_ports", "_idx", "_failed_here"]).to_dict("records"))

    table = pd.DataFrame(rows)[FEATURE_COLUMNS]
    table = table.sort_values(["window_start", "device_mac"]).reset_index(drop=True)
    for c in ("connection_count", "new_destination_count", "failed_conn_count",
              "traffic_spike_flag", "unusual_port_flag", "port_src", "port_dst"):
        table[c] = table[c].astype(int)
    return table, out_baselines


# --------------------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="pcap -> FR-03 feature vectors (10 s windows)")
    ap.add_argument("pcap", help="input .pcap / .pcapng")
    ap.add_argument("-o", "--out", required=True, help="output features CSV")
    ap.add_argument("--devices", help="devices.csv (mac,name,type). Default: auto-detect initiators")
    ap.add_argument("--baseline-from", help="baseline JSON from a normal capture (skips LEARNING)")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(message)s")

    flows = extract_flows(a.pcap)
    log.info("flows (<=10 s pieces): %d", len(flows))
    ext = json.loads(Path(a.baseline_from).read_text()) if a.baseline_from else None
    table, baselines = build_features(flows, load_devices(a.devices), ext)

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(out, index=False)
    if not ext:
        bpath = out.with_name(out.stem.removesuffix("_features") + "_baseline.json")
        bpath.write_text(json.dumps(baselines, indent=2))
        log.info("baseline  -> %s", bpath)
    log.info("features  -> %s  (%d rows, %d devices)", out, len(table), table["device_mac"].nunique())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
