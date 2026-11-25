"""Week 10 check of FR-05 + re-run of the Week 9 integration check (report Section 5).

    python -m trustadapt.anomaly.evaluate                       # real lab captures in data/processed/
    python -m trustadapt.anomaly.evaluate --normal N.csv --attack A.csv --out data/processed/anomaly_eval

Baselines are built with baseline_profile.build_baseline() on the first 50 windows of each device in the
NORMAL capture. Every window of both captures is then scored by detector.py and fed to the real
TrustScoreEngine (start score 100, as in the Week 9 check).

Model comparison (planned in the Week 8 report, Section 5): the same rows are also scored by
  * Isolation Forest alone (the calibrated profile model, no z-score part),
  * One-Class SVM alone (standardised features, RBF kernel, nu = 0.05), with the same out-of-fold
    99th-percentile threshold as baseline_profile.py, trained on the same 50 windows.
One-Class SVM is a comparison only: the deciding model stays the Isolation Forest of baseline_profile.py.

Ground truth for the attack capture: a window is an attack window when a flag is set or failed_conn_count > 0
(the same rule as the dashboard alerts).
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from trustadapt.anomaly.detector import AnomalyDetectorRegistry
from trustadapt.baseline.baseline_profile import FEATURES, BaselineContaminated, BaselineNotReady, build_baseline
from trustadapt.trust_score.engine import TrustScoreEngine

ROOT = Path(__file__).resolve().parents[3]
NORMAL = ROOT / "data/processed/normal_20261119_024550_features.csv"
ATTACK = ROOT / "data/processed/attack_20261119_030826_features.csv"
DEVICES = ROOT / "lab/devices.csv"


def truth(table: pd.DataFrame) -> pd.Series:
    return (table.traffic_spike_flag + table.unusual_port_flag + (table.failed_conn_count > 0)) > 0


def week9_severity(normal_rows: pd.DataFrame, rows: pd.DataFrame) -> np.ndarray:
    """The Week 9 detector for comparison: own model, A from 1st-99th pct of in-sample scores."""
    from sklearn.ensemble import IsolationForest
    X = normal_rows.sort_values("window_start").head(50)[list(FEATURES)].to_numpy(float)
    m = IsolationForest(n_estimators=150, contamination=0.02, random_state=42).fit(X)
    base = m.decision_function(X)
    lo, hi = np.percentile(base, [1, 99])
    return np.clip((hi - m.decision_function(rows[list(FEATURES)].to_numpy(float))) / (hi - lo), 0, 1)


def ocsvm_anomalous(normal_rows: pd.DataFrame, rows: pd.DataFrame, random_state: int = 42) -> np.ndarray:
    """One-Class SVM comparison: True where the window is beyond the out-of-fold threshold."""
    from sklearn.model_selection import KFold
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import OneClassSVM

    def model():
        return make_pipeline(StandardScaler(), OneClassSVM(nu=0.05, gamma="scale"))

    X = normal_rows.sort_values("window_start").head(50)[list(FEATURES)].to_numpy(float)
    held = np.empty(len(X))
    for train, test in KFold(5, shuffle=True, random_state=random_state).split(X):
        held[test] = model().fit(X[train]).decision_function(X[test])
    threshold = np.quantile(held, 0.01)                      # same rule as baseline_profile.py
    return model().fit(X).decision_function(rows[list(FEATURES)].to_numpy(float)) < threshold


def run(normal: pd.DataFrame, attack: pd.DataFrame):
    reg, refused = AnomalyDetectorRegistry(), {}
    for mac, g in normal.groupby("device_mac", sort=True):
        try:
            reg.add_profile(build_baseline(mac, g))
        except (BaselineNotReady, BaselineContaminated) as err:
            refused[mac] = str(err)

    scored = {}
    for scen, table in (("normal", normal), ("attack", attack)):
        parts = []
        for mac in reg.devices():
            rows = table[table.device_mac == mac].sort_values("window_start")
            det = reg.get(mac)
            sc = det.score_table(rows)
            sc["truth"] = truth(rows).to_numpy()
            sc["in_baseline"] = (np.arange(len(sc)) < 50) if scen == "normal" else False
            sc["week9_anomalous"] = week9_severity(normal[normal.device_mac == mac], rows) > 0.3
            sc["iforest_only"] = sc.a_iforest > 0.3
            sc["ocsvm_only"] = ocsvm_anomalous(normal[normal.device_mac == mac], rows)
            engine, base = TrustScoreEngine(mac, score=100.0), det.engine_baseline()
            recs = [engine.update(dict(zip(FEATURES, r[list(FEATURES)].astype(float))), base, s)
                    for (_, r), s in zip(rows.iterrows(), sc.severity)]
            sc["trust"] = [r["new_score"] for r in recs]
            sc["trust_level"] = [r["trust_level"] for r in recs]
            sc["contributions"] = [r["contributions"] for r in recs]
            parts.append(sc)
        scored[scen] = pd.concat(parts, ignore_index=True)
    return reg, refused, scored


def summary(scored: dict, names: dict) -> tuple[pd.DataFrame, pd.DataFrame]:
    for sc in scored.values():
        sc["anomalous"] = sc.severity > 0.3
    n, a = scored["normal"], scored["attack"]
    held = n[~n.in_baseline]
    methods = pd.DataFrame([{
        "detector": label,
        "attack windows found": f"{int((a[col] & a.truth).sum())}/{int(a.truth.sum())}",
        "false alarms, attack capture": f"{int((a[col] & ~a.truth).sum())}/{int((~a.truth).sum())}",
        "false alarms, normal hold-out": f"{int(held[col].sum())}/{len(held)}",
        "false alarms, whole normal capture": f"{int(n[col].sum())}/{len(n)}",
    } for label, col in (("Week 9 (old)", "week9_anomalous"),
                         ("Isolation Forest only (calibrated)", "iforest_only"),
                         ("One-Class SVM only (calibrated)", "ocsvm_only"),
                         ("Week 10 (IF + z-score, deciding)", "anomalous"))])
    trust = pd.DataFrame([{
        "scenario": scen, "device": names.get(mac, mac),
        "anomalous windows": f"{int(g.anomalous.sum())}/{len(g)}",
        "of which attack": int((g.anomalous & g.truth).sum()),
        "lowest score": float(g.trust.min()), "final score": float(g.trust.iloc[-1]),
        "final level": g.trust_level.iloc[-1],
    } for scen, sc in scored.items() for mac, g in sc.groupby("device_mac", sort=True)])
    return methods, trust


def main(argv=None):
    ap = argparse.ArgumentParser(description="FR-05 Week 10 check")
    ap.add_argument("--normal", default=str(NORMAL))
    ap.add_argument("--attack", default=str(ATTACK))
    ap.add_argument("--devices", default=str(DEVICES))
    ap.add_argument("--out", default=None, help="folder for per-window CSVs and the saved baselines")
    args = ap.parse_args(argv)

    normal, attack = pd.read_csv(args.normal), pd.read_csv(args.attack)
    names = dict(pd.read_csv(args.devices)[["mac", "name"]].values) if Path(args.devices).exists() else {}
    reg, refused, scored = run(normal, attack)
    methods, trust = summary(scored, names)

    pd.set_option("display.width", 200)
    print("Refused baselines:", refused or "none")
    print("\nThresholds (out of fold, from baseline_profile.py)")
    for mac in reg.devices():
        p = reg.get(mac).profile
        print(f"  {names.get(mac, mac):10s} if_threshold {p.if_threshold:+.4f}  z_threshold {p.z_threshold:.2f}")
    print("\nDetectors\n" + methods.to_string(index=False))
    print("\nTrust Score (TrustScoreEngine, start 100)\n" + trust.to_string(index=False))

    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for scen, sc in scored.items():
            sc.to_csv(out / f"{scen}_scored.csv", index=False)
        methods.to_csv(out / "detectors.csv", index=False)
        trust.to_csv(out / "trust_scores.csv", index=False)
        for mac in reg.devices():
            reg.get(mac).profile.save(out / "baselines")
        print(f"\nWritten to {out}/")


if __name__ == "__main__":
    main()
