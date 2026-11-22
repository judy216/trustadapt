"""FR-05 Week 10: calibrated detector on the real lab captures of 2026-11-19 (data/processed/)."""
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from trustadapt.anomaly.detector import AnomalyDetectorRegistry, DeviceAnomalyDetector
from trustadapt.anomaly.evaluate import ATTACK, NORMAL, run, truth
from trustadapt.baseline.baseline_profile import FEATURES, BaselineProfile, build_baseline

CAM = "02:42:0a:4d:00:11"
pytestmark = pytest.mark.skipif(not NORMAL.exists() or not ATTACK.exists(), reason="real captures not present")


@pytest.fixture(scope="module")
def result():
    return run(pd.read_csv(NORMAL), pd.read_csv(ATTACK))


def test_no_baseline_refused(result):
    _, refused, _ = result
    assert refused == {}


def test_every_attack_window_found(result):
    a = result[2]["attack"]
    assert a.truth.sum() == 23
    assert (a[a.truth].severity > 0.3).all()


def test_failed_connections_caught_although_zero_in_baseline(result):
    # failed_conn_count is 0 in every baseline window, so Isolation Forest never uses it; the z part must
    a = result[2]["attack"]
    only_failed = a[a.truth & (a.z_traffic_spike_flag.abs() < 1) & (a.z_failed_conn_count > 4)]
    assert len(only_failed) > 0
    assert (only_failed.severity > 0.3).all() and (only_failed.source == "zscore").all()


def test_normal_devices_stay_trusted(result):
    n = result[2]["normal"]
    assert (n[~n.in_baseline].severity > 0.3).sum() <= 2      # Week 9: 42 of 66
    assert (n.trust >= 80).all()                               # never leaves Trusted
    a = result[2]["attack"]
    for mac, g in a.groupby("device_mac"):
        if mac != CAM:
            assert g.trust.iloc[-1] >= 80                      # untouched devices end Trusted


def test_attacked_camera_is_blocked(result):
    a = result[2]["attack"]
    assert a[a.device_mac == CAM].trust.min() < 20


def test_normal_window_has_zero_severity(result):
    n = result[2]["normal"]
    assert n.severity.median() == 0 and n.severity.between(0, 1).all()


def test_profile_save_load_keeps_thresholds(tmp_path):
    g = pd.read_csv(NORMAL)
    p = build_baseline(CAM, g[g.device_mac == CAM])
    p.save(tmp_path)
    q = BaselineProfile.load(tmp_path, CAM)
    assert (q.if_threshold, q.if_spread, q.z_threshold) == (p.if_threshold, p.if_spread, p.z_threshold)
    reg = AnomalyDetectorRegistry()
    assert reg.load_dir(tmp_path) == [CAM]
    row = g[g.device_mac == CAM].iloc[60]
    x = [row[f] for f in FEATURES]
    assert reg.get(CAM).severity(x) == DeviceAnomalyDetector(CAM, p).severity(x)


def test_old_profile_format_is_refused(tmp_path):
    import json
    g = pd.read_csv(NORMAL)
    path = build_baseline(CAM, g[g.device_mac == CAM]).save(tmp_path)
    meta = json.loads(path.read_text())
    del meta["if_threshold"]
    path.write_text(json.dumps(meta))
    with pytest.raises(ValueError, match="older format"):
        BaselineProfile.load(tmp_path, CAM)


def test_std_floor_below_real_std():
    # Week 9 finding: the old 1.0 floor was above the real std of these features
    g = pd.read_csv(NORMAL)
    for mac, rows in g.groupby("device_mac"):
        p = build_baseline(mac, rows)
        real = rows.sort_values("window_start").head(50)[list(FEATURES)].std(ddof=0).to_numpy()
        i = FEATURES.index("packet_rate_10s")
        assert np.isclose(p.std[i], max(real[i], 0.1, 0.05 * abs(p.mean[i])))
        assert p.std[i] < 1.0
