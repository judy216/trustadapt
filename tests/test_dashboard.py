"""Dashboard data layer (Student 4). Pure pandas - no Streamlit needed."""
import io

import pandas as pd
import pytest

from trustadapt.dashboard.data import (SAMPLE_DIR, SAMPLE_SCENARIOS, DataError, alerts, build_dataset,
                            device_summary, load_sample)

NORMAL, ATTACK = list(SAMPLE_SCENARIOS)
CAM = "02:42:0a:4d:00:11"


def test_sample_loads_with_names_and_local_time():
    ds = load_sample(NORMAL)
    assert set(ds.features["device_name"]) == {"cam-01", "therm-01", "sensor-01"}
    assert str(ds.features["time"].dt.tz) == "Asia/Riyadh"
    assert len(ds.baseline) == 3


def test_normal_capture_has_no_alerts():
    assert alerts(load_sample(NORMAL)).empty


def test_attack_alerts_only_on_cam01():
    al = alerts(load_sample(ATTACK))
    assert not al.empty
    assert set(al["device_mac"]) == {CAM}
    assert al["reasons"].str.contains("Traffic spike").any()
    assert al["reasons"].str.contains("failed connections").any()


def test_summary_one_row_per_device_all_monitoring():
    s = device_summary(load_sample(ATTACK))
    assert len(s) == 3
    assert (s["status"] == "MONITORING").all()
    assert s.set_index("device_mac").loc[CAM, "alert_windows"] > 0


def test_learning_without_baseline_for_short_capture():
    csv = (SAMPLE_DIR / "synthetic_normal_features.csv").read_text().splitlines()
    short = "\n".join(csv[:1] + csv[1:31])          # 10 windows x 3 devices
    ds = build_dataset(io.StringIO(short))
    assert (device_summary(ds)["status"] == "LEARNING").all()


def test_missing_column_is_reported():
    df = pd.read_csv(SAMPLE_DIR / "synthetic_normal_features.csv").drop(columns=["packet_rate_10s"])
    with pytest.raises(DataError, match="packet_rate_10s"):
        build_dataset(io.StringIO(df.to_csv(index=False)))


def test_contract_follows_team_modules():
    from trustadapt.dashboard.contract import FEATURE_COLUMNS, ML_FEATURES, std_floor
    from trustadapt.trust_score.engine import ML_FEATURES as ENGINE_ML
    assert FEATURE_COLUMNS[0] == "window_start" and len(FEATURE_COLUMNS) == 20
    assert ML_FEATURES == ENGINE_ML
    sample = pd.read_csv(SAMPLE_DIR / "synthetic_normal_features.csv", nrows=1)
    assert list(sample.columns) == FEATURE_COLUMNS
    from trustadapt.baseline.baseline_profile import ABS_FLOOR
    assert all(std_floor(f) == ABS_FLOOR[f] for f in ML_FEATURES)          # same floors as engine.py
    assert std_floor("packet_rate_10s") == 0.1 and std_floor("traffic_spike_flag") == 0.2
