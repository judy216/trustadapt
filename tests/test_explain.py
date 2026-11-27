"""Tests for the SHAP groundwork (FR-09, Week 10)."""
import numpy as np
import pandas as pd
import pytest

from trustadapt.baseline.baseline_profile import FEATURES, build_baseline
from trustadapt.explain.shap_explainer import DeviceShapExplainer, ShapExplainerRegistry

MAC = "AA:BB:CC:DD:EE:01"


def make_baseline(n=50, seed=1):
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({
        "window_start": np.arange(n) * 10.0,
        "packet_rate_10s": rng.normal(45, 6, n), "bytes_sent_rate": rng.normal(25_000, 4_000, n),
        "connection_count": rng.integers(2, 5, n), "new_destination_count": np.zeros(n),
        "activity_time": rng.integers(8, 11, n), "mean_packet_size": rng.normal(555, 40, n),
        "std_packet_size": rng.normal(310, 30, n), "mean_inter_arrival": rng.normal(22, 5, n),
        "std_inter_arrival": rng.normal(15, 5, n), "traffic_spike_flag": np.zeros(n),
        "unusual_port_flag": np.zeros(n), "failed_conn_count": np.zeros(n),
    })
    return build_baseline(MAC, df)


@pytest.fixture(scope="module")
def explainer():
    return DeviceShapExplainer(make_baseline())


NORMAL = [45, 25_000, 3, 0, 9, 555, 310, 22, 15, 0, 0, 0]
ATTACK = [250, 300_000, 18, 4, 10, 1200, 420, 4, 3, 1, 1, 14]


def test_shap_adds_up_to_model_output(explainer):
    X = np.array([NORMAL, ATTACK], dtype=float)
    assert explainer.check_additivity(X) < 1e-6
    e = explainer.explain(ATTACK)
    assert e.decision_score == pytest.approx(explainer.model.decision_function([ATTACK])[0], abs=1e-6)


def test_one_value_per_feature_in_fixed_order(explainer):
    e = explainer.explain(ATTACK)
    assert list(e.shap) == list(FEATURES)
    with pytest.raises(ValueError):
        explainer.shap_values([1.0] * 11)


def test_attack_is_explained_by_anomalous_features(explainer):
    e = explainer.explain(ATTACK)
    assert e.path_length < e.base_value            # shorter path = more anomalous
    assert sum(e.anomaly_share.values()) == pytest.approx(1.0)
    assert set(e.top_features()) <= {"packet_rate_10s", "bytes_sent_rate", "connection_count",
                                     "new_destination_count", "mean_packet_size", "std_packet_size",
                                     "mean_inter_arrival", "std_inter_arrival"}


def test_points_follow_engine_contributions_format(explainer):
    pts = explainer.explain(ATTACK).to_points(20.0)
    assert all(v > 0 for v in pts.values())
    assert sum(pts.values()) == pytest.approx(20.0, abs=0.1)


def test_constant_baseline_features_get_no_shap(explainer):
    """Known limit: a feature that never changes in the baseline is never split on by the trees,
    so SHAP cannot blame it. The Week 12 explanation must cover these with rules/z-scores."""
    sv = explainer.shap_values(ATTACK)[0]
    for f in ("traffic_spike_flag", "unusual_port_flag", "failed_conn_count", "new_destination_count"):
        assert sv[FEATURES.index(f)] == 0.0


def test_registry_refuses_device_in_learning():
    reg = ShapExplainerRegistry()
    with pytest.raises(KeyError):
        reg.get(MAC)
    reg.add(make_baseline())
    assert reg.get(MAC).device_mac == MAC
