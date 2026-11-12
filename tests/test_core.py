import random

from trustadapt.anomaly.detector import AnomalyDetectorRegistry
from trustadapt.features.schema import (AppProtocol, IoTDeviceFeatureVector,
                                        TransportProtocol)
from trustadapt.trust_score.engine import TrustScoreEngine, ML_FEATURES


def make_vector(**over):
    base = dict(
        window_start=0.0, device_mac="AA:BB:CC:DD:EE:01", ip_src="192.168.1.20",
        ip_dst="192.168.1.1", port_src=50000, port_dst=443,
        protocol_type=TransportProtocol.TCP, app_protocol=AppProtocol.HTTP,
        packet_rate_10s=45, bytes_sent_rate=25_000, connection_count=3,
        new_destination_count=0, activity_time=10, mean_packet_size=555,
        std_packet_size=310, mean_inter_arrival=22, std_inter_arrival=15,
        traffic_spike_flag=False, unusual_port_flag=False, failed_conn_count=0,
    )
    base.update(over)
    return IoTDeviceFeatureVector(**base)


def test_vector_has_12_values_in_fixed_order():
    v = make_vector()
    assert len(ML_FEATURES) == 12
    assert len(v.to_ml_input_array()) == 12
    assert v.to_ml_input_array()[0] == 45.0


def test_attack_window_scores_higher_than_normal():
    random.seed(1)
    baseline = [make_vector(
        packet_rate_10s=random.gauss(45, 6), bytes_sent_rate=random.gauss(25_000, 4_000),
        connection_count=max(0, round(random.gauss(3, 1))),
        mean_packet_size=random.gauss(555, 40), std_packet_size=random.gauss(310, 30),
        mean_inter_arrival=random.gauss(22, 5), std_inter_arrival=random.gauss(15, 5),
    ) for _ in range(50)]
    det = AnomalyDetectorRegistry().train_device("AA:BB:CC:DD:EE:01", baseline)
    attack = make_vector(packet_rate_10s=250, bytes_sent_rate=300_000, connection_count=18,
                         new_destination_count=4, mean_packet_size=1200,
                         std_packet_size=420, mean_inter_arrival=4, std_inter_arrival=3,
                         traffic_spike_flag=True, unusual_port_flag=True, failed_conn_count=14)
    normal_avg = sum(det.severity(v) for v in baseline) / len(baseline)
    assert det.severity(attack) > 0.3
    assert det.severity(attack) > normal_avg


def test_score_levels_and_decimal_scores():
    e = TrustScoreEngine("d", score=79.5)
    assert e.trust_level()[0] == "Suspicious"
    e.score = 100
    assert e.trust_level()[0] == "Trusted"
    e.score = 0
    assert e.trust_level()[0] == "Blocked"


def test_one_window_cannot_drop_trusted_to_quarantined():
    e = TrustScoreEngine("d", score=80.0)
    base = {n: (0.0, 1.0) for n in ML_FEATURES}
    e.update({n: 10.0 for n in ML_FEATURES}, base, severity=1.0)
    assert e.score == 50.0  # P_MAX = 30
