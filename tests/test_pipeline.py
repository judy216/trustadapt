"""End-to-end tests on synthetic traffic (run: pytest -q)."""
import json
import struct

import pandas as pd
import pytest
from scapy.all import IP, TCP, Ether, PcapWriter

from trustadapt.features import synth
from trustadapt.features.extract import build_features, extract_flows, load_devices
from trustadapt.features.schema import (BASELINE_WINDOWS, FEATURE_COLUMNS, ML_FEATURES,
                               IoTDeviceFeatureVector)
from trustadapt.features.validate import check_schema, cross_check

CAM = "02:42:0a:4d:00:11"
T0 = synth.T0


@pytest.fixture(scope="session")
def env(tmp_path_factory):
    d = tmp_path_factory.mktemp("lab")
    devices_csv = d / "devices.csv"
    synth.write_devices_csv(devices_csv)
    devices = load_devices(devices_csv)
    normal = synth.generate("normal", d / "normal.pcap")
    attack = synth.generate("attack", d / "attack.pcap")
    n_tab, n_base = build_features(extract_flows(normal), devices)
    a_tab, _ = build_features(extract_flows(attack), devices, n_base)
    a_self, _ = build_features(extract_flows(attack), devices)          # self-learning baseline
    return dict(normal=normal, attack=attack, devices=devices, n_tab=n_tab, n_base=n_base,
                a_tab=a_tab, a_self=a_self)


def test_schema_constants():
    assert len(FEATURE_COLUMNS) == 20            # window_start + 19 schema fields
    assert len(ML_FEATURES) == 12
    v = IoTDeviceFeatureVector(0.0, "m", "a", "b", 1, 2, "TCP", "HTTP", 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 0, 2)
    assert v.to_ml_input_array() == [1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 0, 2]


def test_normal_schema_and_totals(env):
    assert check_schema(env["n_tab"]) == []
    errs, _ = cross_check(str(env["normal"]), env["n_tab"])
    assert errs == []                             # packet and byte totals match the pcap exactly
    assert env["n_tab"]["device_mac"].nunique() == 3
    assert len(env["n_tab"]) == 3 * 72


def test_normal_baseline_and_flags(env):
    for mac, b in env["n_base"].items():
        assert b["complete"] and b["windows_used"] == BASELINE_WINDOWS
    assert env["n_base"][CAM]["port_whitelist"] == [80, 1883]
    # learning windows: both flags 0; normal traffic stays unflagged afterwards
    assert env["n_tab"]["traffic_spike_flag"].sum() == 0
    assert env["n_tab"]["unusual_port_flag"].sum() == 0


def test_attack_detected_with_external_baseline(env):
    t = env["a_tab"]
    cam = t[t.device_mac == CAM].assign(sec=lambda x: (x.window_start - T0).astype(int))
    flood = cam[(cam.sec >= 300) & (cam.sec < 360)]
    assert (flood.traffic_spike_flag == 1).all() and (flood.unusual_port_flag == 1).all()
    scan = cam[(cam.sec >= 400) & (cam.sec < 430)]
    assert scan.failed_conn_count.max() >= 400
    exfil = cam[(cam.sec >= 500) & (cam.sec < 560)]
    assert exfil.new_destination_count.sum() == 37
    quiet = cam[(cam.sec < 300)]
    assert quiet.traffic_spike_flag.sum() == 0
    others = t[t.device_mac != CAM]
    assert others[["traffic_spike_flag", "unusual_port_flag", "failed_conn_count"]].sum().sum() == 0


def test_learning_state_without_external_baseline(env):
    """Attack starts inside the first 50 windows -> flags stay 0 during LEARNING (baseline poisoning risk)."""
    cam = env["a_self"][env["a_self"].device_mac == CAM].reset_index(drop=True)
    assert (cam.loc[:BASELINE_WINDOWS - 1, ["traffic_spike_flag", "unusual_port_flag"]] == 0).all().all()


def test_empty_windows_are_emitted(tmp_path):
    p = tmp_path / "gap.pcap"
    with PcapWriter(str(p)) as w:
        for t in (0.5, 0.6, 45.2):
            pkt = Ether(src=CAM, dst="02:42:0a:4d:00:64") / IP(src="10.77.0.11", dst="10.77.0.100") / TCP(sport=4000, dport=80, flags="S")
            pkt.time = T0 + t
            w.write(pkt)
    tab, _ = build_features(extract_flows(p), None)
    assert len(tab) == 5                           # windows 0..4 -> three of them empty
    empty = tab[tab.packet_rate_10s == 0]
    assert len(empty) == 3
    assert (empty[["bytes_sent_rate", "connection_count", "activity_time",
                   "mean_packet_size", "mean_inter_arrival"]] == 0).all().all()
    assert check_schema(tab) == []


def test_payload_not_needed(env, tmp_path):
    """Capture with snaplen 128 (headers only, NFR-05) gives identical features."""
    b = env["attack"].read_bytes()
    out = bytearray(b[:24])
    struct.pack_into("<I", out, 16, 128)
    i = 24
    while i < len(b):
        ts, us, cap, orig = struct.unpack("<IIII", b[i:i + 16])
        data = b[i + 16:i + 16 + cap]
        i += 16 + cap
        out += struct.pack("<IIII", ts, us, min(cap, 128), orig) + data[:128]
    p = tmp_path / "snap.pcap"
    p.write_bytes(bytes(out))
    t, _ = build_features(extract_flows(p), env["devices"], env["n_base"])
    pd.testing.assert_frame_equal(t, env["a_tab"])
