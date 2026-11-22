"""Tests for the Week 10 finalization changes (run: pytest -q). Each test pins down one problem that was found
in the Week 9 pipeline, so it cannot come back."""
import sqlite3
import struct

import pandas as pd
import pytest
from scapy.all import IP, UDP, Ether, PcapWriter, Raw

from trustadapt.features import synth
from trustadapt.features.extract import (NoDevicesFound, build_features, extract_flows, load_devices, main,
                                spike_threshold)
from trustadapt.features.schema import BASELINE_WINDOWS, FEATURE_COLUMNS
from trustadapt.store.feature_vectors import read_feature_vectors, write_feature_vectors
from trustadapt.features.validate import MAX_NORMAL_FRAME, cross_check

CAM = "02:42:0a:4d:00:11"
CAM_IP = "10.77.0.11"
T0 = synth.T0
FIXTURES = __import__("pathlib").Path(__file__).resolve().parent / "fixtures"   # small synthetic reference CSVs


@pytest.fixture(scope="session")
def lab(tmp_path_factory):
    d = tmp_path_factory.mktemp("final")
    synth.write_devices_csv(d / "devices.csv")
    return dict(dir=d, devices_csv=d / "devices.csv", devices=load_devices(d / "devices.csv"),
                normal=synth.generate("normal", d / "normal.pcap"), attack=synth.generate("attack", d / "attack.pcap"))


# ---- known_destinations must describe the baseline windows only -------------------------------------------
def test_known_destinations_only_from_baseline_windows(lab, tmp_path):
    b = synth.Builder(7)
    b.normal()
    b.tcp(T0 + 605, CAM, synth.CLOUD_MAC, CAM_IP, "10.77.0.200", 80, up=[100], down=[100])   # first contact in window 60
    b.write(tmp_path / "late.pcap")
    _, base = build_features(extract_flows(tmp_path / "late.pcap"), lab["devices"])
    assert "10.77.0.200" not in base[CAM]["known_destinations"]
    assert "10.77.0.100" in base[CAM]["known_destinations"]            # the cloud, contacted in the baseline


def test_late_destination_is_new_when_baseline_is_reused(lab, tmp_path):
    """A host the normal capture only met AFTER its baseline must count as new when an attack capture contacts it."""
    late = synth.Builder(7)
    late.normal()
    late.tcp(T0 + 605, CAM, synth.CLOUD_MAC, CAM_IP, "10.77.0.200", 80, up=[100], down=[100])
    late.write(tmp_path / "late.pcap")
    atk = synth.Builder(7)
    atk.attack()
    atk.tcp(T0 + 15, CAM, synth.CLOUD_MAC, CAM_IP, "10.77.0.200", 80, up=[100], down=[100])
    atk.write(tmp_path / "atk.pcap")
    _, base_late = build_features(extract_flows(tmp_path / "late.pcap"), lab["devices"])
    _, base_norm = build_features(extract_flows(lab["normal"]), lab["devices"])
    t_late, _ = build_features(extract_flows(tmp_path / "atk.pcap"), lab["devices"], base_late)
    t_norm, _ = build_features(extract_flows(tmp_path / "atk.pcap"), lab["devices"], base_norm)
    new = lambda t: int(t[t.device_mac == CAM].new_destination_count.sum())
    assert new(t_late) == new(t_norm)             # neither baseline knew 10.77.0.200, so both count it


# ---- wrong device list gives a clear message --------------------------------------------------------------
def test_unknown_devices_raise_a_clear_error(lab, tmp_path):
    (tmp_path / "wrong.csv").write_text("mac,name,type\n02:42:0a:4d:00:aa,ghost,camera\n")
    with pytest.raises(NoDevicesFound) as e:
        build_features(extract_flows(lab["normal"]), load_devices(tmp_path / "wrong.csv"))
    assert CAM in str(e.value)                                            # tells the user which MACs it did see


def test_cli_returns_2_for_unknown_devices(lab, tmp_path):
    (tmp_path / "wrong.csv").write_text("mac,name,type\n02:42:0a:4d:00:aa,ghost,camera\n")
    assert main([str(lab["normal"]), "-o", str(tmp_path / "o" / "x_features.csv"), "--devices", str(tmp_path / "wrong.csv")]) == 2


# ---- spike flag for sparse devices ------------------------------------------------------------------------
def test_spike_threshold_keeps_the_literal_rule_for_steady_devices():
    assert spike_threshold(4.4, 0.5) == pytest.approx(13.2)               # 3 x mean is larger -> unchanged
    assert spike_threshold(0.066, 0.093) == pytest.approx(0.345)          # sparse device: mean + 3 std is larger
    assert spike_threshold(0.0, 0.0) == 0.0                               # no baseline traffic -> any traffic is a spike


def _heartbeat_capture(path, one_off_packet):
    """UDP heartbeat (2 packets) every 30 s. With a start-up packet the baseline holds 16 heartbeats instead of 17."""
    mac, ip = "02:42:0a:4d:00:21", "10.77.0.21"
    with PcapWriter(str(path)) as w:
        def pkt(src_mac, dst_mac, sip, dip, sp, dp, t):
            p = Ether(src=src_mac, dst=dst_mac) / IP(src=sip, dst=dip) / UDP(sport=sp, dport=dp) / Raw(b"\x00" * 30)
            p.time = T0 + t
            w.write(p)
        if one_off_packet:
            pkt(mac, synth.CLOUD_MAC, ip, synth.CLOUD_IP, 50501, 5683, 0.5)
        t = 25.0 if one_off_packet else 5.0
        while t < 1500:
            pkt(mac, synth.CLOUD_MAC, ip, synth.CLOUD_IP, 50500, 5683, t)
            pkt(synth.CLOUD_MAC, mac, synth.CLOUD_IP, ip, 5683, 50500, t + 0.005)
            t += 30
    return mac


@pytest.mark.parametrize("one_off", [False, True])
def test_heartbeat_device_is_not_flagged_either_way(tmp_path, one_off):
    mac = _heartbeat_capture(tmp_path / "hb.pcap", one_off)
    (tmp_path / "hb.csv").write_text(f"mac,name,type\n{mac},hb,sensor\n")
    tab, base = build_features(extract_flows(tmp_path / "hb.pcap"), load_devices(tmp_path / "hb.csv"))
    heartbeats_in_baseline = int((tab.packet_rate_10s.iloc[:BASELINE_WINDOWS] >= 0.2).sum())
    assert heartbeats_in_baseline == (16 if one_off else 17)              # the two cases really differ
    assert tab.iloc[BASELINE_WINDOWS:].traffic_spike_flag.sum() == 0      # the old rule flagged all of them when 16
    assert base[mac]["spike_threshold"] > 0.3


def test_flood_still_triggers_the_spike_flag(lab):
    _, base = build_features(extract_flows(lab["normal"]), lab["devices"])
    tab, _ = build_features(extract_flows(lab["attack"]), lab["devices"], base)
    flood = tab[(tab.device_mac == CAM) & ((tab.window_start - T0) >= 300) & ((tab.window_start - T0) < 360)]
    assert (flood.traffic_spike_flag == 1).all()


def test_old_baseline_json_without_std_still_works(lab):
    """A baseline file from before this version has no std_packet_rate: fall back to ml_std, then to the literal rule."""
    _, base = build_features(extract_flows(lab["normal"]), lab["devices"])
    old = {m: {k: v for k, v in b.items() if k not in ("std_packet_rate", "spike_threshold")} for m, b in base.items()}
    tab, _ = build_features(extract_flows(lab["attack"]), lab["devices"], old)
    assert tab[tab.device_mac == CAM].traffic_spike_flag.sum() > 0


# ---- the identifier columns hide a scan: the ports file shows it ------------------------------------------
def test_ports_file_shows_every_destination_port(lab):
    _, base = build_features(extract_flows(lab["normal"]), lab["devices"])
    ports = []
    tab, _ = build_features(extract_flows(lab["attack"]), lab["devices"], base, ports_out=ports)
    p = pd.DataFrame(ports)
    scan = (p.device_mac == CAM) & ((p.window_start - T0) >= 400) & ((p.window_start - T0) < 410)
    ident = tab[(tab.device_mac == CAM) & ((tab.window_start - T0) == 400)]
    assert ident.port_dst.nunique() == 1                                    # the vector names ONE port ...
    assert p[scan].port_dst.nunique() > 100                                 # ... the ports file lists the whole scan
    normal_ports = p.port_dst.isin([80, 1883])                              # the camera's own whitelisted ports
    assert (p[scan & ~normal_ports].outside_whitelist == 1).all()           # every scanned port is outside it
    assert (p[scan & normal_ports].outside_whitelist == 0).all()            # its normal traffic is still inside
    quiet = p[(p.device_mac == CAM) & ((p.window_start - T0) < 300)]
    assert quiet.outside_whitelist.sum() == 0 and set(quiet.port_dst) == {80, 1883}
    flood = p[(p.device_mac == CAM) & (p.port_dst == 9999)]
    assert flood.packets_sent.sum() > 10000 and (flood.protocol_type == "UDP").all()


def test_ports_file_packets_match_bytes_free_totals(lab):
    """Every packet the device sent is in exactly one ports row."""
    ports = []
    build_features(extract_flows(lab["normal"]), lab["devices"], ports_out=ports)
    p = pd.DataFrame(ports)
    assert p.packets_sent.min() > 0 and p.flows.min() >= 1
    assert set(p.columns) == {"window_start", "device_mac", "port_dst", "protocol_type", "app_protocol",
                              "packets_sent", "flows", "outside_whitelist"}


def test_cli_writes_features_baseline_ports_and_database(lab, tmp_path):
    out, db = tmp_path / "proc" / "demo_features.csv", tmp_path / "store" / "trust.db"
    assert main([str(lab["normal"]), "-o", str(out), "--devices", str(lab["devices_csv"]), "--db", str(db)]) == 0
    assert out.exists() and (tmp_path / "proc" / "demo_baseline.json").exists() and (tmp_path / "proc" / "demo_ports.csv").exists()
    csv = pd.read_csv(out, keep_default_na=False, na_values=[])
    assert len(read_feature_vectors(db)) == len(csv) == 3 * 72


# ---- shared store -----------------------------------------------------------------------------------------
def test_database_round_trip_and_no_duplicates(lab, tmp_path):
    tab, _ = build_features(extract_flows(lab["normal"]), lab["devices"])
    db = tmp_path / "s.db"
    assert write_feature_vectors(db, tab) == len(tab)
    assert write_feature_vectors(db, tab) == len(tab)                       # run twice: still one row per window
    back = read_feature_vectors(db)
    assert len(back) == len(tab) and list(back.columns) == FEATURE_COLUMNS
    pd.testing.assert_frame_equal(back.sort_values(["window_start", "device_mac"]).reset_index(drop=True),
                                  tab.sort_values(["window_start", "device_mac"]).reset_index(drop=True),
                                  check_dtype=False)
    assert len(read_feature_vectors(db, CAM)) == 72
    assert sqlite3.connect(db).execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_database_rejects_a_table_with_wrong_columns(tmp_path):
    with pytest.raises(ValueError):
        write_feature_vectors(tmp_path / "s.db", pd.DataFrame({"a": [1]}))


# ---- regression: the synthetic reference CSVs must not change --------------------------------------------
def test_synthetic_reference_csvs_are_reproduced(lab):
    """tests/fixtures holds the feature CSVs that real NFStream produced from the synthetic captures (Week 9). The pipeline must
    still reproduce them exactly. The test is skipped when the files are not in the repository."""
    base_tab, base = build_features(extract_flows(lab["normal"]), lab["devices"])
    atk_tab, _ = build_features(extract_flows(lab["attack"]), lab["devices"], base)
    for tab, name in ((base_tab, "synthetic_normal_features.csv"), (atk_tab, "synthetic_attack_features.csv")):
        if not (FIXTURES / name).exists():
            pytest.skip(f"{name} is not in tests/fixtures")
        ref = pd.read_csv(FIXTURES / name, keep_default_na=False, na_values=[])
        pd.testing.assert_frame_equal(tab.reset_index(drop=True), ref, check_dtype=False)


# ---- validator warns about merged (offloaded) frames ------------------------------------------------------
def test_validator_reports_oversized_frames(tmp_path):
    p = tmp_path / "big.pcap"
    with PcapWriter(str(p)) as w:
        for t, size in ((0.5, 100), (0.6, 4000)):                           # 4000 B payload: a merged "super frame"
            pkt = Ether(src=CAM, dst=synth.CLOUD_MAC) / IP(src=CAM_IP, dst=synth.CLOUD_IP) / UDP(sport=4000, dport=9999) / Raw(b"\x00" * size)
            pkt.time = T0 + t
            w.write(pkt)
    tab, _ = build_features(extract_flows(p), None)
    _, info = cross_check(str(p), tab)
    assert info[CAM]["max_frame_B"] > MAX_NORMAL_FRAME
