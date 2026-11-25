"""Tests added after the first real capture: merged TCP frames (segmentation offload) and sessions that were already open
when the capture started. Run: pytest -q"""
import numpy as np
import pandas as pd
import pytest
from scapy.all import IP, TCP, Ether, PcapWriter, Raw

from trustadapt.features import synth
from trustadapt.features.extract import build_features, extract_flows, load_devices
from trustadapt.features.resegment import MTU_FRAME, TCP_HEADERS, expand_tcp_frames, segment_sizes
from trustadapt.features.schema import ML_FEATURES
from trustadapt.features.validate import cross_check

DEV, DEV_IP = "02:42:0a:4d:00:31", "10.77.0.31"
GW = synth.CLOUD_MAC
SERVER = synth.CLOUD_IP
BROKER = "10.77.0.2"
T0 = synth.T0
HDR = 54                      # scapy frame with a 20-byte TCP header: 14 + 20 + 20


def _write(path, packets):
    """packets: (time, src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags, frame_size)."""
    with PcapWriter(str(path)) as w:
        for t, smac, dmac, sip, dip, sp, dp, fl, size in sorted(packets):
            pkt = Ether(src=smac, dst=dmac) / IP(src=sip, dst=dip) / TCP(sport=sp, dport=dp, flags=fl) / Raw(b"\x00" * max(size - HDR, 0))
            pkt.time = T0 + t
            w.write(pkt)


def _devices(tmp_path):
    (tmp_path / "d.csv").write_text(f"mac,name,type\n{DEV},cam,camera\n")
    return load_devices(tmp_path / "d.csv")


def _bursts(frame_sizes_for_burst, n=30):
    """One burst every 3 s (at x.5 s so the pieces stay inside one millisecond); an ACK comes back after each."""
    pk = []
    for i in range(n):
        t = 1.5 + 3 * i
        for k, size in enumerate(frame_sizes_for_burst(i)):
            pk.append((t + k * 0.0001, DEV, GW, DEV_IP, SERVER, 4000, 80, "PA", size))
        pk.append((t + 0.01, GW, DEV, SERVER, DEV_IP, 80, 4000, "A", HDR))
    return pk


# ---- the split itself ------------------------------------------------------------------------------------
@pytest.mark.parametrize("size", [1514, 1515, 1580, 2962, 2963, 4380, 6000, 7000, 65226])
def test_vectorised_split_equals_the_plain_function(size):
    pk = pd.DataFrame({"fi": [0, 1, 2], "t": [10, 20, 30], "size": [100, size, 100], "dir": [0, 1, 0]})
    out, n_split, n_added = expand_tcp_frames(pk, np.array([True, True, True]))
    expected = segment_sizes(size)
    assert list(out["size"]) == [100, *expected, 100]
    assert list(out["fi"]) == [0, *([1] * len(expected)), 2]                  # order, flow and direction are kept
    assert list(out["dir"]) == [0, *([1] * len(expected)), 0] and set(out["t"][1:1 + len(expected)]) == {20}
    assert n_split == (1 if size > MTU_FRAME else 0) and n_added == len(expected) - 1
    assert max(expected) <= MTU_FRAME
    assert sum(expected) == size + (len(expected) - 1) * TCP_HEADERS         # one extra header per extra frame


def test_only_tcp_is_split_and_mtu_zero_keeps_frames():
    pk = pd.DataFrame({"fi": [0, 1], "t": [1, 2], "size": [6000, 6000], "dir": [0, 0]})
    out, n_split, _ = expand_tcp_frames(pk, np.array([False, True]))
    assert list(out["size"][:1]) == [6000] and n_split == 1                   # the non-TCP frame is untouched
    assert expand_tcp_frames(pk, np.array([True, True]), 0)[0] is pk          # mtu 0 = off
    jumbo = segment_sizes(20000, 9014)
    assert max(jumbo) <= 9014 and len(jumbo) == 3                             # a jumbo-frame lab can set --mtu 9014


# ---- features from a capture with merged frames -----------------------------------------------------------
def test_merged_frames_give_the_same_features_as_the_real_frames(tmp_path):
    sizes = [4200 + 700 * (i % 5) for i in range(30)]                        # the camera posts 4.2-7.0 KB at a time
    _write(tmp_path / "merged.pcap", _bursts(lambda i: [sizes[i]]))
    _write(tmp_path / "wire.pcap", _bursts(lambda i: segment_sizes(sizes[i])))   # what a link would have carried
    dev = _devices(tmp_path)
    merged, _ = build_features(extract_flows(tmp_path / "merged.pcap"), dev)
    wire, _ = build_features(extract_flows(tmp_path / "wire.pcap"), dev)
    pd.testing.assert_frame_equal(merged[list(ML_FEATURES)], wire[list(ML_FEATURES)], check_exact=False, atol=1e-9)


def test_without_the_split_merged_frames_distort_the_features(tmp_path):
    _write(tmp_path / "merged.pcap", _bursts(lambda i: [6000]))
    dev = _devices(tmp_path)
    raw, _ = build_features(extract_flows(tmp_path / "merged.pcap"), dev, mtu=0)
    fixed, _ = build_features(extract_flows(tmp_path / "merged.pcap"), dev)
    bound = lambda t: np.sqrt(t.mean_packet_size * (1514 - t.mean_packet_size).clip(lower=0))
    assert (raw.std_packet_size > bound(raw) + 1e-6).any()                  # impossible for real frames: the symptom
    assert (fixed.std_packet_size <= bound(fixed) + 1e-6).all()             # gone after the split
    assert fixed.packet_rate_10s.sum() > 2 * raw.packet_rate_10s.sum()      # the packet rate was far too low
    assert fixed.mean_packet_size.max() <= MTU_FRAME


def test_validator_recount_agrees_with_the_split(tmp_path):
    _write(tmp_path / "merged.pcap", _bursts(lambda i: [4200 + 700 * (i % 5)]))
    dev = _devices(tmp_path)
    tab, _ = build_features(extract_flows(tmp_path / "merged.pcap"), dev)
    errs, info = cross_check(str(tmp_path / "merged.pcap"), tab)
    assert errs == [] and info[DEV]["max_frame_B"] > MTU_FRAME
    errs_off, _ = cross_check(str(tmp_path / "merged.pcap"), tab, 0)         # validator and extractor must use the same --mtu
    assert errs_off


# ---- sessions that were already open when the capture started ----------------------------------------------
def _open_session(path, seconds, with_reconnect=False):
    pk = [(t, DEV, GW, DEV_IP, BROKER, 4100, 1883, "PA", 100) for t in range(1, seconds, 2)]      # no SYN anywhere
    pk += [(t + 0.01, GW, DEV, BROKER, DEV_IP, 1883, 4100, "A", HDR) for t in range(1, seconds, 2)]
    if with_reconnect:                                                       # the session breaks: a fresh connection
        t = 15.0
        pk += [(t, DEV, GW, DEV_IP, BROKER, 4200, 1883, "S", HDR), (t + 0.01, GW, DEV, BROKER, DEV_IP, 1883, 4200, "SA", HDR),
               (t + 0.02, DEV, GW, DEV_IP, BROKER, 4200, 1883, "A", HDR)]
        t = 25.0                                                             # ... and one really new host
        pk += [(t, DEV, GW, DEV_IP, "10.77.0.250", 4300, 80, "S", HDR), (t + 0.01, GW, DEV, "10.77.0.250", DEV_IP, 80, 4300, "SA", HDR)]
    _write(path, pk)


def test_known_destinations_include_sessions_open_before_the_capture(tmp_path):
    _open_session(tmp_path / "base.pcap", 620)                              # 62 windows, nothing initiated
    _, base = build_features(extract_flows(tmp_path / "base.pcap"), _devices(tmp_path))
    assert BROKER in base[DEV]["known_destinations"]                        # real data had the broker missing for every device
    assert base[DEV]["port_whitelist"] == [1883]


def test_reconnect_to_a_known_broker_is_not_a_new_destination(tmp_path):
    _open_session(tmp_path / "base.pcap", 620)
    dev = _devices(tmp_path)
    _, base = build_features(extract_flows(tmp_path / "base.pcap"), dev)
    _open_session(tmp_path / "later.pcap", 60, with_reconnect=True)
    tab, _ = build_features(extract_flows(tmp_path / "later.pcap"), dev, base)
    assert tab.new_destination_count.sum() == 1                             # only 10.77.0.250 is new
    assert tab.connection_count.sum() == 2                                  # the reconnect and the connection to the new host
