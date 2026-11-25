# Design Notes - extraction layer (Week 9, Part 1; finalized in Week 10)

Implements Week 8 report (FR-03 schema, Section 10 NFStream design). Where the code differs from the
Section 10 sketch, the reason is listed here so the team can update the report consistently.

## 1. Deviations from the Section 10 sketch

| Topic | Sketch (Section 10) | Implementation | Why |
|---|---|---|---|
| Window statistics | Packet-weighted averages of per-flow NFStream values | NFStream is the flow engine; a plugin records `(time, frame length, direction)` of every packet and all window statistics are computed per packet | The sketch's inter-arrival values are **not** close to the exact figure when a window has several flows. Measured on the synthetic lab: the flow-averaged value is about 2-3 ms (gaps inside one connection), while the exact per-device value is about 180 / 304 / 1452 ms (cam / thermostat / sensor); mean error 178 / 302 / 1449 ms. Rates, sizes, activity_time now match an independent scapy recount exactly |
| Window assignment | Whole flow piece goes to the window where it starts | Each packet goes to its own window | A flow piece can span two windows |
| activity_time | Seconds between first and last packet of each flow | Distinct seconds that really carried a packet | The sketch counts idle seconds inside a flow as active |
| connection_count | Number of flow pieces | Initiated connections only (TCP: SYN in first piece; UDP/ICMP: not an active-timeout continuation) | Cutting flows every 10 s would otherwise count one long MQTT session as a new connection every window |
| Direction | Only flows the device initiated | Device counted as source **and** destination | A device also receives traffic it did not initiate (server responses, inbound requests) |

## 2. Definitions that the report leaves open (decisions taken)
1. `packet_rate_10s` counts packets sent **and** received; `bytes_sent_rate` counts bytes **sent** only.
2. `new_destination_count` uses destinations of initiated connections; the "seen" set starts empty (or from the
   external baseline's `known_destinations`), so in a fresh capture the first window counts every destination as new.
3. `unusual_port_flag` = 1 when **any** port the device sent traffic to in the window is outside the whitelist.
4. `traffic_spike_flag` = 1 when the rate is above **max(3 x baseline mean, baseline mean + 3 x baseline std)** (Week 10; the Week 9
   rule was 3 x mean only, see section 5). A device with baseline mean 0 and any traffic -> 1.
5. `failed_conn_count` = trailing 60 s (current + 5 previous windows); it stays high for 60 s after a scan stops.
6. Identifier columns (`ip_*`, `port_*`, `protocol_type`, `app_protocol`) describe the **dominant flow** (most packets) of the window.
7. Population standard deviation everywhere (`ddof = 0`).

## 3. Privacy (FR-02, NFR-05)
* nDPI disabled (`n_dissections=0`); application protocol only from the destination port.
* Capture uses snaplen 128: only Ethernet/IP/TCP|UDP headers reach the disk. A test (`test_payload_not_needed`) proves the
  features are identical with and without payload bytes.
* The plugin stores time, frame length and direction only; no payload field is read.

## 4. Known limitations (state them in the report - they are honest engineering limits)
* **NFStream runs on Linux/macOS only**; on Windows use WSL2 (matches the GP template: Ubuntu 24.04 + Python 3.12).
* The per-packet trace is kept in memory: fine for lab captures (tens of thousands of packets); for multi-GB public
  pcaps (IoT-23) process them in slices (`editcap -c` / `tcpdump -r -w`).
* Device identity = MAC seen at the capture point. Behind a router all devices share the router MAC; the lab uses one flat bridge so each device keeps its own MAC.
* **Baseline poisoning (FR-11):** an attack inside the first 50 windows is learned as normal; flags stay 0 during LEARNING
  (`test_learning_state_without_external_baseline` documents this). Evaluate attacks with `--baseline-from` a clean capture.
  The baseline-profiling code (ML side) also refuses baselines that contain extreme windows, but it cannot catch every case.
* Only IPv4/IPv6 TCP/UDP/ICMP is processed; ARP, IGMP and other protocols are ignored.
* The Docker lab files (`lab/`) are written to match the tested pipeline but could not be executed in the environment
  where the code was developed; the first run on your machine is the real test (see README troubleshooting).
* Timestamps from NFStream have whole-millisecond resolution, so inter-arrival values do too (about 1 ms). The delivered
  synthetic CSVs are reproduced exactly only when pcap timestamps are truncated to milliseconds. At more than a few hundred
  packets/s (the 250 pkt/s flood) `std_inter_arrival` is therefore slightly noisy.
* **Real-capture status.** The first real captures were analysed from their feature CSVs only (section 6). Still unchecked on real
  traffic: TCP resets and teardown, real device timing at scale, NFStream speed on large files, and the re-processed pcaps.

## 5. Week 10 finalization - what changed and why
| # | Change | Reason (how it was found) | Test |
|---|---|---|---|
| 1 | `known_destinations` in the baseline JSON now holds only hosts met in the 50 baseline windows | It collected every host in the whole capture, so a host first contacted later in the normal capture was wrongly "known" when the baseline was reused for an attack capture | `test_known_destinations_only_from_baseline_windows`, `test_late_destination_is_new_when_baseline_is_reused` |
| 2 | Clear error and exit code 2 when none of the listed devices appears in the capture (`NoDevicesFound`) | Before, a wrong MAC list ended in a `KeyError` on the column list | `test_unknown_devices_raise_a_clear_error`, `test_cli_returns_2_for_unknown_devices` |
| 3 | Spike rule: rate > max(3 x mean, mean + 3 x std); baseline JSON gains `std_packet_rate` and `spike_threshold` | A heartbeat device (2 packets every 30 s) was flagged in 34 of 34 normal heartbeat windows when its baseline held 16 heartbeats, and in 0 of 33 when it held 17. For steady devices 3 x mean is the larger term, so nothing changes (the delivered CSVs are reproduced exactly). Older baseline JSON files still work (fallback to `ml_std`, then to 3 x mean) | `test_heartbeat_device_is_not_flagged_either_way`, `test_spike_threshold_keeps_the_literal_rule_for_steady_devices`, `test_flood_still_triggers_the_spike_flag`, `test_old_baseline_json_without_std_still_works` |
| 4 | New `<stem>_ports.csv`: one row per device x window x destination port the device sent to, with packets, flows and `outside_whitelist` | The identifier columns describe only the busiest flow, so a port scan is invisible there (a scan window names 1 port while the device contacted about 200) | `test_ports_file_shows_every_destination_port`, `test_ports_file_packets_match_bytes_free_totals` |
| 5 | `store/feature_vectors.py` and `--db` (imported only when `--db` is used): vectors are also written to the SQLite table `feature_vectors` (key: device_mac + window_start, WAL mode) | The architecture hands vectors to the other modules through one shared store. **The table layout is a proposal and must be confirmed by Integration & Docs** | `test_database_round_trip_and_no_duplicates`, `test_cli_writes_features_baseline_ports_and_database` |
| 6 | `validate` warns when a frame is larger than 1518 bytes | A Docker bridge can merge packets (segmentation offload), which would silently distort counts and sizes | `test_validator_reports_oversized_frames` |
| 7 | Regression test against the synthetic reference CSVs in `tests/fixtures` | Finalization must not change results the team already uses | `test_synthetic_reference_csvs_are_reproduced` |

How it was tested: NFStream and scapy could not be installed where this was finalized, so a stand-in that cuts a pcap into flows
the way NFStream is configured here (10 s active timeout, integer-millisecond timestamps) was used. With it the unchanged
Week 9 pipeline reproduces the delivered `synthetic_normal_features.csv` and `synthetic_attack_features.csv` exactly (216 rows x 20
columns each) and the baselines. Re-introducing each of the bugs in rows 1 to 4 makes the matching tests fail. This proves the logic, not NFStream compatibility.

## 6. Update after the first real capture
| # | Change | Reason (found in the real CSVs) | Test |
|---|---|---|---|
| 8 | New `features/resegment.py`: TCP frames larger than the MTU frame (default 1514, `--mtu`) are split into the frames a link would carry, with the original timestamp; `validate` uses the same rule in an independent per-frame version | On the Docker bridge, segmentation offload merges TCP writes into frames of up to 64 KB. In all 72 normal windows of the camera `std_packet_size` (1,008-1,684) was above the maximum possible for frames <= 1514 B (about 700), and exfiltration windows had a mean packet size of 4,700-6,600 B. Packet rate was too low and the size statistics too high | `test_vectorised_split_equals_the_plain_function`, `test_only_tcp_is_split_and_mtu_zero_keeps_frames`, `test_merged_frames_give_the_same_features_as_the_real_frames`, `test_without_the_split_merged_frames_distort_the_features`, `test_validator_recount_agrees_with_the_split` |
| 9 | `known_destinations` and the "seen before" set now include every peer the device sent traffic to, also over sessions that were already open when the capture started | Sessions open at capture start have no SYN, so they never counted as "initiated": the MQTT broker 10.77.0.2 was missing from `known_destinations` of all three devices. A later reconnect (with SYN) would have counted as a new destination and lowered a healthy device's trust | `test_known_destinations_include_sessions_open_before_the_capture`, `test_reconnect_to_a_known_broker_is_not_a_new_destination` |

Assumptions of change 8: headers of 66 bytes (Ethernet 14 + IPv4 20 + TCP 32 with timestamps), so a full segment carries 1448 payload bytes;
pieces of one merged frame share its timestamp (they travel back to back, inside the 1 ms resolution); only TCP is split. A lab with
jumbo frames sets `--mtu 9014`; `--mtu 0` disables the correction. The packet count of a window can still differ slightly from a
capture made with offloading off (segment boundaries depend on the sender), but the distortion above is removed.

Unchanged by the real data: the spike rule (for the three real devices 3 x mean is the larger term, so thresholds equal the Week 9
ones and no flag changes), the flags, the ports file, the schema.
