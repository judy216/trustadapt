# Capture Log

Fill one row per capture. Only the isolated lab network (`trustadapt0`) is captured - never the home,
university or any network the team does not own. Captures keep **headers only** (snaplen 128).

| # | File (data/raw/) | Date / time | Scenario | Duration | Devices up | Attack commands (time offset) | Packets | Validated (PASS/FAIL) | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | normal_20261119_024550.pcap | 2026-11-19 02:45:50 | normal | 720 s (72 windows) | cam-01, therm-01, sensor-01 | - | not recorded | not recorded | baseline source; TCP frames merged by offload (see `REAL_CAPTURE_FINDINGS.md`); re-process with the Week 10 code |
| 2 | attack_20261119_030826.pcap | 2026-11-19 03:08:26 | attack | 730 s (73 windows) | same | flood @430 s, scan @530 s, exfil @640 s (offsets read from the CSV) | not recorded | not recorded | use baseline from #1; re-process with the Week 10 code |

## Scenario timeline for the attack capture (720 s)
| Offset | Action (second terminal) | Expected feature reaction on cam-01 |
|---|---|---|
| 0-300 s | nothing (normal behaviour) | no flags |
| 300 s | `docker compose exec cam-01 python device.py --attack flood --seconds 60` | traffic_spike_flag = 1, unusual_port_flag = 1 (port 9999), packet_rate x50 |
| 400 s | `docker compose exec cam-01 python device.py --attack scan --seconds 30` | failed_conn_count rises, unusual_port_flag = 1 |
| 500 s | `docker compose exec cam-01 python device.py --attack exfil --seconds 60` | new_destination_count > 0 (8 hosts), unusual_port_flag = 1, bytes_sent_rate high |

## What the first real attack capture showed (cam-01, offsets from the first window)
| Offset | Observed |
|---|---|
| 0-420 s | no flags |
| 430-490 s | UDP flood to port 9999: `traffic_spike_flag` = 1 and `unusual_port_flag` = 1, packet rate up to 241 pkt/s |
| 530-560 s | scan: `unusual_port_flag` = 1 from 530 s, `traffic_spike_flag` = 1 from 540 s (the first window, 13.6 pkt/s, is below the threshold of 15.6), up to 201 connections per window; `failed_conn_count` is above 0 from 530 s to 610 s (peak 592) because it is a rolling 60 s count |
| 640-700 s | exfiltration to port 8080: 8 new destinations in the first window, `unusual_port_flag` = 1 until 700 s, `traffic_spike_flag` = 1 until 690 s; the mean packet size is 4,700-6,600 B because offload merged the frames (corrected by re-segmentation) |
| other devices | no flags in the whole attack capture |
The operator started the attacks later than the planned 300 / 400 / 500 s; the table above is what the data shows.
