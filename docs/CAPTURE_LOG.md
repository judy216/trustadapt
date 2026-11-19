# Capture Log

Fill one row per capture. Only the isolated lab network (`trustadapt0`) is captured - never the home,
university or any network the team does not own. Captures keep **headers only** (snaplen 128).

| # | File (data/raw/) | Date / time | Scenario | Duration | Devices up | Attack commands (time offset) | Packets | Validated (PASS/FAIL) | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | normal_YYYYMMDD_HHMMSS.pcap | | normal | 720 s | cam-01, therm-01, sensor-01 | - | | | baseline source |
| 2 | attack_YYYYMMDD_HHMMSS.pcap | | attack | 720 s | same | flood @300 s, scan @400 s, exfil @500 s | | | use baseline from #1 |

## Scenario timeline for the attack capture (720 s)
| Offset | Action (second terminal) | Expected feature reaction on cam-01 |
|---|---|---|
| 0-300 s | nothing (normal behaviour) | no flags |
| 300 s | `docker compose exec cam-01 python device.py --attack flood --seconds 60` | traffic_spike_flag = 1, unusual_port_flag = 1 (port 9999), packet_rate x50 |
| 400 s | `docker compose exec cam-01 python device.py --attack scan --seconds 30` | failed_conn_count rises, unusual_port_flag = 1 |
| 500 s | `docker compose exec cam-01 python device.py --attack exfil --seconds 60` | new_destination_count > 0 (8 hosts), unusual_port_flag = 1, bytes_sent_rate high |
