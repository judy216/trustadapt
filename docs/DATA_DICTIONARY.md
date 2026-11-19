# Data Dictionary - feature table (FR-03)

One row per **device x 10 s window** (`window_start` = epoch seconds, multiple of 10).
Column order = Week 8 report, Section 4. 12 columns form the ML vector (`ML_FEATURES` in `schema.py`).
Windows with no traffic are still emitted (all rates/counts/sizes/activity = 0), so the rhythm is steady.

| Column | Type | In ML vector | Definition (as implemented) |
|---|---|---|---|
| window_start | float | no | Start of the 10 s window, epoch seconds (metadata) |
| device_mac | str | no | Device MAC (key of the devices table, FR-01), lower-case |
| ip_src | str | no | Device IP in the dominant flow of the window (empty if no traffic) |
| ip_dst | str | no | Peer IP in the dominant flow |
| port_src | int | no | Device port in the dominant flow (0 if no traffic) |
| port_dst | int | no | Peer port in the dominant flow |
| protocol_type | enum | no | TCP / UDP / ICMP of the dominant flow (empty if no traffic) |
| app_protocol | enum | no | MQTT / HTTP / CoAP / OTHER, inferred **from port_dst only** (nDPI off) |
| packet_rate_10s | float | yes | (packets sent + received by the device in the window) / 10 |
| bytes_sent_rate | float | yes | Link-layer bytes **sent by the device** in the window / 10 |
| connection_count | int | yes | Connections **initiated** by the device in the window (TCP: SYN seen; UDP/ICMP: new flow) |
| new_destination_count | int | yes | Destination IPs of initiated connections never contacted before by this device |
| activity_time | float | yes | Distinct seconds of the window with >= 1 packet (0-10) |
| mean_packet_size | float | yes | Mean frame length (bytes) of all packets of the device in the window |
| std_packet_size | float | yes | Population std of frame length (0 if < 2 packets) |
| mean_inter_arrival | float | yes | Mean gap (ms) between consecutive packets of the device in the window (0 if < 2 packets) |
| std_inter_arrival | float | yes | Population std of those gaps (ms) |
| traffic_spike_flag | 0/1 | yes | 1 if packet_rate_10s > 3 x baseline mean; 0 during LEARNING |
| unusual_port_flag | 0/1 | yes | 1 if the device sent traffic in the window to a destination port outside its baseline whitelist; 0 during LEARNING |
| failed_conn_count | int | yes | TCP connections initiated in the **last 60 s** (this + previous 5 windows) with SYN but no SYN-ACK |

## baseline JSON (per device) - for Student 2 (FR-04 / FR-06)

`complete`, `windows_used` (50), `mean_packet_rate`, `port_whitelist`, `known_destinations`,
`ml_mean` and `ml_std` (mean / population std of the 12 ML values over the baseline windows).
Features with `ml_std == 0` (e.g. new_destination_count) need the zero-std rule from the Trust Score design.

## Units and conventions
* Sizes are **link-layer frame lengths** (same as Wireshark `frame.len`). Not payload size.
* Inter-arrival times are in **milliseconds**; rates are per second.
* LEARNING = first 50 windows of a device (about 8 min). Both flags are 0 there. When a baseline JSON is
  passed with `--baseline-from`, the LEARNING state is skipped and flags are computed from window 1.
