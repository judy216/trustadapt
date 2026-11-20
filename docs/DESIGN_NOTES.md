# Design Notes - extraction layer (Week 9, Part 1)

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
4. `traffic_spike_flag` is the literal rule rate > 3 x baseline mean (a device with baseline mean 0 and any traffic -> 1).
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
* Only IPv4/IPv6 TCP/UDP/ICMP is processed; ARP, IGMP and other protocols are ignored.
* The Docker lab files (`lab/`) are written to match the tested pipeline but could not be executed in the environment
  where the code was developed; the first run on your machine is the real test (see README troubleshooting).
