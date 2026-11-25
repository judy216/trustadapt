# First real capture - findings

**What was analysed:** `normal_20261119_024550_features.csv` (3 devices x 72 windows), `attack_20261119_030826_features.csv` (3 x 73) and
`normal_20261119_024550_baseline.json`. The pcaps were not available to the analysis, so nothing could be re-extracted yet; the
fixes below are tested on synthetic traffic and must be applied by re-running the pipeline on the pcaps (README section 6).

## What was already correct
- Both CSVs follow the schema (20 columns, no missing values, contiguous 10 s windows, three devices). The baseline JSON is complete
  (`complete: true`, 50 windows) for every device.
- Normal capture: both flags are 0 in every window.
- Attack capture: only cam-01 is flagged; flood, scan and exfiltration each show the reactions listed in `CAPTURE_LOG.md`; the other devices are not flagged.
- The spike flag does not change with the Week 10 rule: for the three real devices `3 x mean` is larger than `mean + 3 x std`
  (15.6 vs 7.1, 2.63 vs 2.60, 1.86 vs 1.27), so thresholds are the Week 9 ones.

## Problems found and what changed
| # | Problem | Evidence | Change |
|---|---|---|---|
| 1 | **TCP frames merged by segmentation offload** on the Docker bridge | For frames of at most 1514 B the standard deviation cannot exceed sqrt(mean x (1514 - mean)). The camera's `std_packet_size` was 1,008-1,684 against a limit of about 700 in all 72 normal windows (and in 66 of 73 attack windows); the other two devices never exceed the limit. Exfiltration windows had a mean packet size of 4,700-6,600 B. The lab code makes the camera post 4.2-7.0 KB at a time, which is one frame after merging and 3-5 frames on a link. The four non-attack windows that the baseline model wrongly scored as unusual on the attack capture all had a large `std_packet_size` (1,080-1,430) | `resegment.py`, `--mtu` (default 1514): oversized TCP frames are split as a link would carry them; the validator recounts independently with the same rule |
| 2 | **`known_destinations` missed open sessions** | The MQTT broker 10.77.0.2 was absent from `known_destinations` of all three devices (cam-01 and therm-01 list only the cloud 10.77.0.100, sensor-01 lists nothing and has `connection_count` 0): their MQTT sessions were already open when the capture started, so no SYN was seen | Peers the device sent traffic to count as known whether or not a SYN was seen |
| 3 | Planned and actual attack times differ | The attacks ran at 430 / 530 / 640 s, not 300 / 400 / 500 s | `CAPTURE_LOG.md` records what the data shows |

## What to expect after re-processing (not yet measured)
- cam-01: `packet_rate_10s` higher and `mean_packet_size` lower during normal posts, `std_packet_size` below about 700, exfiltration windows
  with a packet rate in the hundreds instead of about 40; flags and `new_destination_count` unchanged.
- Baseline JSON: the broker appears in `known_destinations`.
- Anything computed from the old CSVs (model baselines, thresholds) has to be rebuilt from the new ones.

## Still open
- Offloading itself can be switched off before the capture for exact frame timing (`ethtool -K ... tso off gso off gro off`); untested.
- TCP reset and teardown handling, speed on large captures, and the raw NFStream flows of a real capture are still unchecked.
