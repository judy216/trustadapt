# TrustAdapt - Data & Features (Student 1) - Week 9 deliverable, finalized in Week 10

**Tasks:** Week 9 *Set up environment + capture sample traffic*; Week 10 *Finalize feature extraction pipeline*.
Output = reproducible environment, lab captures, FR-03 feature CSVs, baseline JSON, a ports file and an optional
SQLite store, documentation - ready for the ML / anomaly-detection work (FR-04/05/06).

```
src/trustadapt/features/   schema.py (19 fields + 12-value ML vector)   extract.py (pcap -> features, baseline, ports file)
                           validate.py (schema + exact recount + frame check)   synth.py (synthetic test traffic)
                           resegment.py (undo TCP offload merging)
src/trustadapt/store/      feature_vectors.py (features -> SQLite table feature_vectors; to be merged into the shared store)
lab/              docker-compose.yml (isolated lab) + device simulator + devices.csv
scripts/          setup_wsl.sh  capture.sh  run_pipeline.sh
tests/            test_pipeline.py (7)  test_finalization.py (16)  test_real_capture.py (15)  fixtures/ (2 small synthetic reference CSVs)
docs/             DATA_README.md (this file)  DATA_DICTIONARY.md  CAPTURE_LOG.md  DESIGN_NOTES.md  REAL_CAPTURE_FINDINGS.md
data/processed/   feature CSVs, baseline JSON and ports file of the real captures (re-run them after Week 10, see section 6)
```

## Status
| Part | State |
|---|---|
| Extractor, schema, validator, synthetic generator | Tested: 7/7 original tests pass, packet and byte totals match an independent recount exactly |
| Week 10 finalization (`docs/DESIGN_NOTES.md` sections 5 and 6) | 31 new tests; with the 7 original ones, 38/38 pass (the repo's 4 `test_core.py` tests pass too) against a stand-in for NFStream and scapy, which reproduces the Week 9 synthetic feature CSVs (`tests/fixtures`) exactly. Run `pytest` on your machine for the real result |
| First real capture (`docs/REAL_CAPTURE_FINDINGS.md`) | The delivered CSVs and baseline JSON were analysed (pcaps were not available): flags and attack reactions are correct. It exposed **TCP frames merged by segmentation offload** and a baseline that missed open sessions; both are fixed in this version, but **the pcaps must be re-processed** (section 6) |
| Docker lab + `capture.sh` | Ran: one normal and one attack capture exist. Compose, MAC addresses and the capture script worked |

## 1. Setup on Windows (WSL2) - about 30 min
NFStream (the flow engine chosen in the report) has no Windows build, and the GP template fixes Ubuntu 24.04 + Python 3.12, so work inside WSL2:
1. PowerShell as Administrator: `wsl --install -d Ubuntu-24.04`, restart, create the Linux user.
2. Install **Docker Desktop** -> Settings -> Resources -> WSL integration -> enable *Ubuntu-24.04*.
3. In the Ubuntu terminal, in your project folder (use the Linux home `~/`, not `/mnt/c`, for speed):
   ```bash
   git clone <your-repo-url> trustadapt && cd trustadapt     # or copy this folder here
   bash scripts/setup_wsl.sh                                  # venv + install + self-test
   source .venv/bin/activate
   ```
   The self-test must end without failures (the data & features tests are 38 of them).

## 2. Try the pipeline without Docker (synthetic traffic)
```bash
ta-synth normal -o data/raw/synthetic_normal.pcap
ta-synth attack -o data/raw/synthetic_attack.pcap
bash scripts/run_pipeline.sh data/raw/synthetic_normal.pcap
bash scripts/run_pipeline.sh data/raw/synthetic_attack.pcap data/processed/synthetic_normal_baseline.json
```
Each run writes `<stem>_features.csv`, `<stem>_baseline.json` (normal captures) and `<stem>_ports.csv`.
To also fill the shared SQLite store: `TA_DB=data/trustadapt.db bash scripts/run_pipeline.sh <pcap> [baseline.json]`
(or `--db` on `ta-extract`). Writing the same capture again replaces rows, never duplicates them.
TCP frames larger than the MTU (merged by offload on the capture interface) are split into link-sized frames by default;
`TA_MTU=0` keeps frames as captured, `TA_MTU=9014` suits a jumbo-frame lab. Extract and validate always use the same value.

## 3. Real lab captures (Docker)
```bash
cd lab && docker compose up -d --build && cd ..       # 3 devices + broker + cloud + 8 extra hosts
docker compose -f lab/docker-compose.yml ps           # all "running"
```
Wait 1 minute, then **normal capture** (12 min):
```bash
bash scripts/capture.sh normal 720
bash scripts/run_pipeline.sh data/raw/normal_<stamp>.pcap          # makes <stamp>_baseline.json
```
**Attack capture** - terminal 1: `bash scripts/capture.sh attack 720`; terminal 2, at the offsets in `docs/CAPTURE_LOG.md`:
```bash
docker compose -f lab/docker-compose.yml exec cam-01 python device.py --attack flood --seconds 60   # at 300 s
docker compose -f lab/docker-compose.yml exec cam-01 python device.py --attack scan  --seconds 30   # at 400 s
docker compose -f lab/docker-compose.yml exec cam-01 python device.py --attack exfil --seconds 60   # at 500 s
bash scripts/run_pipeline.sh data/raw/attack_<stamp>.pcap data/processed/normal_<stamp>_baseline.json
```
Stop the lab: `docker compose -f lab/docker-compose.yml down`. Fill `docs/CAPTURE_LOG.md` for every capture.

## 4. Done criteria (hand-off to Student 2)
- [ ] `pytest` passes on your machine (38 data & features tests)
- [ ] 1 normal + 1 attack capture in `data/raw` (share via team drive, not git); `validate` prints **PASS** for both
- [ ] `*_features.csv`, `*_baseline.json` and `*_ports.csv` committed in `data/processed`
- [ ] Attack CSV shows the reactions listed in `docs/CAPTURE_LOG.md` (flood / scan / exfil on cam-01 only)
- [ ] Capture log filled, `docs/DESIGN_NOTES.md` deviations agreed with the team

## 5. Troubleshooting
| Symptom | Fix |
|---|---|
| `tcpdump: trustadapt0: No such device` | lab not up (`docker compose up -d`) or the bridge name differs: `docker network inspect trustadapt_lab` |
| Capture file is empty | `docker compose ps`; devices must be running; try `docker compose logs cam-01` |
| `pip install nfstream` fails | you are on native Windows - use the WSL2 Ubuntu terminal |
| `validate` says FAIL on totals | send me the printed lines + `ta-extract -v` output |
| Few windows (< 50) | normal capture shorter than 8.5 min: baseline `complete: false`, flags stay 0 |
| `ERROR: no requested device appears in the capture. MACs that opened connections ...` (exit code 2) | the MACs in `lab/devices.csv` are not the ones on the wire (Docker may ignore `mac_address`). Copy the MACs the message lists into `lab/devices.csv` |
| `WARNING: frames larger than a normal Ethernet frame` from `validate`, or `re-segmented N TCP frames` from `ta-extract` | expected on the Docker bridge: the capture interface merged TCP packets (segmentation offload). `ta-extract` splits them into link-sized frames, so the features are corrected; only the timing inside a burst is approximate. For exact frames you can try `ethtool -K <iface> tso off gso off gro off` on the lab bridge and its container links; **untested** |

## 6. First real capture - status and what to re-check
The first real captures (`normal_20261119_024550`, `attack_20261119_030826`) were analysed from their CSVs; the findings are in
`docs/REAL_CAPTURE_FINDINGS.md`. Two problems were fixed in the code, so **the existing pcaps must be processed again** with this version
and the old CSV/JSON replaced:
```bash
bash scripts/run_pipeline.sh data/raw/normal_20261119_024550.pcap
bash scripts/run_pipeline.sh data/raw/attack_20261119_030826.pcap data/processed/normal_20261119_024550_baseline.json
```
- [ ] `ta-extract` logs `re-segmented N TCP frames ...` (expected: that is the offload correction working)
- [ ] `ta-validate` prints PASS (the frame-size WARNING is expected and handled)
- [ ] New normal CSV: in every window `std_packet_size` <= sqrt(mean x (1514 - mean)) (before: the camera had a std of 1,000-1,700 with a mean of 380-560, which is impossible) and `mean_packet_size` <= 1514
- [ ] New baseline JSON: `known_destinations` of every device contains the MQTT broker `10.77.0.2` (before: missing for all three)
- [ ] Attack CSV still flags only cam-01 with the reactions in `docs/CAPTURE_LOG.md`; the other devices stay unflagged
- [ ] Send the `ta-validate` output and the raw NFStream flows of the normal capture (`extract_flows(pcap).to_csv(...)`) so the windowing can be re-tested offline
- [ ] Hand the re-run CSVs to the ML work: numbers such as packet rate and packet size change, so anything computed from the old CSVs (baselines, thresholds) must be recomputed
