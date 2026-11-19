# TrustAdapt - Data & Features (Student 1) - Week 9 deliverable

**Task:** *Begin implementation: code network device behavior monitoring (Part 1)* -
*Set up environment + capture sample traffic.* Output = reproducible environment, lab captures,
FR-03 feature CSVs, baseline JSON, documentation - ready for Student 2 (FR-04/05/06).

```
src/trustadapt/   schema.py (19 fields + 12-value ML vector)   extract.py (pcap -> features)
                  validate.py (schema + exact recount)          synth.py (synthetic test traffic)
lab/              docker-compose.yml (isolated lab) + device simulator + devices.csv
scripts/          setup_wsl.sh  capture.sh  run_pipeline.sh
tests/            test_pipeline.py (7 tests)         docs/  data dictionary, capture log, design notes
data/processed/   synthetic_* CSV + baseline JSON (placeholders until real captures exist)
```

## Status
| Part | State |
|---|---|
| Extractor, schema, validator, synthetic generator | Tested: 7/7 tests pass, packet and byte totals match an independent recount exactly |
| Docker lab + `capture.sh` | Written, YAML/shell syntax checked, **not yet run** - first run happens on your machine |

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
   The self-test must end with `7 passed`.

## 2. Try the pipeline without Docker (synthetic traffic)
```bash
ta-synth normal -o data/raw/synthetic_normal.pcap
ta-synth attack -o data/raw/synthetic_attack.pcap
bash scripts/run_pipeline.sh data/raw/synthetic_normal.pcap
bash scripts/run_pipeline.sh data/raw/synthetic_attack.pcap data/processed/synthetic_normal_baseline.json
```

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
- [ ] `pytest` = 7 passed on your machine
- [ ] 1 normal + 1 attack capture in `data/raw` (share via team drive, not git); `validate` prints **PASS** for both
- [ ] `*_features.csv` and `*_baseline.json` committed in `data/processed`
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
