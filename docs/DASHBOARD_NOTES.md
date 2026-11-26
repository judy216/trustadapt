# Dashboard (FR-10) - Week 9: dashboard skeleton

## Run
From the repo root, with the venv active:
```bash
pip install -r requirements.txt     # Windows without WSL: pip install streamlit==1.64.0 pandas==3.0.6 scikit-learn==1.9.1 pytest
                                    # (nfstream has no Windows build; the dashboard does not need it)
PYTHONPATH=src pytest -q            # all tests, incl. tests/test_dashboard.py
streamlit run src/trustadapt/dashboard/app.py   # http://localhost:8501
```
Sidebar -> **Synthetic - attack**: only cam-01 shows alerts (flood, scan, exfil). **Upload files** takes any
feature CSV (+ optional baseline JSON / devices.csv) produced by the features module.

| File (`src/trustadapt/dashboard/`) | Role |
|---|---|
| `app.py` | entry: sidebar data source + page navigation |
| `contract.py` | UI labels/units; columns from `features.schema`, std floors + trust levels from `trust_score.engine` |
| `data.py` | load + check CSV/JSON, device summary, rule-based alerts (pure pandas, tested) |
| `integrations.py` | placeholders: `trust_scores()`, `access_levels()`, `explanations()` |
| `views/` | overview, device, alerts, explain, data_health |
| `samples/` | ~75 KB synthetic feature CSVs + baseline JSON + devices.csv (no real traffic; `data/` is git-ignored) |

## Expected result on the samples
| Page | Synthetic - normal | Synthetic - attack |
|---|---|---|
| Overview | 3 devices, 3 monitoring, 0 alert windows | 20 alert windows |
| Device details (cam-01) | packet rate below ~6 pkt/s | jumps to ~255 pkt/s |
| Alerts | "No alerts" | 20 alerts, all cam-01 |
| Data health | 72 windows per device, 0 gaps | same |

## Decisions taken (review in the PR)
1. **Status:** MONITORING if a complete baseline exists for the device or after 50 windows, otherwise LEARNING.
2. **Week 9 alerts are rule-based:** windows with `traffic_spike_flag`, `unusual_port_flag` or
   `failed_conn_count > 0`. `new_destination_count` is an optional toggle (a fresh capture counts every
   destination as new in its first window).
3. **Severity 0-6** only sorts the alert table (spike +2, failed conn +2, unusual port +1, new destination +1).
   It is not the Trust Score.
4. **Explanations page:** z-score vs baseline with the same std floors as `TrustScoreEngine` (1.0 / 0.2 for
   flags), until SHAP (FR-09) exists.
5. **Samples in the code folder:** small synthetic files only, so the dashboard runs for everyone after a clone.

## Next (Week 10-11)
* Week 10: load the real lab captures (Upload, or replace the files in `samples/` if the team agrees).
* Week 11: fill `trust_scores()` from `AnomalyDetectorRegistry` + `TrustScoreEngine.update()` records
  (`new_score`, `trust_level`, `access_decision`, `contributions`), add a score column + colour per
  `TRUST_LEVELS` (Trusted / Suspicious / Quarantined / Blocked) and a score-over-time chart.
