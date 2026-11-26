# FR-05 Anomaly detection: Week 10 calibration (Student 2)

Agreed with the team: `baseline/baseline_profile.py` is the only place a model is trained; the vector stays
12 values in `ML_FEATURES` order. `anomaly/detector.py` reads the `BaselineProfile` and computes the severity.

## Changes

| File | Change |
|---|---|
| `baseline/baseline_profile.py` | Per-feature std floors (`ABS_FLOOR`, `REL_FLOOR`) instead of a flat 1.0. Out-of-fold thresholds (`if_threshold`, `if_spread`, `z_threshold`): 5 folds, a model trained on 4 scores the 5th. `max_samples=32` so fold and final models share one score scale. Older saved profiles are refused (rebuild). Data check (Tukey fences) unchanged |
| `anomaly/detector.py` | No own model. A = max(A_iforest, A_z); 0 below the thresholds, 0.3 just above them (engine rule unchanged); no penalty if no feature has \|z\| >= 2 |
| `trust_score/engine.py` | z-scores use the same floors as `baseline_profile.py` |
| `anomaly/evaluate.py` | Week 9 integration check, repeated with the real engine; One-Class SVM comparison |
| `tests/test_anomaly.py` | 10 tests on the real (re-processed) captures |

## Results on the re-processed captures (2026-11-19, PR #11: offload correction, broker in known_destinations)

Baselines and models are rebuilt from the new CSVs every time `evaluate.py` runs (first 50 windows of each device in the
normal capture). The new `std_packet_size` / `mean_packet_size` values are therefore already in the profiles below.
Re-run with `PYTHONPATH=src python -m trustadapt.anomaly.evaluate`; all 10 tests in `tests/test_anomaly.py` pass.

| Detector | Attack windows found | False alarms, attack capture | False alarms, normal hold-out | False alarms, whole normal capture |
|---|---|---|---|---|
| Week 9 | 22/23 | 103/196 | 42/66 | 105/216 |
| Isolation Forest only (calibrated) | 17/23 | 2/196 | 0/66 | 1/216 |
| One-Class SVM only (calibrated, comparison) | 23/23 | 4/196 | 1/66 | 1/216 |
| Week 10 (IF + z-score, deciding) | 23/23 | 5/196 | 1/66 | 2/216 |

The numbers in the first version of this file (106/196 and 18/23) came from the CSVs before re-processing.

Out-of-fold thresholds: cam-01 `if_threshold` -0.1509, therm-01 -0.1604, sensor-01 -0.1422; `z_threshold` 4.00 for
all three (the floor `Z_ALARM_MIN`).

Trust Score (real `TrustScoreEngine`, start 100): normal devices all end Trusted and never drop below 90;
cam-01 in the attack capture reaches Blocked (0) in the flood; therm-01 and sensor-01 in the attack capture end Trusted
(lowest 88.6).

### Remaining false alarms (7 windows)

| Capture | Device | t (s) | Source | Feature with largest \|z\| |
|---|---|---|---|---|
| attack | cam-01 | 0 | zscore | mean_inter_arrival (z = -9.3) |
| attack | sensor-01 | 0 | zscore | std_inter_arrival (z = -5.5) |
| attack | cam-01 | 80, 180 | iforest | activity_time (z = 2.8) |
| attack | cam-01 | 270 | zscore | activity_time (z = 4.6) |
| normal | cam-01 | 620 | zscore | mean_inter_arrival (z = 5.2) |
| normal | therm-01 | 220 | iforest | std_inter_arrival (z = -2.4), inside the baseline windows |

The oversized `std_packet_size` windows are gone after re-processing, so they no longer cause false alarms.
Two of the false alarms are the first window of the attack capture (t = 0), which is likely a partial window at the
start of the capture: worth checking with Student 1.

## Answers to the review questions

**1. Rebuild after the new CSVs.** Done: the baselines are built from the re-processed CSVs (table above). Saved
profiles from before Week 10 are refused by `BaselineProfile.load()` ("older format; rebuild it").

**2. Which Isolation Forest is final?** `baseline/baseline_profile.py`. Since PR #10, `anomaly/detector.py` has no
model of its own: it loads the `BaselineProfile` and uses `profile.model` to compute the severity. SHAP on
`baseline_profile` is the right choice; it only has to be re-run because the model now uses `max_samples=32`.

**3. Flags and `failed_conn_count` are always 0 in the baseline.** Proposal: keep the 12-value vector as it is.
Isolation Forest only (same out-of-fold rule) gives the same result with 12 and with 9 inputs: 17/23 attack windows
found with both; false alarms 2/196 and 1/216 with 12 inputs, 1/196 and 2/216 with 9. So removing them changes nothing
for the model, but would change the FR-03 contract used by `schema.py`, `engine.py` and the dashboard. The three
features are already covered by a rule: the z-score part of the detector (flag z = 5, `failed_conn_count` z up to
1184 in the scan), which marks these windows with `source = zscore`. For SHAP: these three always get a SHAP value
of 0 from Isolation Forest, so for `source = zscore` windows the explanation should use the engine's penalty split
(`contributions`) instead of SHAP. To be agreed by the team.

## Notes for the team
- SHAP (Student 3) must be re-run on `profile.model` (now `max_samples=32`, re-processed data).
- Student 3 can leave dry-run: the numbers above are on the re-processed captures.
