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
| `tests/test_anomaly.py` | 10 tests on the real captures |

## Results on the real captures (2026-11-19)

| Detector | Attack windows found | False alarms, attack capture | False alarms, normal hold-out | False alarms, whole normal capture |
|---|---|---|---|---|
| Week 9 | 22/23 | 106/196 | 42/66 | 105/216 |
| Isolation Forest only (calibrated) | 18/23 | 2/196 | 0/66 | 1/216 |
| One-Class SVM only (calibrated, comparison) | 23/23 | 4/196 | 1/66 | 1/216 |
| Week 10 (IF + z-score, deciding) | 23/23 | 5/196 | 1/66 | 2/216 |

One-Class SVM (planned in Week 8) is close to the deciding detector. Isolation Forest + z-score stays the deciding
model because SHAP (TreeExplainer) is built on the Isolation Forest; SHAP for One-Class SVM would need the much
slower KernelExplainer. The choice is re-checked on the re-processed captures.

Trust Score (real `TrustScoreEngine`, start 100): normal devices all end Trusted and never drop below 88;
cam-01 in the attack capture reaches Blocked; therm-01 and sensor-01 in the attack capture end Trusted.

## Notes for the team
- SHAP (Student 3) must be re-run: the model now uses `max_samples=32`.
- The flags and `failed_conn_count` stay in the vector. Isolation Forest ignores them (always 0 in the baseline);
  the z part catches them (`source = zscore`), so the penalty split is the explanation for those windows.
- After Student 1 re-processes the captures with `resegment.py`, rebuild every baseline and re-run
  `python -m trustadapt.anomaly.evaluate`. Several of the 5 false alarms on cam-01 in the attack capture are
  likely the oversized `std_packet_size` windows described in `REAL_CAPTURE_FINDINGS.md`.
- Student 3 can leave dry-run once the re-processed captures confirm these numbers.
