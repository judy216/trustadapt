# SHAP Groundwork (FR-09) - Week 10

**Owner:** Student 3 (Explainability & Access)
**Code:** `src/trustadapt/explain/shap_explainer.py` - **Tests:** `tests/test_explain.py`

## 1. What was done
* One `shap.TreeExplainer` per device, built on `profile.model` of that device's `BaselineProfile` (FR-04), the only
  Isolation Forest in the system since PR #10. Built once when the baseline is ready, reused every 10 s window
  (`ShapExplainerRegistry`).
* Every window gets 12 SHAP values in `ML_FEATURES` order, the same order the model uses.
* Each explanation is checked against the model: `base_value + sum(SHAP)` reproduces `decision_function` exactly
  (error about 3e-16 on the lab captures).
* `to_points(penalty)` already returns `{feature: points}` in the same format as the engine's `contributions`,
  so Week 12 can swap z-score blame for SHAP blame without changing the dashboard.

## 2. How to read the numbers
SHAP on an Isolation Forest explains the **average path length**, not the score directly:

    h(x) = base_value + sum(shap_i)
    decision_function(x) = -2^(-h(x) / c(n)) - offset        (n = model.max_samples_ = 32)

* `base_value` = expected path length of a normal window (about 6.2-6.6 in the lab).
* **Negative SHAP = the feature made the window easier to isolate = pushed it toward anomalous.** Only these are blamed.
* `anomaly_share` = each negative value divided by their total, so the shares sum to 100%.

## 3. Results on the re-processed captures (2026-11-19, after PR #11 / #12)
Baseline = first 50 windows of the normal capture, explained = attack capture. "Unusual" = decision score below the
baseline's 5th percentile.

| Device | Windows | Unusual | Additivity error | Time / window | SHAP top-1 within z-score top-3 |
|---|---|---|---|---|---|
| cam-01 | 73 | 25 | 3e-16 | 0.2 ms | 6 / 25 |
| therm-01 | 73 | 0 | 3e-16 | 0.2 ms | - |
| sensor-01 | 73 | 1 | 3e-16 | 0.2 ms | 0 / 1 |

Speed is not a concern (well under 1 ms per window). After re-processing, `std_packet_size` no longer leads the
cam-01 explanations; on the most unusual window the top three are `activity_time` 21%, `new_destination_count` 16%,
`packet_rate_10s` 14%.

## 4. Findings for the team
**G1 - The Isolation Forest cannot see features that never change in the baseline.**
`traffic_spike_flag`, `unusual_port_flag` and `failed_conn_count` are always 0 in the 50 baseline windows, so no tree
ever splits on them and their SHAP value is always 0. In the attack capture cam-01 reaches `failed_conn_count = 592`
and has a flag set in 23 windows. For sensor-01 `connection_count` and `new_destination_count` are also constant.
Covered since PR #10: the z-score part of the detector catches these windows (`source = zscore`).

**G2 - SHAP and z-scores blame different features on cam-01.** On its 25 unusual windows the z-scores blame
`bytes_sent_rate` (14), `failed_conn_count` (6) and `activity_time` (4); SHAP blames `activity_time` (21) and
`connection_count` (3). The z-score says "furthest from the average", SHAP says "what the model actually used".
Both are correct answers to different questions.

## 5. Plan for Week 12 (FR-09), aligned with `ANOMALY_WEEK10.md`
The explanation follows the detector's `source`, so no strong signal is lost:
1. **`source = zscore`**: use the engine's penalty split (`contributions`) and fixed rule reasons for the three
   constant features ("connected to a port never seen before", "592 failed connections in 60 s").
2. **`source = iforest`**: SHAP, top 3 features by `anomaly_share`, shown as % in the dashboard.
3. Keep the z-score value next to each feature so the text can say *how far* it moved ("6x the normal rate").

## 6. Open questions
1. Student 4: is a top-3 list with percentages enough for the dashboard, or do we want a bar chart (SHAP waterfall)?
2. Team: for `source = iforest` windows, penalty points by SHAP share (`to_points`) or keep the z-score split in the engine?

## 7. How to run
    pip install -r requirements.txt
    python -m pytest tests/test_explain.py
    python -m trustadapt.explain.shap_explainer data/processed/normal_20261119_024550_features.csv \
        data/processed/attack_20261119_030826_features.csv
