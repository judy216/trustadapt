"""Plug points for the other components. Week 9: placeholders only.

Each function returns None until the owning student delivers an output; the pages already show a
"pending" state for None, so wiring in the real output later changes only this file.
Agree the formats below with the team (see docs/WEEK9_NOTES.md, "Interfaces to agree").
"""
from __future__ import annotations

import pandas as pd

from .data import Dataset


def trust_scores(ds: Dataset) -> pd.DataFrame | None:
    """FR-05/FR-06 (anomaly/detector.py + trust_score/engine.py). Week 11: one row per TrustScoreEngine.update()
    record + window_start: device_mac, window_start, new_score (0-100), anomaly_score, trust_level, contributions."""
    return None


def access_levels(ds: Dataset) -> pd.DataFrame | None:
    """FR-07/FR-08. Levels already fixed in engine.TRUST_LEVELS (Trusted / Suspicious / Quarantined / Blocked);
    proposed: device_mac, window_start, trust_level, access_decision, enforced (0/1)."""
    return None


def explanations(ds: Dataset, device_mac: str, window_start: float) -> pd.DataFrame | None:
    """FR-09 (Week 12). Proposed: feature, value, z, points_lost (engine `contributions`), shap_value."""
    return None
