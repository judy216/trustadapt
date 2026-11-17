"""Dashboard view of the FR-03 data contract.

Column names, ML order and std floors come from the team's own modules (features.schema, trust_score.engine),
so the dashboard always matches them; this file only adds the UI labels and units.
"""
from __future__ import annotations

from dataclasses import fields

from trustadapt.features.schema import IoTDeviceFeatureVector
from trustadapt.trust_score.engine import FLAG_FIELDS, MIN_STD, MIN_STD_FLAG, TRUST_LEVELS  # noqa: F401

FEATURE_COLUMNS = [f.name for f in fields(IoTDeviceFeatureVector)]   # window_start + 19 fields
ML_FEATURES = IoTDeviceFeatureVector.ML_FEATURES
WINDOW_S = 10
BASELINE_WINDOWS = 50        # FR-04 learning period
DISPLAY_TZ = "Asia/Riyadh"


def std_floor(feature: str) -> float:
    """Same floor as TrustScoreEngine.z_scores, so dashboard z-scores match the Trust Score."""
    return MIN_STD_FLAG if feature in FLAG_FIELDS else MIN_STD


# Human-readable labels + units shown in the UI (definitions: Student 1 DATA_DICTIONARY.md)
FEATURE_LABELS = {
    "packet_rate_10s": ("Packet rate", "pkt/s"),
    "bytes_sent_rate": ("Bytes sent rate", "B/s"),
    "connection_count": ("New connections", "per 10 s"),
    "new_destination_count": ("New destinations", "per 10 s"),
    "activity_time": ("Active time", "s of 10"),
    "mean_packet_size": ("Mean packet size", "bytes"),
    "std_packet_size": ("Packet size std", "bytes"),
    "mean_inter_arrival": ("Mean inter-arrival", "ms"),
    "std_inter_arrival": ("Inter-arrival std", "ms"),
    "traffic_spike_flag": ("Traffic spike", "0/1"),
    "unusual_port_flag": ("Unusual port", "0/1"),
    "failed_conn_count": ("Failed connections", "last 60 s"),
}


def label(feature: str) -> str:
    name, unit = FEATURE_LABELS.get(feature, (feature, ""))
    return f"{name} ({unit})" if unit else name
