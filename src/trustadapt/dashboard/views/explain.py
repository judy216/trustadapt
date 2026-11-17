import pandas as pd
import streamlit as st

from trustadapt.dashboard import integrations
from trustadapt.dashboard.contract import ML_FEATURES, label, std_floor
from trustadapt.dashboard.views.common import device_picker, pending, require_dataset

ds = require_dataset()
st.header("Explanations")
pending("SHAP explanations (FR-09, Week 12)", "Student 3")
st.caption("Until SHAP is ready this page compares one window with the device baseline. "
           "It is a deviation view, not a model explanation.")

mac = device_picker(ds, key="explain_device")
g = ds.features[ds.features["device_mac"] == mac].reset_index(drop=True)
idx = st.select_slider("Window", options=list(g.index), value=int(g["packet_rate_10s"].idxmax()),
                       format_func=lambda i: g.loc[i, "time"].strftime("%H:%M:%S"))
row = g.loc[idx]

shap = integrations.explanations(ds, mac, float(row["window_start"]))
if shap is not None:
    st.dataframe(shap, hide_index=True)
    st.stop()

base = ds.baseline.get(mac)
if not base:
    st.warning("No baseline for this device - load a baseline JSON to compare.")
    st.stop()

mean, std = base.get("ml_mean", {}), base.get("ml_std", {})
rows = []
for feat in ML_FEATURES:
    m, s = mean.get(feat), std.get(feat)
    s = max(s, std_floor(feat)) if s is not None else None  # same floor as Student 2 -> same z-scores
    z = (row[feat] - m) / s if m is not None and s else None
    rows.append({"feature": label(feat), "value": float(row[feat]), "baseline mean": m,
                 "baseline std (floored)": s, "z-score": z})
table = pd.DataFrame(rows)
st.dataframe(
    table,
    hide_index=True,
    column_config={
        "value": st.column_config.NumberColumn(format="%.2f"),
        "baseline mean": st.column_config.NumberColumn(format="%.2f"),
        "baseline std (floored)": st.column_config.NumberColumn(format="%.2f"),
        "z-score": st.column_config.NumberColumn(format="%+.1f", help="(value - mean) / max(std, floor); floor 1.0, or 0.2 for the two flags"),
    },
)
