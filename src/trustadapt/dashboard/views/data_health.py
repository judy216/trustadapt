import streamlit as st

from trustadapt.dashboard.contract import WINDOW_S
from trustadapt.dashboard.views.common import require_dataset

ds = require_dataset()
f = ds.features
st.header("Data health")
st.caption("Quick checks on the loaded files. Full validation is Student 1's `ta-validate`.")

st.success("Columns match the FR-03 schema (checked on load).")

rows = []
for mac, g in f.groupby("device_mac"):
    steps = g["window_start"].diff().dropna()
    rows.append({
        "device": g["device_name"].iloc[0],
        "mac": mac,
        "windows": len(g),
        "gaps": int((steps != WINDOW_S).sum()),
        "silent windows": int((g["packet_rate_10s"] == 0).sum()),
        "in baseline JSON": mac in ds.baseline,
    })
st.dataframe(rows, hide_index=True,
             column_config={"gaps": st.column_config.NumberColumn(help="Steps between windows that are not 10 s")})

unknown = sorted(set(f["device_mac"]) - set(ds.devices["mac"]))
if unknown:
    st.warning(f"MACs not in devices.csv (shown by MAC): {', '.join(unknown)}")

c1, c2, c3 = st.columns(3)
c1.metric("Rows", len(f))
c2.metric("From", f["time"].min().strftime("%Y-%m-%d %H:%M"))
c3.metric("To", f["time"].max().strftime("%Y-%m-%d %H:%M"))
