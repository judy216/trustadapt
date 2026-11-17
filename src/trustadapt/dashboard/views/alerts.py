import streamlit as st

from trustadapt.dashboard.data import alerts
from trustadapt.dashboard.views.common import require_dataset

ds = require_dataset()
st.header("Alerts")
st.caption("Week 9: rule-based, from the flags in the feature CSV. "
           "The anomaly model (FR-05, Student 2) will add model-based alerts.")

c1, c2 = st.columns([2, 1])
with c1:
    names = sorted(ds.features["device_name"].unique())
    pick = st.multiselect("Devices", names, default=names)
with c2:
    with_new_dst = st.toggle("Include new destinations", value=False,
                             help="Off by default: without a baseline the first window counts every "
                                  "destination as new.")

al = alerts(ds, include_new_destinations=with_new_dst)
al = al[al["device_name"].isin(pick)]

if al.empty:
    st.success("No alerts for the selected devices.")
    st.stop()

st.metric("Alert windows", len(al))
st.bar_chart(al.groupby("device_name").size().rename("alert windows"), horizontal=True, height=180)
st.dataframe(
    al,
    hide_index=True,
    column_config={
        "time": st.column_config.DatetimeColumn("Time", format="HH:mm:ss"),
        "device_name": "Device",
        "device_mac": "MAC",
        "severity": st.column_config.ProgressColumn("Severity", min_value=0, max_value=6, format="%d"),
        "reasons": st.column_config.TextColumn("Why", width="large"),
        "packet_rate_10s": st.column_config.NumberColumn("pkt/s", format="%.1f"),
        "bytes_sent_rate": st.column_config.NumberColumn("B/s sent", format="%.0f"),
        "port_dst": "Dst port",
        "ip_dst": "Dst IP",
    },
)
