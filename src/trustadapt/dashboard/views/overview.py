import streamlit as st

from trustadapt.dashboard import integrations
from trustadapt.dashboard.data import alerts, device_summary
from trustadapt.dashboard.views.common import pending, require_dataset

ds = require_dataset()
st.header("Overview")
st.caption(f"Source: {ds.source}")

summary = device_summary(ds)
al = alerts(ds)
f = ds.features

c1, c2, c3, c4 = st.columns(4)
c1.metric("Devices", len(summary))
c2.metric("Monitoring", int((summary["status"] == "MONITORING").sum()),
          help="Devices with a complete baseline (FR-04). Others are still LEARNING.")
c3.metric("Alert windows", len(al), help="10 s windows with a spike, unusual-port or failed-connection flag")
c4.metric("Time covered", f"{(f['window_start'].max() - f['window_start'].min() + 10) / 60:.0f} min")

scores = integrations.trust_scores(ds)
if scores is None:
    pending("Trust Score (FR-06)", "Student 2")
if integrations.access_levels(ds) is None:
    pending("Access level (FR-07)", "Student 3")

st.subheader("Devices")
st.dataframe(
    summary,
    hide_index=True,
    column_config={
        "device_name": "Device",
        "device_type": "Type",
        "device_mac": "MAC",
        "ip": "IP",
        "status": "Status",
        "windows": st.column_config.NumberColumn("Windows", help="10 s windows in this capture"),
        "last_seen": st.column_config.DatetimeColumn("Last traffic", format="HH:mm:ss"),
        "last_packet_rate": st.column_config.NumberColumn("Packet rate now", format="%.1f pkt/s"),
        "baseline_packet_rate": st.column_config.NumberColumn("Baseline rate", format="%.1f pkt/s"),
        "alert_windows": st.column_config.NumberColumn("Alerts"),
    },
)

st.subheader("Packet rate - all devices")
wide = f.pivot_table(index="time", columns="device_name", values="packet_rate_10s")
st.line_chart(wide, y_label="pkt/s", x_label="")
