import pandas as pd
import streamlit as st

from trustadapt.dashboard.contract import ML_FEATURES, label
from trustadapt.dashboard.data import alerts, device_status
from trustadapt.dashboard.views.common import device_picker, require_dataset

ds = require_dataset()
st.header("Device details")

mac = device_picker(ds)
g = ds.features[ds.features["device_mac"] == mac].set_index("time")
base = ds.baseline.get(mac, {})
last = g.iloc[-1]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Status", device_status(ds, mac))
c2.metric("Packet rate (last window)", f"{last['packet_rate_10s']:.1f} pkt/s",
          delta=(f"{last['packet_rate_10s'] - base['mean_packet_rate']:+.1f} vs baseline"
                 if "mean_packet_rate" in base else None),
          delta_color="inverse")
c3.metric("Protocol (dominant flow)", f"{last['app_protocol'] or '-'} / {last['protocol_type'] or '-'}")
c4.metric("Alert windows", int((alerts(ds)["device_mac"] == mac).sum()))

if base:
    with st.expander("Baseline profile (FR-04)"):
        st.write(f"Windows used: {base.get('windows_used')} | complete: {base.get('complete')}")
        st.write("Port whitelist:", ", ".join(map(str, base.get("port_whitelist", []))) or "-")
        st.write("Known destinations:", ", ".join(base.get("known_destinations", [])) or "-")
else:
    st.caption("No baseline JSON loaded for this device - baseline lines are hidden.")

st.subheader("Behaviour over time")
chosen = st.multiselect("Features", list(ML_FEATURES), default=["packet_rate_10s", "bytes_sent_rate"],
                        format_func=label)
for feat in chosen:
    chart = pd.DataFrame({"value": g[feat]})
    mean = base.get("ml_mean", {}).get(feat)
    if mean is not None:
        chart["baseline mean"] = mean
    st.markdown(f"**{label(feat)}**")
    st.line_chart(chart, height=200, x_label="")

with st.expander("Raw feature rows"):
    st.dataframe(g.drop(columns=["device_name", "device_type"]))
