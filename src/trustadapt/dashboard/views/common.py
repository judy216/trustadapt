"""Helpers shared by the pages."""
from __future__ import annotations

import streamlit as st

from trustadapt.dashboard.data import Dataset


def require_dataset() -> Dataset:
    ds = st.session_state.get("ds")
    if ds is None:
        st.info("No data loaded. Choose a sample scenario or upload files in the sidebar.")
        st.stop()
    return ds


def device_picker(ds: Dataset, key: str = "device") -> str:
    f = ds.features
    macs = sorted(f["device_mac"].unique())
    names = dict(zip(f["device_mac"], f["device_name"]))
    return st.selectbox("Device", macs, format_func=lambda m: f"{names[m]}  ({m})", key=key)


def pending(component: str, owner: str) -> None:
    st.caption(f":material/hourglass_empty: {component} - pending ({owner})")
