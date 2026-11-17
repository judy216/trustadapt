"""TrustAdapt dashboard - entry point (Student 4, Week 9 skeleton).

Run from the repo root:  streamlit run src/trustadapt/dashboard/app.py
The sidebar picks the data source; the loaded Dataset is shared with every page via st.session_state.
"""
from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# Make `import trustadapt` work when run as `streamlit run src/trustadapt/dashboard/app.py` (no install needed)
SRC = str(Path(__file__).resolve().parents[2])
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from trustadapt.dashboard.data import SAMPLE_SCENARIOS, DataError, build_dataset, load_sample  # noqa: E402

st.set_page_config(page_title="TrustAdapt", page_icon=":material/shield:", layout="wide")



@st.cache_data(show_spinner=False)
def _sample(scenario: str):
    return load_sample(scenario)


@st.cache_data(show_spinner=False)
def _uploaded(features: bytes, baseline: bytes | None, devices: bytes | None, name: str):
    import io
    wrap = lambda b: io.BytesIO(b) if b is not None else None  # noqa: E731
    return build_dataset(wrap(features), wrap(baseline), wrap(devices), source=f"Upload: {name}")


with st.sidebar:
    st.title("TrustAdapt")
    st.caption("IoT device behaviour monitoring")
    mode = st.radio("Data source", ["Sample data", "Upload files"], horizontal=True)
    ds = None
    try:
        if mode == "Sample data":
            scenario = st.selectbox("Scenario", list(SAMPLE_SCENARIOS))
            ds = _sample(scenario)
        else:
            f = st.file_uploader("Feature CSV (FR-03)", type="csv")
            b = st.file_uploader("Baseline JSON (optional)", type="json")
            d = st.file_uploader("devices.csv (optional)", type="csv")
            if f is not None:
                ds = _uploaded(f.getvalue(), b.getvalue() if b else None,
                               d.getvalue() if d else None, f.name)
            else:
                st.info("Upload a `*_features.csv` from the extraction pipeline.")
    except DataError as e:
        st.error(str(e))
    except Exception as e:  # malformed file: show it instead of a stack trace
        st.error(f"Could not read the files: {e}")

st.session_state["ds"] = ds

pages = [
    st.Page("views/overview.py", title="Overview", icon=":material/dashboard:", default=True),
    st.Page("views/device.py", title="Device details", icon=":material/router:"),
    st.Page("views/alerts.py", title="Alerts", icon=":material/warning:"),
    st.Page("views/explain.py", title="Explanations", icon=":material/psychology:"),
    st.Page("views/data_health.py", title="Data health", icon=":material/fact_check:"),
]
st.navigation(pages).run()
