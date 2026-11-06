import streamlit as st
import sqlite3
import pandas as pd
from pathlib import Path
import sys

root_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(root_dir))
from core.baseline import BaselineManager

st.set_page_config(page_title="SentinelFIM Dashboard", layout="wide")

st.title("🛡️ SentinelFIM Security Dashboard")

conn = sqlite3.connect(str(root_dir / "activity.db"))

st.sidebar.header("Controls")
severity_filter = st.sidebar.multiselect("Filter Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=["LOW", "MEDIUM", "HIGH", "CRITICAL"])

query = "SELECT * FROM events"
if severity_filter:
    placeholders = ",".join(["?"] * len(severity_filter))
    query += f" WHERE severity IN ({placeholders})"
query += " ORDER BY id DESC"

df = pd.read_sql(query, conn, params=severity_filter)

col1, col2, col3 = st.columns(3)
col1.metric("Total Events", len(df))
col2.metric("Critical Events", len(df[df["severity"] == "CRITICAL"]) if not df.empty else 0)
col3.metric("High Risk Events", len(df[df["severity"] == "HIGH"]) if not df.empty else 0)

st.subheader("Recent FIM Events")
st.dataframe(df, use_container_width=True)

st.subheader("Integrity Verification")
if st.button("Run Baseline Check"):
    bm = BaselineManager(str(root_dir / "activity.db"))
    watch_path = root_dir / "monitored"
    if watch_path.exists():
        bm.create_baseline(watch_path)
    tampered = bm.verify_baseline()
    if tampered:
        st.error(f"Tampering detected! {len(tampered)} files altered/deleted.")
        st.dataframe(pd.DataFrame(tampered, columns=["File Path", "Status"]))
    else:
        st.success("No unauthorized file changes detected.")
