#!/usr/bin/env python3
import streamlit as st
import sqlite3
import pandas as pd
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import hashlib
import json
import csv
import threading
import time
import yaml

# Config
CONFIG = {
    "watch_path": "monitored",
    "enable_baseline": True,
    "high_risk_threshold": 70,
    "critical_threshold": 85,
}

DB_PATH = "activity.db"

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            file_path TEXT,
            risk_score INTEGER,
            severity TEXT,
            details TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS baselines(
            file_path TEXT PRIMARY KEY,
            file_hash TEXT,
            last_checked TEXT
        )
    """)
    conn.commit()
    conn.close()

# Risk engine
class RiskEngine:
    EVENT_SCORES = {"created": 20, "modified": 30, "moved": 40, "deleted": 60}
    HIGH_RISK_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi"}
    SENSITIVE_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".db", ".sqlite", ".json"}
    HIGH_RISK_PATHS = {"windows", "system32", "startup", "programdata"}

    @classmethod
    def calculate_risk(cls, event_type: str, file_path: str):
        score = cls.EVENT_SCORES.get(event_type.lower(), 5)
        extension = Path(file_path).suffix.lower()
        if extension in cls.HIGH_RISK_EXTENSIONS:
            score += 40
        if extension in cls.SENSITIVE_EXTENSIONS:
            score += 15
        path_lower = str(file_path).lower()
        for keyword in cls.HIGH_RISK_PATHS:
            if keyword in path_lower:
                score += 30
                break
        score = min(score, 100)
        severity = "CRITICAL" if score >= 85 else "HIGH" if score >= 70 else "MEDIUM" if score >= 50 else "LOW"
        return score, severity

# Baseline manager
class BaselineManager:
    @staticmethod
    def compute_hash(file_path):
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None

    @staticmethod
    def create_baseline(root_path):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        root = Path(root_path)
        for path in root.rglob("*"):
            if path.is_file():
                file_hash = BaselineManager.compute_hash(path)
                if file_hash:
                    cursor.execute(
                        "INSERT OR REPLACE INTO baselines(file_path, file_hash, last_checked) VALUES (?, ?, datetime('now'))",
                        (str(path), file_hash)
                    )
        conn.commit()
        conn.close()

    @staticmethod
    def verify_baseline():
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT file_path, file_hash FROM baselines")
        rows = cursor.fetchall()
        tampered = []
        for file_path, stored_hash in rows:
            if not Path(file_path).exists():
                tampered.append((file_path, "DELETED"))
                continue
            current_hash = BaselineManager.compute_hash(file_path)
            if current_hash != stored_hash:
                tampered.append((file_path, "MODIFIED"))
        conn.close()
        return tampered

# File monitoring handler
class SentinelHandler(FileSystemEventHandler):
    def log_event(self, event_type, file_path, details):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        score, severity = RiskEngine.calculate_risk(event_type, file_path)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO events(timestamp, event_type, file_path, risk_score, severity, details) VALUES(?,?,?,?,?,?)",
            (timestamp, event_type, file_path, score, severity, details)
        )
        conn.commit()
        conn.close()

    def on_created(self, event):
        if not event.is_directory:
            self.log_event("created", event.src_path, "File created")

    def on_modified(self, event):
        if not event.is_directory:
            self.log_event("modified", event.src_path, "File modified")

    def on_deleted(self, event):
        if not event.is_directory:
            self.log_event("deleted", event.src_path, "File deleted")

    def on_moved(self, event):
        if not event.is_directory:
            self.log_event("moved", event.dest_path, f"Moved from {event.src_path}")

# Export utilities
class Exporter:
    @staticmethod
    def export_csv():
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events ORDER BY id DESC")
        rows = cursor.fetchall()
        columns = ["id", "timestamp", "event_type", "file_path", "risk_score", "severity", "details"]
        df = pd.DataFrame(rows, columns=columns)
        conn.close()
        return df.to_csv(index=False).encode()

    @staticmethod
    def export_json():
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events ORDER BY id DESC")
        rows = cursor.fetchall()
        columns = ["id", "timestamp", "event_type", "file_path", "risk_score", "severity", "details"]
        data = [dict(zip(columns, row)) for row in rows]
        conn.close()
        return json.dumps(data, indent=2).encode()

# Initialize
init_db()

st.set_page_config(page_title="SentinelFIM", layout="wide")
st.title("🛡️ SentinelFIM - File Integrity Monitoring")

# Session state
if "monitoring" not in st.session_state:
    st.session_state.monitoring = False
    st.session_state.observer = None

# Sidebar controls
with st.sidebar:
    st.header("⚙️ Controls")

    if st.button("▶️ Start Monitoring" if not st.session_state.monitoring else "⏹️ Stop Monitoring"):
        if not st.session_state.monitoring:
            watch_path = Path(CONFIG["watch_path"])
            watch_path.mkdir(exist_ok=True)
            observer = Observer()
            handler = SentinelHandler()
            observer.schedule(handler, str(watch_path), recursive=True)
            observer.start()
            st.session_state.observer = observer
            st.session_state.monitoring = True
            st.success("Monitoring started!")
        else:
            if st.session_state.observer:
                st.session_state.observer.stop()
                st.session_state.observer.join()
            st.session_state.monitoring = False
            st.info("Monitoring stopped")

    st.write(f"**Status:** {'🟢 Active' if st.session_state.monitoring else '🔴 Inactive'}")

    st.divider()
    st.subheader("Baseline")
    if st.button("📸 Create Baseline"):
        with st.spinner("Creating baseline..."):
            BaselineManager.create_baseline(CONFIG["watch_path"])
            st.success("Baseline created!")

    if st.button("✅ Verify Baseline"):
        with st.spinner("Verifying..."):
            tampered = BaselineManager.verify_baseline()
            if tampered:
                st.error(f"⚠️ {len(tampered)} files tampered!")
                for fpath, status in tampered:
                    st.write(f"- {fpath}: {status}")
            else:
                st.success("✓ All files intact!")

    st.divider()
    st.subheader("Export")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📊 CSV"):
            csv_data = Exporter.export_csv()
            st.download_button("Download CSV", csv_data, "events.csv", "text/csv")
    with col2:
        if st.button("📄 JSON"):
            json_data = Exporter.export_json()
            st.download_button("Download JSON", json_data, "events.json", "application/json")

# Main dashboard
tabs = st.tabs(["📊 Dashboard", "📋 Events", "⚡ Risk Analysis", "ℹ️ About"])

with tabs[0]:
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT * FROM events ORDER BY id DESC", conn)
    conn.close()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Events", len(df) if not df.empty else 0)
    with col2:
        critical = len(df[df["severity"] == "CRITICAL"]) if not df.empty else 0
        st.metric("🚨 Critical", critical)
    with col3:
        high = len(df[df["severity"] == "HIGH"]) if not df.empty else 0
        st.metric("⚠️ High", high)
    with col4:
        deleted = len(df[df["event_type"] == "deleted"]) if not df.empty else 0
        st.metric("🗑️ Deletions", deleted)

    if not df.empty:
        st.subheader("Risk Heatmap (Last 24h)")
        severity_counts = df["severity"].value_counts()
        st.bar_chart(severity_counts)

with tabs[1]:
    severity_filter = st.multiselect("Filter Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=["LOW", "MEDIUM", "HIGH", "CRITICAL"])

    conn = sqlite3.connect(DB_PATH)
    if severity_filter:
        placeholders = ",".join(["?"] * len(severity_filter))
        df = pd.read_sql(f"SELECT * FROM events WHERE severity IN ({placeholders}) ORDER BY id DESC", conn, params=severity_filter)
    else:
        df = pd.read_sql("SELECT * FROM events ORDER BY id DESC", conn)
    conn.close()

    st.dataframe(df, use_container_width=True)

with tabs[2]:
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT * FROM events ORDER BY id DESC", conn)
    conn.close()

    if not df.empty:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Events by Type")
            event_counts = df["event_type"].value_counts()
            st.bar_chart(event_counts)
        with col2:
            st.subheader("Risk Distribution")
            risk_avg = df.groupby("event_type")["risk_score"].mean().sort_values(ascending=False)
            st.bar_chart(risk_avg)

        st.subheader("High-Risk Files")
        high_risk = df[df["risk_score"] >= 70].sort_values("risk_score", ascending=False)
        if not high_risk.empty:
            st.dataframe(high_risk[["timestamp", "file_path", "risk_score", "severity"]], use_container_width=True)
        else:
            st.info("No high-risk events detected.")

with tabs[3]:
    st.markdown("""
    ### SentinelFIM - File Integrity Monitoring System

    **Features:**
    - Real-time file monitoring (creation, modification, deletion, move)
    - Risk scoring based on file type & location
    - SHA-256 baseline integrity verification
    - Event database & export (CSV/JSON)
    - Live dashboard with risk analytics

    **Risk Scoring:**
    - High-risk executables: +40 (`.exe`, `.dll`, `.bat`, `.ps1`, etc.)
    - Sensitive docs: +15 (`.pdf`, `.docx`, `.xlsx`, `.sqlite`, etc.)
    - System paths: +30 (`system32`, `startup`, `programdata`)
    - Event base score: 5-60 (deleted = 60, modified = 30, etc.)

    **Severity Levels:**
    - 🟢 LOW: 0-25
    - 🟡 MEDIUM: 25-50
    - 🟠 HIGH: 50-75
    - 🔴 CRITICAL: 75+
    """)
