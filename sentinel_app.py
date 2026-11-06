#!/usr/bin/env python3
import csv
from datetime import datetime
import hashlib
import json
from pathlib import Path
import queue
import sqlite3
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

DB_PATH = "activity.db"


class Database:

    @staticmethod
    def init_db():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                file_path TEXT,
                risk_score INTEGER,
                severity TEXT,
                details TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS baselines (
                file_path TEXT PRIMARY KEY,
                file_hash TEXT,
                last_checked TEXT
            )
        """)
        conn.commit()
        conn.close()

    @staticmethod
    def insert_event(timestamp, event_type, file_path, risk_score, severity, details):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO events (timestamp, event_type, file_path, risk_score, severity, details) VALUES (?,?,?,?,?,?)",
            (timestamp, event_type, file_path, risk_score, severity, details)
        )
        conn.commit()
        conn.close()

    @staticmethod
    def get_events(limit=500):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT timestamp, event_type, file_path, risk_score, severity, details FROM events ORDER BY id DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
        return rows


class RiskEngine:
    EVENT_SCORES = {"created": 20, "modified": 30, "moved": 40, "deleted": 60}
    HIGH_RISK_EXT = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".sh"}
    SENSITIVE_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".db", ".sqlite", ".json", ".env", ".key"}
    HIGH_RISK_PATHS = {"windows", "system32", "startup", "programdata", "etc", "bin", "sbin"}

    @classmethod
    def calculate_risk(cls, event_type: str, file_path: str):
        score = cls.EVENT_SCORES.get(event_type.lower(), 10)
        ext = Path(file_path).suffix.lower()
        if ext in cls.HIGH_RISK_EXT:
            score += 40
        if ext in cls.SENSITIVE_EXT:
            score += 20
        path_str = str(file_path).lower()
        for kw in cls.HIGH_RISK_PATHS:
            if kw in path_str:
                score += 30
                break
        score = min(score, 100)
        if score >= 85:
            severity = "CRITICAL"
        elif score >= 65:
            severity = "HIGH"
        elif score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        return score, severity


class BaselineManager:

    @staticmethod
    def compute_hash(path):
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(8192):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    @staticmethod
    def create_baseline(watch_dir):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        root = Path(watch_dir)
        count = 0
        for p in root.rglob("*"):
            if p.is_file():
                f_hash = BaselineManager.compute_hash(p)
                if f_hash:
                    c.execute(
                        "INSERT OR REPLACE INTO baselines (file_path, file_hash, last_checked) VALUES (?, ?, datetime('now'))",
                        (str(p), f_hash)
                    )
                    count += 1
        conn.commit()
        conn.close()
        return count

    @staticmethod
    def verify_baseline():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT file_path, file_hash FROM baselines")
        rows = c.fetchall()
        tampered = []
        for f_path, saved_hash in rows:
            p = Path(f_path)
            if not p.exists():
                tampered.append((f_path, "DELETED"))
            else:
                curr_hash = BaselineManager.compute_hash(p)
                if curr_hash != saved_hash:
                    tampered.append((f_path, "MODIFIED"))
        conn.close()
        return tampered


class FIMHandler(FileSystemEventHandler):

    def __init__(self, evt_queue):
        super().__init__()
        self.queue = evt_queue

    def log(self, event_type, path, details=""):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        score, severity = RiskEngine.calculate_risk(event_type, path)
        Database.insert_event(ts, event_type, path, score, severity, details)
        self.queue.put((ts, event_type, path, score, severity, details))

    def on_created(self, event):
        if not event.is_directory:
            self.log("created", event.src_path, "New file created")

    def on_modified(self, event):
        if not event.is_directory:
            self.log("modified", event.src_path, "File content modified")

    def on_deleted(self, event):
        if not event.is_directory:
            self.log("deleted", event.src_path, "File removed")

    def on_moved(self, event):
        if not event.is_directory:
            self.log("moved", event.dest_path, f"Renamed from {event.src_path}")


class SentinelFIMApp:

    def __init__(self, root):
        self.root = root
        self.root.title("SentinelFIM - Native Security Suite")
        self.root.geometry("1100x680")
        self.root.minsize(900, 500)

        Database.init_db()

        self.watch_dir = Path("monitored").resolve()
        self.watch_dir.mkdir(exist_ok=True)

        self.observer = None
        self.monitoring = False
        self.event_queue = queue.Queue()

        self.counts = {"TOTAL": 0, "CRITICAL": 0, "HIGH": 0, "DELETED": 0}

        self.setup_ui()
        self.load_history()
        self.poll_queue()

    def setup_ui(self):
        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.pack(fill=tk.X)

        ttk.Label(top_frame, text="Watch Directory:").pack(side=tk.LEFT, padx=5)
        self.path_entry = ttk.Entry(top_frame, width=45)
        self.path_entry.insert(0, str(self.watch_dir))
        self.path_entry.pack(side=tk.LEFT, padx=5)

        ttk.Button(top_frame, text="Browse", command=self.browse_dir).pack(side=tk.LEFT, padx=5)

        self.btn_toggle = ttk.Button(top_frame, text="▶ Start Monitoring", command=self.toggle_monitoring)
        self.btn_toggle.pack(side=tk.LEFT, padx=10)

        self.lbl_status = ttk.Label(top_frame, text="STOPPED", foreground="red", font=("Helvetica", 10, "bold"))
        self.lbl_status.pack(side=tk.LEFT, padx=5)

        btn_baseline = ttk.Button(top_frame, text="Snapshot Baseline", command=self.create_baseline)
        btn_baseline.pack(side=tk.RIGHT, padx=5)

        btn_verify = ttk.Button(top_frame, text="Verify Integrity", command=self.verify_baseline)
        btn_verify.pack(side=tk.RIGHT, padx=5)

        # Metric Cards Frame
        card_frame = ttk.Frame(self.root, padding=10)
        card_frame.pack(fill=tk.X)

        self.lbl_total = ttk.Label(card_frame, text="Total: 0", font=("Helvetica", 11, "bold"))
        self.lbl_total.pack(side=tk.LEFT, expand=True)

        self.lbl_crit = ttk.Label(card_frame, text="Critical: 0", foreground="#d9534f", font=("Helvetica", 11, "bold"))
        self.lbl_crit.pack(side=tk.LEFT, expand=True)

        self.lbl_high = ttk.Label(card_frame, text="High: 0", foreground="#f0ad4e", font=("Helvetica", 11, "bold"))
        self.lbl_high.pack(side=tk.LEFT, expand=True)

        self.lbl_del = ttk.Label(card_frame, text="Deletions: 0", foreground="#5bc0de", font=("Helvetica", 11, "bold"))
        self.lbl_del.pack(side=tk.LEFT, expand=True)

        # Controls & Filter Bar
        mid_frame = ttk.Frame(self.root, padding=10)
        mid_frame.pack(fill=tk.X)

        ttk.Label(mid_frame, text="Filter Severity:").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar(value="ALL")
        cb = ttk.Combobox(mid_frame, textvariable=self.filter_var, values=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"], state="readonly", width=12)
        cb.pack(side=tk.LEFT, padx=5)
        cb.bind("<<ComboboxSelected>>", lambda _: self.apply_filter())

        ttk.Button(mid_frame, text="Export CSV", command=self.export_csv).pack(side=tk.RIGHT, padx=5)
        ttk.Button(mid_frame, text="Export JSON", command=self.export_json).pack(side=tk.RIGHT, padx=5)

        # Table Treeview
        table_frame = ttk.Frame(self.root, padding=10)
        table_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("timestamp", "event_type", "severity", "risk_score", "file_path", "details")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")

        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("event_type", text="Event")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("risk_score", text="Score")
        self.tree.heading("file_path", text="Path")
        self.tree.heading("details", text="Details")

        self.tree.column("timestamp", width=140, anchor=tk.CENTER)
        self.tree.column("event_type", width=90, anchor=tk.CENTER)
        self.tree.column("severity", width=90, anchor=tk.CENTER)
        self.tree.column("risk_score", width=60, anchor=tk.CENTER)
        self.tree.column("file_path", width=420)
        self.tree.column("details", width=220)

        # Tag colors
        self.tree.tag_configure("CRITICAL", background="#ffebee", foreground="#c62828")
        self.tree.tag_configure("HIGH", background="#fff3e0", foreground="#ef6c00")
        self.tree.tag_configure("MEDIUM", background="#fffde7", foreground="#f57f17")
        self.tree.tag_configure("LOW", background="#f1f8e9", foreground="#33691e")

        scrolly = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrolly.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrolly.pack(side=tk.RIGHT, fill=tk.Y)

    def browse_dir(self):
        chosen = filedialog.askdirectory(initialdir=str(self.watch_dir))
        if chosen:
            self.watch_dir = Path(chosen)
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, str(self.watch_dir))

    def toggle_monitoring(self):
        if not self.monitoring:
            path_str = self.path_entry.get().strip()
            self.watch_dir = Path(path_str)
            self.watch_dir.mkdir(parents=True, exist_ok=True)

            self.observer = Observer()
            handler = FIMHandler(self.event_queue)
            self.observer.schedule(handler, str(self.watch_dir), recursive=True)
            self.observer.start()

            self.monitoring = True
            self.lbl_status.config(text="RUNNING", foreground="green")
            self.btn_toggle.config(text="⏹ Stop Monitoring")
        else:
            if self.observer:
                self.observer.stop()
                self.observer.join()
                self.observer = None
            self.monitoring = False
            self.lbl_status.config(text="STOPPED", foreground="red")
            self.btn_toggle.config(text="▶ Start Monitoring")

    def create_baseline(self):
        path_str = self.path_entry.get().strip()
        count = BaselineManager.create_baseline(path_str)
        messagebox.showinfo("Baseline Created", f"Recorded SHA-256 signatures for {count} files.")

    def verify_baseline(self):
        tampered = BaselineManager.verify_baseline()
        if not tampered:
            messagebox.showinfo("Verification Passed", "All file integrity checks passed. No tampering detected.")
        else:
            msg = f"Alert: {len(tampered)} files altered or missing!\n\n"
            for fpath, st in tampered[:10]:
                msg += f"• {st}: {fpath}\n"
            if len(tampered) > 10:
                msg += f"... and {len(tampered) - 10} more."
            messagebox.showwarning("Tampering Detected", msg)

    def add_tree_item(self, row):
        ts, evt, path, score, sev, det = row
        self.tree.insert("", 0, values=(ts, evt.upper(), sev, score, path, det), tags=(sev,))
        self.counts["TOTAL"] += 1
        if sev == "CRITICAL":
            self.counts["CRITICAL"] += 1
        elif sev == "HIGH":
            self.counts["HIGH"] += 1
        if evt.lower() == "deleted":
            self.counts["DELETED"] += 1
        self.update_card_labels()

    def update_card_labels(self):
        self.lbl_total.config(text=f"Total: {self.counts['TOTAL']}")
        self.lbl_crit.config(text=f"Critical: {self.counts['CRITICAL']}")
        self.lbl_high.config(text=f"High: {self.counts['HIGH']}")
        self.lbl_del.config(text=f"Deletions: {self.counts['DELETED']}")

    def load_history(self):
        rows = Database.get_events()
        for r in reversed(rows):
            self.add_tree_item(r)

    def apply_filter(self):
        selected = self.filter_var.get()
        self.tree.delete(*self.tree.get_children())
        self.counts = {"TOTAL": 0, "CRITICAL": 0, "HIGH": 0, "DELETED": 0}
        rows = Database.get_events()
        for r in reversed(rows):
            sev = r[4]
            if selected == "ALL" or sev == selected:
                self.add_tree_item(r)

    def poll_queue(self):
        while not self.event_queue.empty():
            try:
                row = self.event_queue.get_nowait()
                selected = self.filter_var.get()
                if selected == "ALL" or row[4] == selected:
                    self.add_tree_item(row)
            except queue.Empty:
                break
        self.root.after(300, self.poll_queue)

    def export_csv(self):
        fn = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if fn:
            rows = Database.get_events(limit=50000)
            with open(fn, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Event", "Path", "RiskScore", "Severity", "Details"])
                writer.writerows(rows)
            messagebox.showinfo("Export Successful", f"Saved {len(rows)} events to CSV.")

    def export_json(self):
        fn = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if fn:
            rows = Database.get_events(limit=50000)
            cols = ["timestamp", "event_type", "file_path", "risk_score", "severity", "details"]
            data = [dict(zip(cols, r)) for r in rows]
            with open(fn, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            messagebox.showinfo("Export Successful", f"Saved {len(rows)} events to JSON.")

    def on_closing(self):
        if self.monitoring and self.observer:
            self.observer.stop()
            self.observer.join()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = SentinelFIMApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
