import hashlib
import sqlite3
from pathlib import Path

class BaselineManager:
    def __init__(self, db_path="activity.db"):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS baselines(
                file_path TEXT PRIMARY KEY,
                file_hash TEXT,
                last_checked TEXT
            )
        """)
        self.conn.commit()

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

    def create_baseline(self, root_path):
        root = Path(root_path)
        for path in root.rglob("*"):
            if path.is_file():
                file_hash = self.compute_hash(path)
                if file_hash:
                    self.cursor.execute(
                        "INSERT OR REPLACE INTO baselines(file_path, file_hash, last_checked) VALUES (?, ?, datetime('now'))",
                        (str(path), file_hash)
                    )
        self.conn.commit()

    def verify_baseline(self):
        self.cursor.execute("SELECT file_path, file_hash FROM baselines")
        rows = self.cursor.fetchall()
        tampered = []
        for file_path, stored_hash in rows:
            if not Path(file_path).exists():
                tampered.append((file_path, "DELETED"))
                continue
            current_hash = self.compute_hash(file_path)
            if current_hash != stored_hash:
                tampered.append((file_path, "MODIFIED"))
        return tampered
