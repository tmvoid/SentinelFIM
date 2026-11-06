import sqlite3
import json
import csv

class Exporter:
    @staticmethod
    def export_csv(db_path="activity.csv", limit=None):
        conn = sqlite3.connect("activity.db")
        cursor = conn.cursor()
        query = "SELECT * FROM events ORDER BY id DESC"
        if limit:
            query += f" LIMIT {limit}"
        cursor.execute(query)
        rows = cursor.fetchall()
        with open(db_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["id", "timestamp", "event_type", "file_path", "risk_score", "severity", "details"])
            writer.writerows(rows)
        conn.close()

    @staticmethod
    def export_json(db_path="export.json"):
        conn = sqlite3.connect("activity.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events ORDER BY id DESC")
        rows = cursor.fetchall()
        columns = ["id", "timestamp", "event_type", "file_path", "risk_score", "severity", "details"]
        data = [dict(zip(columns, row)) for row in rows]
        with open(db_path, "w") as f:
            json.dump(data, f, indent=2)
        conn.close()