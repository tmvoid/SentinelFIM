from datetime import datetime
from watchdog.events import FileSystemEventHandler

from core.risk_engine import RiskEngine
from database.database import Database


class SentinelHandler(FileSystemEventHandler):

    def __init__(self):
        self.db = Database()

    def log_event(self, event_type, file_path, details):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        score, severity = RiskEngine.calculate_risk(
            event_type,
            file_path
        )

        self.db.insert_event(
            timestamp,
            event_type,
            file_path,
            score,
            severity,
            details
        )

        print(
            f"[{timestamp}] "
            f"{event_type.upper()} | "
            f"{severity} ({score}) | "
            f"{file_path}"
        )

    def on_created(self, event):
        if not event.is_directory:
            self.log_event(
                "created",
                event.src_path,
                "File created"
            )

    def on_modified(self, event):
        if not event.is_directory:
            self.log_event(
                "modified",
                event.src_path,
                "File modified"
            )

    def on_deleted(self, event):
        if not event.is_directory:
            self.log_event(
                "deleted",
                event.src_path,
                "File deleted"
            )

    def on_moved(self, event):
        if not event.is_directory:
            self.log_event(
                "moved",
                event.dest_path,
                f"Moved from {event.src_path}"
            )
