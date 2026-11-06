from datetime import datetime

from database.database import Database
from core.risk_engine import RiskEngine

db = Database()


class Logger:

    @staticmethod
    def log(event_type, file_path):

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        risk_score, severity = RiskEngine.calculate_risk(
            event_type,
            file_path
        )

        log_entry = (
            f"[{timestamp}] "
            f"[{event_type}] "
            f"[{severity}] "
            f"[Risk:{risk_score}] "
            f"{file_path}"
        )

        print(log_entry)

        with open("activity.log", "a", encoding="utf-8") as file:
            file.write(log_entry + "\n")

        db.insert_event(
            timestamp=timestamp,
            event_type=event_type,
            file_path=file_path,
            risk_score=risk_score,
            severity=severity,
            details=event_type
        )
