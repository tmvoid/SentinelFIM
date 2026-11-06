from pathlib import Path
from watchdog.observers import Observer
from core.watchdog_handler import SentinelHandler
from core.baseline import BaselineManager

import time
import yaml

WATCH_PATH = Path("monitored")
WATCH_PATH.mkdir(exist_ok=True)
config_path = Path("config.yaml")

with open(config_path) as f:
    config = yaml.safe_load(f)

ENABLE_BASELINE = config.get("enable_baseline", True)
HIGH_RISK_THRESHOLD = config.get("high_risk_threshold", 70)
CRITICAL_THRESHOLD = config.get("critical_threshold", 85)

observer = Observer()
handler = SentinelHandler()

observer.schedule(
    handler,
    str(WATCH_PATH),
    recursive=True
)

observer.start()

if ENABLE_BASELINE:
    BaselineManager().create_baseline(WATCH_PATH)

print(f"Monitoring: {WATCH_PATH}")

try:
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    observer.stop()

observer.join()