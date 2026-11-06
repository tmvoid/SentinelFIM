import urllib.request
import json

class Notifier:
    @staticmethod
    def send_webhook(url, payload):
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            print(f"[ERROR] Webhook failed: {e}")
