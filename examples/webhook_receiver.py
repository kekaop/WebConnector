"""Local signed-webhook receiver for integration testing. Set WEBCONNECTOR_WEBHOOK_SECRET privately."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
import hmac
import json
import os
import time

secret = os.environ["WEBCONNECTOR_WEBHOOK_SECRET"].encode()
seen = {}


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/webhook":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 65536:
                raise ValueError()
            self.connection.settimeout(5)
            raw = self.rfile.read(length)
            timestamp = self.headers["X-WebConnector-Timestamp"]
            age = abs((datetime.now(timezone.utc) - datetime.fromisoformat(timestamp.replace("Z", "+00:00"))).total_seconds())
            expected = "sha256=" + hmac.new(secret, timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
            if age > 600 or not hmac.compare_digest(expected, self.headers.get("X-WebConnector-Signature", "")):
                raise ValueError()
            event = json.loads(raw)
            event_id = self.headers["X-WebConnector-Id"]
            if event["id"] != event_id or event["timestamp"] != timestamp:
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            self.send_error(401)
            return
        now = time.monotonic()
        for previous in list(seen):
            if seen[previous] < now - 1200:
                del seen[previous]
        if event_id not in seen:
            if len(seen) >= 10000:
                self.send_error(429)
                return
            seen[event_id] = now
            print(json.dumps({"id": event_id, "type": event.get("type", event.get("event")), "accepted": True}), flush=True)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    print("Mock receiver: http://127.0.0.1:3000/webhook", flush=True)
    HTTPServer(("127.0.0.1", 3000), Receiver).serve_forever()
