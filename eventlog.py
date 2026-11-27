"""Thread-safe JSONL security events; no credentials, tokens or message bodies."""
import datetime
import json
import threading
from pathlib import Path

class EventLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

    def write(self, event: str, **fields) -> None:
        allowed = {"peer", "username", "reason", "bytes", "tls", "cipher", "code", "sha256", "cert_sha256", "seq"}
        rec = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "event": event}
        rec.update({k: v for k, v in fields.items() if k in allowed and isinstance(v, (str, int, float, bool, type(None)))})
        with self.lock, self.path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
