"""Aggregate JSONL events, detect failed auth bursts and TLS failures."""
import argparse
import collections
import datetime as dt
import json
from pathlib import Path

SUSPICIOUS = {"tls.handshake_failed", "auth.failed", "auth.rate_limited", "data.integrity_failed", "access.denied", "data.rejected", "protocol.error", "connection.failed"}


def summarize(path, event=None, user=None, since=None):
    counts = collections.Counter()
    suspicious = collections.Counter()
    users = collections.Counter()
    selected = 0
    malformed = 0
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
            if not isinstance(record, dict) or "event" not in record:
                raise ValueError()
            if event and record.get("event") != event:
                continue
            if user and record.get("username") != user:
                continue
            if since and record.get("ts", "") < since:
                continue
            selected += 1
            counts[record["event"]] += 1
            if record["event"] in SUSPICIOUS:
                suspicious[(record.get("peer", "unknown"), record["event"])] += 1
            if "username" in record:
                users[record["username"]] += 1
        except (ValueError, json.JSONDecodeError):
            malformed += 1
    bursts = [{"peer": peer, "failures": sum(n for (p, evt), n in suspicious.items() if p == peer and evt in {"auth.failed", "auth.rate_limited"})} for peer in sorted({p for p, evt in suspicious})]
    bursts = [b for b in bursts if b["failures"] >= 3]
    return {"events_analyzed": selected, "malformed_lines": malformed, "by_event": dict(counts), "by_user": dict(users), "suspicious": [{"peer": peer, "event": evt, "count": num} for ((peer,evt),num) in sorted(suspicious.items())], "auth_failure_bursts_ge3": bursts}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default="logs/server.jsonl")
    ap.add_argument("--event")
    ap.add_argument("--user")
    ap.add_argument("--since", help="ISO UTC timestamp, e.g. 2026-11-27T00:00:00")
    ap.add_argument("--out", help="write JSON report to file (logs themselves are local)")
    args = ap.parse_args()
    result = summarize(args.path, event=args.event, user=args.user, since=args.since)
    report = json.dumps(result, ensure_ascii=False, indent=2)
    print(report)
    if args.out:
        Path(args.out).parent.mkdir(parents=True,exist_ok=True)
        Path(args.out).write_text(report+"\n", encoding="utf-8")

if __name__ == "__main__":
    main()
