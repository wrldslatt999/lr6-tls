"""Verified TLS client; password never goes into the command line or logs."""
import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import ssl
import sys
import getpass
from pathlib import Path
from eventlog import EventLog
from security import ack_mac, req_mac

MAX_FRAME = 64 * 1024

class ProtocolError(Exception):
    pass


def exchange(host, port, server_name, cafile, user, password, content: bytes, *, tamper=False, log="logs/client.jsonl"):
    if not isinstance(content, bytes) or len(content) > 32768:
        raise ValueError("Payload limit: 32768 bytes")
    events = EventLog(log)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=10) as raw, ctx.wrap_socket(raw, server_hostname=server_name) as secured:
            secured.settimeout(10)
            tls = {"version": secured.version(), "cipher": secured.cipher()[0], "cert_sha256": hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest(), "subject": str(secured.getpeercert().get("subject"))}
            events.write("tls.verified", peer=host, tls=tls["version"], cipher=tls["cipher"], cert_sha256=tls["cert_sha256"])
            with secured.makefile("rwb") as stream:
                def request(payload):
                    stream.write((json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode())
                    stream.flush()
                    line = stream.readline(MAX_FRAME+1)
                    if not line or len(line)>MAX_FRAME or not line.endswith(b"\n"):
                        raise ProtocolError("Server closed connection or returned oversized reply")
                    try:
                        parsed = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ProtocolError("Invalid server JSON") from exc
                    if not isinstance(parsed, dict):
                        raise ProtocolError("Server response is not an object")
                    return parsed
                auth = request({"op": "auth", "username": user, "password": password})
                if not auth.get("ok"):
                    events.write("auth.failed", peer=host, username=user, reason=str(auth.get("error", "unknown")))
                    return {"tls": tls, "auth": {"ok": False, "error": auth.get("error")}}
                events.write("auth.succeeded", peer=host, username=user)
                key = base64.b64decode(auth["mac_key"], validate=True)
                if len(key) != 32:
                    raise ProtocolError("Invalid session MAC key length")
                seq = 1
                payload_b64 = base64.b64encode(content).decode("ascii")
                signature = req_mac(key, seq, payload_b64)
                if tamper:
                    signature = ("0" if signature[0] != "0" else "1") + signature[1:]
                answer = request({"op":"data", "token":auth["token"], "seq":seq, "payload_b64":payload_b64,"hmac":signature})
                if answer.get("ok"):
                    expected_hash = hashlib.sha256(content).hexdigest()
                    expected_mac = ack_mac(key, seq, len(content), expected_hash)
                    if answer.get("seq") != seq or answer.get("bytes") != len(content) or answer.get("sha256") != expected_hash or not hmac.compare_digest(str(answer.get("hmac", "")), expected_mac):
                        events.write("data.integrity_failed", peer=host, username=user, reason="bad_reply_hmac")
                        raise ProtocolError("Server response integrity verification failed")
                    events.write("data.verified", peer=host, username=user, bytes=len(content), sha256=expected_hash)
                else:
                    events.write("data.rejected", peer=host, username=user, reason=str(answer.get("error", "unknown")))
                request({"op":"logout"})
                return {"tls": tls, "auth": {"ok": True, "expires_in": auth.get("expires_in")}, "data": answer}
    except (ssl.SSLError, ssl.CertificateError, ConnectionError, TimeoutError, OSError, ProtocolError) as exc:
        events.write("connection.failed", peer=host, reason=type(exc).__name__)
        raise


def main():
    ap = argparse.ArgumentParser(description="Verified TLS client for LR6")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--server-name", default="localhost")
    ap.add_argument("--ca", default="certs/ca.crt")
    ap.add_argument("--user", required=True)
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument("--msg")
    source.add_argument("--file")
    ap.add_argument("--tamper", action="store_true", help="deliberately corrupt application HMAC for own lab server")
    ap.add_argument("--log", default="logs/client.jsonl")
    args = ap.parse_args()
    password = getpass.getpass("Password (hidden): ")
    try:
        content = args.msg.encode("utf-8") if args.msg is not None else Path(args.file).read_bytes()
        result = exchange(args.host, args.port, args.server_name, args.ca, args.user, password, content, tamper=args.tamper, log=args.log)
        print("TLS verified:", result["tls"]["version"], result["tls"]["cipher"])
        print("Certificate SHA-256:", result["tls"]["cert_sha256"])
        print("Certificate subject:", result["tls"]["subject"])
        print("Authentication:", "OK" if result["auth"]["ok"] else result["auth"]["error"])
        if "data" in result:
            data = result["data"]
            print("Data:", ("VERIFIED" if data.get("ok") else "REJECTED " + str(data.get("error"))))
            if data.get("ok"):
                print("Accepted bytes:", data["bytes"], "SHA-256:", data["sha256"])
        return 0 if result.get("data", {}).get("ok") else 2
    except (OSError, ValueError, ProtocolError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
