"""TLS 1.2+ socket server derived from the teacher's server.py skeleton."""
import argparse
import base64
import binascii
import hashlib
import hmac
import json
import socket
import socketserver
import ssl
from pathlib import Path

from eventlog import EventLog
from security import SecurityState, ack_mac, load_users, req_mac

MAX_FRAME = 64 * 1024
MAX_PAYLOAD = 32 * 1024


def send_line(wfile, message):
    wfile.write((json.dumps(message, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8"))
    wfile.flush()


class RequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        state = self.server.state
        events = self.server.events
        ip = self.client_address[0]
        tls = self.request.version()
        cipher = self.request.cipher()[0]
        events.write("tls.connected", peer=ip, tls=tls, cipher=cipher)
        session = None
        try:
            while True:
                line = self.rfile.readline(MAX_FRAME + 1)
                if not line:
                    break
                if len(line) > MAX_FRAME or not line.endswith(b"\n"):
                    send_line(self.wfile, {"ok": False, "error": "frame_too_large"})
                    events.write("protocol.error", peer=ip, reason="frame_too_large")
                    break
                try:
                    msg = json.loads(line)
                    if not isinstance(msg, dict):
                        raise ValueError("not object")
                except (json.JSONDecodeError, UnicodeError, ValueError):
                    send_line(self.wfile, {"ok": False, "error": "invalid_json"})
                    events.write("protocol.error", peer=ip, reason="invalid_json")
                    break
                if session is None:
                    if msg.get("op") != "auth":
                        send_line(self.wfile, {"ok": False, "error": "authentication_required"})
                        events.write("access.denied", peer=ip, reason="unauthenticated")
                        break
                    username, password = msg.get("username"), msg.get("password")
                    if not isinstance(username, str) or len(username) > 32 or not isinstance(password, str) or len(password) > 1024:
                        send_line(self.wfile, {"ok": False, "error": "invalid_credentials"})
                        events.write("auth.failed", peer=ip, reason="invalid_input")
                        break
                    code, session = state.authenticate(ip, username, password)
                    if code != "ok":
                        send_line(self.wfile, {"ok": False, "error": code})
                        events.write("auth.failed" if code == "invalid_credentials" else "auth.rate_limited", peer=ip, username=username, reason=code)
                        break
                    send_line(self.wfile, {"ok": True, "token": session.token, "mac_key": base64.b64encode(session.mac_key).decode("ascii"), "expires_in": state.ttl})
                    events.write("auth.succeeded", peer=ip, username=username)
                    continue
                if msg.get("op") == "logout":
                    state.logout(session)
                    events.write("session.logout", peer=ip, username=session.username)
                    send_line(self.wfile, {"ok": True, "bye": True})
                    break
                if msg.get("op") != "data":
                    send_line(self.wfile, {"ok": False, "error": "unsupported_operation"})
                    events.write("protocol.error", peer=ip, reason="unsupported_operation")
                    continue
                token, seq, payload, tag = (msg.get(k) for k in ("token", "seq", "payload_b64", "hmac"))
                if not isinstance(token, str) or not isinstance(seq, int) or isinstance(seq, bool) or not isinstance(payload, str) or not isinstance(tag, str):
                    code = "invalid_request"
                else:
                    code = state.validate(token, seq, session)
                if code != "ok":
                    send_line(self.wfile, {"ok": False, "error": code})
                    events.write("access.denied", peer=ip, username=session.username, reason=code)
                    continue
                try:
                    data = base64.b64decode(payload, validate=True)
                    if len(data) > MAX_PAYLOAD:
                        raise ValueError("oversize")
                except (binascii.Error, ValueError):
                    send_line(self.wfile, {"ok": False, "error": "invalid_payload"})
                    events.write("data.rejected", peer=ip, username=session.username, reason="invalid_payload")
                    continue
                expected = req_mac(session.mac_key, seq, payload)
                if not hmac.compare_digest(expected, tag):
                    send_line(self.wfile, {"ok": False, "error": "bad_hmac"})
                    events.write("data.integrity_failed", peer=ip, username=session.username, reason="bad_hmac", bytes=len(data))
                    continue
                state.advance(session, seq)
                digest = hashlib.sha256(data).hexdigest()
                reply = {"ok": True, "seq": seq, "bytes": len(data), "sha256": digest, "hmac": ack_mac(session.mac_key, seq, len(data), digest)}
                send_line(self.wfile, reply)
                events.write("data.accepted", peer=ip, username=session.username, bytes=len(data), sha256=digest, seq=seq)
        except (socket.timeout, TimeoutError):
            events.write("conn.error", peer=ip, reason="timeout")
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError) as exc:
            events.write("conn.error", peer=ip, reason=type(exc).__name__)
        finally:
            events.write("conn.closed", peer=ip)


class TLSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address, cert, key, users, logfile, ttl=900, max_fails=5):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(cert, key)
        self.events = EventLog(logfile)
        self.state = SecurityState(load_users(users), ttl=ttl, max_fails=max_fails)
        super().__init__(address, RequestHandler)

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(10)
        try:
            secured = self.context.wrap_socket(sock, server_side=True)
            return secured, address
        except (ssl.SSLError, OSError) as exc:
            self.events.write("tls.handshake_failed", peer=address[0], reason=type(exc).__name__)
            sock.close()
            raise


def main():
    ap = argparse.ArgumentParser(description="Authenticated TLS client-server lab")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert", default="certs/server.crt")
    ap.add_argument("--key", default="certs/server.key")
    ap.add_argument("--users", default="users.json")
    ap.add_argument("--log", default="logs/server.jsonl")
    ap.add_argument("--ttl", type=int, default=900)
    args = ap.parse_args()
    if not (30 <= args.ttl <= 3600):
        ap.error("--ttl must be 30 to 3600 seconds")
    try:
        with TLSServer((args.host, args.port), args.cert, args.key, args.users, args.log, ttl=args.ttl) as server:
            print(f"TLS server listening at {args.host}:{server.server_address[1]} (TLS 1.2+, certificate verification on client)", flush=True)
            server.serve_forever(poll_interval=.2)
    except (FileNotFoundError, ValueError, ssl.SSLError) as exc:
        ap.error(str(exc))

if __name__ == "__main__":
    main()
