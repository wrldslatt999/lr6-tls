"""Password storage, rate limits and ephemeral authenticated sessions."""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1


def hash_password(password: str) -> str:
    if not 12 <= len(password.encode("utf-8")) <= 1024:
        raise ValueError("Password must be 12-1024 UTF-8 bytes")
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return "scrypt$16384$8$1$%s$%s" % (salt.hex(), key.hex())


def verify_password(password: str, encoded: str) -> bool:
    try:
        alg, ns, rs, ps, salt, expected = encoded.split("$")
        if (alg, int(ns), int(rs), int(ps)) != ("scrypt", SCRYPT_N, SCRYPT_R, SCRYPT_P):
            return False
        if len(password.encode()) > 1024:
            return False
        got = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
        return hmac.compare_digest(got, bytes.fromhex(expected))
    except (ValueError, TypeError, UnicodeError):
        return False


def load_users(path: str) -> dict:
    users = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(users, dict) or not users:
        raise ValueError("User database is empty or invalid")
    for name, entry in users.items():
        if not USERNAME_RE.fullmatch(name) or not isinstance(entry, dict) or entry.get("role") not in ("user", "admin") or not str(entry.get("hash", "")).startswith("scrypt$"):
            raise ValueError("Invalid entry in user database")
    return users


def req_mac(key: bytes, seq: int, payload_b64: str) -> str:
    return hmac.new(key, f"REQ|{seq}|{payload_b64}".encode("ascii"), hashlib.sha256).hexdigest()


def ack_mac(key: bytes, seq: int, size: int, digest: str) -> str:
    return hmac.new(key, f"ACK|{seq}|{size}|{digest}".encode("ascii"), hashlib.sha256).hexdigest()


@dataclass
class Session:
    token: str
    mac_key: bytes
    username: str
    role: str
    expires_at: float
    last_seq: int = 0


class SecurityState:
    def __init__(self, users: dict, ttl: int = 900, max_fails: int = 5, window: int = 60):
        self.users = users
        self.ttl = ttl
        self.max_fails = max_fails
        self.window = window
        self.sessions: dict[str, Session] = {}
        self.failures: dict[str, list[float]] = {}
        self.lock = threading.RLock()
        self._dummy_hash = hash_password("This-is-a-dummy-password-1234")

    def blocked(self, ip: str, now: float | None = None) -> bool:
        t = time.time() if now is None else now
        with self.lock:
            recent = [v for v in self.failures.get(ip, []) if t - v < self.window]
            self.failures[ip] = recent
            return len(recent) >= self.max_fails

    def authenticate(self, ip: str, username: str, password: str) -> tuple[str, Session | None]:
        if self.blocked(ip):
            return "rate_limited", None
        entry = self.users.get(username, {}) if isinstance(username, str) else {}
        valid = verify_password(password, entry.get("hash", self._dummy_hash))
        if not entry or not valid:
            with self.lock:
                self.failures.setdefault(ip, []).append(time.time())
            return "invalid_credentials", None
        with self.lock:
            self.failures.pop(ip, None)
            token = secrets.token_urlsafe(32)
            sess = Session(token, secrets.token_bytes(32), username, entry["role"], time.time()+self.ttl)
            self.sessions[token] = sess
        return "ok", sess

    def validate(self, token: str, seq: int, sess: Session) -> str:
        with self.lock:
            if token != sess.token or self.sessions.get(token) is not sess:
                return "invalid_token"
            if time.time() >= sess.expires_at:
                self.sessions.pop(token, None)
                return "expired_token"
            if seq != sess.last_seq + 1:
                return "invalid_sequence"
            return "ok"

    def advance(self, sess: Session, seq: int) -> None:
        with self.lock:
            sess.last_seq = seq

    def logout(self, sess: Session) -> None:
        with self.lock:
            self.sessions.pop(sess.token, None)
