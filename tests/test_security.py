import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from analyze_logs import summarize
from client import ProtocolError, exchange
from security import SecurityState, ack_mac, hash_password, req_mac, verify_password
from server import TLSServer
from tools.setup_users import add_user

ROOT = Path(__file__).resolve().parents[1]


class PasswordAndStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verifier = hash_password("Test-Only-Strong-Password-724")

    def test_scrypt_roundtrip(self):
        self.assertTrue(verify_password("Test-Only-Strong-Password-724", self.verifier))

    def test_scrypt_wrong_password(self):
        self.assertFalse(verify_password("other-incorrect-password", self.verifier))

    def test_scrypt_random_salts(self):
        self.assertNotEqual(hash_password("Test-Only-Strong-Password-724"), self.verifier)

    def test_invalid_and_short_password(self):
        with self.assertRaises(ValueError):
            hash_password("short")
        self.assertFalse(verify_password("a", "scrypt$wrong$bad"))

    def test_user_store_atomic_and_unique(self):
        with tempfile.TemporaryDirectory() as path:
            users = Path(path)/"users.json"
            add_user(users, "alice", "user", "Test-Only-Strong-Password-724")
            content = json.loads(users.read_text())
            self.assertNotIn("Test-Only-Strong-Password-724", users.read_text())
            self.assertEqual(content["alice"]["role"], "user")
            with self.assertRaisesRegex(ValueError, "already exists"):
                add_user(users, "alice", "admin", "Test-Only-Strong-Password-724")
            self.assertEqual(json.loads(users.read_text())["alice"]["role"], "user")

    def test_create_login_and_expire_session(self):
        s = SecurityState({"alice": {"hash": self.verifier, "role": "user"}})
        self.assertEqual(s.authenticate("1.2.3.4", "alice", "bad-pass-123")[0], "invalid_credentials")
        code, sess = s.authenticate("1.2.3.4", "alice", "Test-Only-Strong-Password-724")
        self.assertEqual(code, "ok")
        self.assertEqual(s.validate(sess.token, 1, sess), "ok")
        s.advance(sess, 1)
        self.assertEqual(s.validate(sess.token, 1, sess), "invalid_sequence")
        sess.expires_at = time.time()-1
        self.assertEqual(s.validate(sess.token, 2, sess), "expired_token")
        self.assertEqual(s.validate(sess.token, 2, sess), "invalid_token")

    def test_rate_limit(self):
        s = SecurityState({"alice": {"hash": self.verifier, "role": "user"}}, max_fails=3)
        for _ in range(3):
            self.assertEqual(s.authenticate("192.0.2.4", "alice", "Wrong-1234567")[0], "invalid_credentials")
        self.assertEqual(s.authenticate("192.0.2.4", "alice", "Test-Only-Strong-Password-724")[0], "rate_limited")

    def test_mac_detects_data_changes(self):
        key = os.urandom(32)
        original = base64.b64encode(b"hello").decode()
        self.assertNotEqual(req_mac(key, 1, original), req_mac(key, 1, base64.b64encode(b"hallo").decode()))
        self.assertNotEqual(req_mac(key, 1, original), req_mac(key, 2, original))
        self.assertNotEqual(ack_mac(key, 1, 5, "sha"), ack_mac(key, 1, 4, "sha"))

    def test_log_analyzer_filters(self):
        with tempfile.TemporaryDirectory() as path:
            file = Path(path)/"events.jsonl"
            rows = [{"ts":"2026-11-27T10:00:00+00:00","event":"auth.failed","peer":"127.0.0.1","username":"alice"}] * 3
            rows.append({"ts":"2026-11-27T10:01:00+00:00","event":"data.accepted","peer":"127.0.0.1","username":"bob"})
            file.write_text("\n".join(json.dumps(x) for x in rows)+"\n")
            result = summarize(file)
            self.assertEqual(result["events_analyzed"], 4)
            self.assertEqual(result["auth_failure_bursts_ge3"][0]["failures"], 3)
            self.assertEqual(summarize(file, user="bob")["events_analyzed"], 1)
            self.assertEqual(summarize(file, event="auth.failed")["events_analyzed"], 3)


class RealTlsIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="lr6-tls-tests-")
        cls.directory = Path(cls.work.name)
        env = os.environ.copy()
        env["LR6_LAB_DIR"] = str(cls.directory)
        subprocess.run(["bash", str(ROOT / "scripts" / "gencerts.sh")], check=True, capture_output=True, text=True, env=env)
        cls.ca = cls.directory/"certs/ca.crt"
        cls.users = cls.directory/"users.json"
        add_user(cls.users, "alice", "user", "Test-Only-Strong-Password-724")
        cls.server_log = cls.directory/"server.jsonl"
        cls.client_log = cls.directory/"client.jsonl"
        cls.server = TLSServer(("127.0.0.1", 0), str(cls.directory/"certs/server.crt"), str(cls.directory/"certs/server.key"), str(cls.users), str(cls.server_log))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=4)
        cls.work.cleanup()

    def setUp(self):
        with self.server.state.lock:
            self.server.state.failures.clear()
            self.server.state.sessions.clear()

    def contact(self, *, password="Test-Only-Strong-Password-724", body=b"hello TLS", server_name="localhost", ca=None, tamper=False):
        return exchange("127.0.0.1", self.port, server_name, str(ca or self.ca), "alice", password, body, tamper=tamper, log=str(self.client_log))

    def _connection(self):
        context = ssl.create_default_context(cafile=str(self.ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        secure = context.wrap_socket(raw, server_hostname="localhost")
        return secure

    def test_tls_verified_connection_and_ack(self):
        response = self.contact()
        self.assertTrue(response["auth"]["ok"])
        self.assertTrue(response["data"]["ok"])
        self.assertIn(response["tls"]["version"], ("TLSv1.2", "TLSv1.3"))
        self.assertTrue(response["tls"]["cipher"])
        self.assertEqual(response["data"]["sha256"], hashlib.sha256(b"hello TLS").hexdigest())

    def test_binary_file_content(self):
        body = b"\x00\xff\x01\x00"+b"text"*25
        result = self.contact(body=body)
        self.assertEqual(result["data"]["bytes"], len(body))

    def test_bad_password_rejected(self):
        result = self.contact(password="incorrect-long-password")
        self.assertEqual(result["auth"]["error"], "invalid_credentials")
        self.assertNotIn("data", result)

    def test_tamper_hmac_rejected(self):
        result = self.contact(tamper=True)
        self.assertFalse(result["data"]["ok"])
        self.assertEqual(result["data"]["error"], "bad_hmac")

    def test_wrong_hostname_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.contact(server_name="not-localhost.invalid")

    def test_wrong_trust_anchor_rejected(self):
        with tempfile.TemporaryDirectory() as path:
            fake = Path(path)/"fake.crt"
            subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-noenc","-subj","/CN=Fake Test CA","-days","1","-keyout",str(Path(path)/"fake.key"),"-out",str(fake)], check=True, capture_output=True)
            with self.assertRaises(ssl.SSLCertVerificationError):
                self.contact(ca=fake)

    def test_application_auth_required(self):
        with self._connection() as conn:
            conn.sendall(b'{"op":"data","payload_b64":"aGVsbG8="}\n')
            r = json.loads(conn.makefile("rb").readline())
            self.assertEqual(r["error"], "authentication_required")

    def test_invalid_json_rejected(self):
        with self._connection() as conn:
            conn.sendall(b'{invalid_json\n')
            r = json.loads(conn.makefile("rb").readline())
            self.assertEqual(r["error"], "invalid_json")

    def test_rate_limit_blocks_repeated_logins(self):
        for i in range(5):
            self.assertEqual(self.contact(password="incorrect-long-password")["auth"]["error"], "invalid_credentials")
        r = self.contact()
        self.assertEqual(r["auth"]["error"], "rate_limited")

    def test_oversized_data_rejected_before_send(self):
        with self.assertRaisesRegex(ValueError, "Payload limit"):
            self.contact(body=os.urandom(32769))

    def test_replay_and_invalid_token(self):
        with self._connection() as conn:
            fh = conn.makefile("rwb")
            def send(msg):
                fh.write((json.dumps(msg)+"\n").encode());fh.flush();return json.loads(fh.readline())
            auth = send({"op":"auth","username":"alice","password":"Test-Only-Strong-Password-724"})
            self.assertTrue(auth["ok"])
            key = base64.b64decode(auth["mac_key"])
            payload = base64.b64encode(b"hi").decode()
            request = {"op":"data","token":auth["token"],"seq":1,"payload_b64":payload,"hmac":req_mac(key,1,payload)}
            self.assertTrue(send(request)["ok"])
            self.assertEqual(send(request)["error"], "invalid_sequence")
            request.update(token="not-valid",seq=2,hmac=req_mac(key,2,payload))
            self.assertEqual(send(request)["error"], "invalid_token")

    def test_failed_tls_is_logged(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=4) as conn:
            conn.sendall(b"GET / HTTP/1.1\r\n\r\n")
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            if self.server_log.exists() and "tls.handshake_failed" in self.server_log.read_text():
                break
            time.sleep(.03)
        self.assertIn("tls.handshake_failed", self.server_log.read_text())

    def test_auth_and_tls_events_logged_without_secrets(self):
        self.contact(body=b"protected-secret-message-content")
        events = self.server_log.read_text()+self.client_log.read_text()
        self.assertIn("auth.succeeded", events)
        self.assertIn("tls.verified", events)
        self.assertNotIn("Test-Only-Strong-Password-724", events)
        self.assertNotIn("protected-secret-message-content", events)

if __name__ == "__main__":
    unittest.main()
