"""Create and manage bcrypt-like memory-hard scrypt password verifiers without exposing passwords in argv."""
import argparse
import getpass
import json
import os
import tempfile
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security import USERNAME_RE, hash_password


def add_user(path, username, role, password):
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Username: 1..32 ASCII letters, digits, ._- only")
    if role not in ("user", "admin"):
        raise ValueError("Invalid role")
    path = Path(path)
    existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    if username in existing:
        raise ValueError("User already exists; no changes made")
    existing[username] = {"hash": hash_password(password), "role": role}
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmpname = tempfile.mkstemp(prefix="users-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(existing, out, indent=2, sort_keys=True)
            out.write("\n")
        os.replace(tmpname, path)
    finally:
        if os.path.exists(tmpname):
            os.unlink(tmpname)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("add-user", nargs="?")
    ap.add_argument("--username", required=True)
    ap.add_argument("--role", choices=["user", "admin"], default="user")
    ap.add_argument("--users", default="users.json")
    args = ap.parse_args()
    p1 = getpass.getpass("New password (hidden, >=12 UTF-8 bytes): ")
    p2 = getpass.getpass("Confirm password: ")
    if p1 != p2:
        ap.error("Passwords do not match")
    try:
        add_user(args.users, args.username, args.role, p1)
    except ValueError as exc:
        ap.error(str(exc))
    print(f"Created user {args.username!r} with role {args.role!r}; password not stored in plaintext")

if __name__ == "__main__":
    main()
