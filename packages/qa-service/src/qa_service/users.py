# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Named local users: the one identity this product has (design D.1). A user is a name, a role (viewer, operator, admin: a fixed set, no custom roles, no per-resource grants) and a scrypt
password hash, kept in ``users.json`` in the data directory (atomic write, mode 0600). Nothing here is SSO, a directory, a tenant or a policy language."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROLES = ("viewer", "operator", "admin")
RANK = {r: i for i, r in enumerate(ROLES)}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,39}$")
MIN_PASSWORD = 12
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1, "dklen": 32}
_DUMMY = None


class UserError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_password(password: str, *, params: Optional[Dict[str, int]] = None) -> str:
    p = params or SCRYPT
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=p["n"], r=p["r"], p=p["p"], dklen=p["dklen"], maxmem=128 * 1024 * 1024)
    return "scrypt$%d$%d$%d$%s$%s" % (p["n"], p["r"], p["p"], base64.b64encode(salt).decode(), base64.b64encode(key).decode())


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt, key = encoded.split("$")
        if scheme != "scrypt":
            return False
        want = base64.b64decode(key)
        got = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=len(want), maxmem=128 * 1024 * 1024)
        return hmac.compare_digest(got, want)
    except (ValueError, TypeError):
        return False


def _dummy() -> str:
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password("not-a-real-password-" + secrets.token_hex(8))
    return _DUMMY


def check_password_policy(password: Any) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD or len(password) > 256:
        raise UserError("weak_password", f"a password is {MIN_PASSWORD} to 256 characters (no other rule)")


class UserStore:
    def __init__(self, data_dir: Path):
        self.path = data_dir / "users.json"
        self._lock = threading.Lock()
        self._params = SCRYPT

    def _read(self) -> List[Dict[str, Any]]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))["users"]
        except (OSError, ValueError, KeyError):
            return []

    def _write(self, users: List[Dict[str, Any]]) -> None:
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"version": 1, "users": users}, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, self.path)

    @staticmethod
    def public(u: Dict[str, Any]) -> Dict[str, Any]:
        return {k: u[k] for k in ("user_id", "name", "display_name", "role", "created_at", "created_by", "disabled", "last_login_at")}

    def count(self) -> int:
        return len(self._read())

    def list(self) -> List[Dict[str, Any]]:
        return [self.public(u) for u in self._read()]

    def get_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        return next((u for u in self._read() if u["name"] == name), None)

    def get(self, user_id: str) -> Optional[Dict[str, Any]]:
        return next((u for u in self._read() if u["user_id"] == user_id), None)

    def add(self, name: str, role: str, password: str, *, display_name: str = "", created_by: str = "bootstrap") -> Dict[str, Any]:
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise UserError("invalid_name", "a user name is 3 to 40 characters: a-z, 0-9, '.', '_' and '-', starting with a letter or digit")
        if role not in ROLES:
            raise UserError("invalid_role", "role is one of " + ", ".join(ROLES))
        check_password_policy(password)
        encoded = hash_password(password, params=self._params)
        with self._lock:
            users = self._read()
            if any(u["name"] == name for u in users):
                raise UserError("exists", "a user with that name exists")
            user = {"user_id": "usr-" + secrets.token_hex(4), "name": name, "display_name": str(display_name)[:80] or name, "role": role, "password_hash": encoded, "created_at": _now(),
                    "created_by": created_by, "disabled": False, "last_login_at": None}
            users.append(user)
            self._write(users)
        return self.public(user)

    def update(self, user_id: str, *, role: Optional[str] = None, disabled: Optional[bool] = None, password: Optional[str] = None) -> Dict[str, Any]:
        if role is not None and role not in ROLES:
            raise UserError("invalid_role", "role is one of " + ", ".join(ROLES))
        if password is not None:
            check_password_policy(password)
        with self._lock:
            users = self._read()
            user = next((u for u in users if u["user_id"] == user_id), None)
            if user is None:
                raise UserError("not_found", "no such user")
            changing_admin = user["role"] == "admin" and not user["disabled"] and (role not in (None, "admin") or disabled is True)
            if changing_admin and sum(1 for u in users if u["role"] == "admin" and not u["disabled"]) <= 1:
                raise UserError("last_admin", "the last enabled admin cannot be demoted or disabled")
            if role is not None:
                user["role"] = role
            if disabled is not None:
                user["disabled"] = bool(disabled)
            if password is not None:
                user["password_hash"] = hash_password(password, params=self._params)
            self._write(users)
            return self.public(user)

    def authenticate(self, name: str, password: str) -> Optional[Dict[str, Any]]:
        """The user record for a right name and password, else ``None``. The same work is done for an unknown name, so the time does not say which names exist."""
        user = self.get_by_name(name) if isinstance(name, str) else None
        ok = verify_password(password if isinstance(password, str) else "", user["password_hash"] if user else _dummy())
        if not (user and ok) or user["disabled"]:
            return None
        with self._lock:
            users = self._read()
            for u in users:
                if u["user_id"] == user["user_id"]:
                    u["last_login_at"] = _now()
            self._write(users)
        return user
