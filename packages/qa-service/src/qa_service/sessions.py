# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Browser sessions: a random 256-bit token (only its sha256 is kept), a CSRF value per session, an idle and an absolute lifetime, a cap per user. In memory: a restart signs everyone out."""
from __future__ import annotations

import hashlib
import secrets
import threading
import time
from typing import Any, Dict, Optional

IDLE_S = 30 * 60
ABSOLUTE_S = 12 * 3600
MAX_PER_USER = 5


def _h(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Sessions:
    def __init__(self, clock=time.time):
        self._clock = clock
        self._by_hash: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def create(self, user_id: str) -> Dict[str, str]:
        token, csrf, now = secrets.token_urlsafe(32), secrets.token_urlsafe(24), self._clock()
        with self._lock:
            mine = sorted((s for s in self._by_hash.items() if s[1]["user_id"] == user_id), key=lambda kv: kv[1]["created"])
            for key, _ in mine[: max(0, len(mine) - MAX_PER_USER + 1)]:
                del self._by_hash[key]
            self._by_hash[_h(token)] = {"user_id": user_id, "csrf": csrf, "created": now, "last_seen": now}
        return {"token": token, "csrf": csrf}

    def get(self, token: str) -> Optional[Dict[str, Any]]:
        now = self._clock()
        with self._lock:
            s = self._by_hash.get(_h(token))
            if s is None:
                return None
            if now - s["last_seen"] > IDLE_S or now - s["created"] > ABSOLUTE_S:
                del self._by_hash[_h(token)]
                return None
            s["last_seen"] = now
            return dict(s)

    def revoke(self, token: str) -> None:
        with self._lock:
            self._by_hash.pop(_h(token), None)

    def revoke_user(self, user_id: str) -> None:
        with self._lock:
            for key in [k for k, v in self._by_hash.items() if v["user_id"] == user_id]:
                del self._by_hash[key]
