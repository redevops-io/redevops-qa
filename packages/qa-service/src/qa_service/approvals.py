# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Approvals that arrive from another product (Projects, Sidekick) on behalf of a person, and the links that say which local user that person is.

The token is the platform's signed, single-use approval token (``agentic_os.mission.approval``): ``b64url(payload_json) + "." + b64url(HMAC-SHA256(secret, payload))`` with a canonical-JSON payload
that binds ``operator``, ``capability``, ``inputs_sha256``, the approval ``marker``, ``exp`` and a random ``nonce``. This module verifies it with the standard library only (this service never imports
``agentic_os``) and fails closed: no secret configured, a bad signature, an expired token, other inputs, another operator or capability, a marker that disagrees with the request, or a nonce already used
all end in refusal. What a token proves is that Projects attests "a human clicked" for the principal named in ``marker.by``; what that person may do is decided by the local user they are linked to."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

OPERATOR = "redevops-qa"
CAPABILITY = "qa.approve_run"
INPUT_KEYS = ("run_id", "approved", "estimate_digest")
EXTERNAL_ACTOR_PREFIX = "projects:"


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def inputs_hash(inputs: Dict[str, Any]) -> str:
    """sha256 of the canonical JSON of the inputs, as the platform computes it (keys that start with ``approval`` and the runtime meta keys are not part of it)."""
    clean = {k: v for k, v in inputs.items() if not (isinstance(k, str) and k.lstrip("_").lower().startswith("approval")) and k not in ("_mission", "_goal", "_node")}
    return hashlib.sha256(_canonical(clean)).hexdigest()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class NonceStore:
    """Single-use nonces, kept until their token expires, and kept on the data volume so that a restart cannot replay a token."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._used: Dict[str, float] = {}
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                nonce, _, exp = line.partition(" ")
                self._used[nonce] = float(exp)
        except (OSError, ValueError):
            pass

    def consume(self, nonce: str, exp: float, now: float) -> bool:
        with self._lock:
            self._used = {n: e for n, e in self._used.items() if e > now}
            if nonce in self._used:
                return False
            self._used[nonce] = exp
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(f"{nonce} {exp}\n")
            return True


def verify_approval(secret: bytes, token: Any, *, run_id: str, approved: bool, estimate_digest: str, nonces: NonceStore, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """The marker iff the token fully verifies for exactly this run, decision and estimate digest, else ``None``. Never raises."""
    if not secret or not isinstance(token, str):
        return None
    t = time.time() if now is None else now
    try:
        p64, s64 = token.split(".")
        payload, sig = _unb64(p64), _unb64(s64)
        if not hmac.compare_digest(hmac.new(secret, payload, hashlib.sha256).digest(), sig):
            return None
        d = json.loads(payload)
        if not (isinstance(d, dict) and float(d["exp"]) > t) or d["operator"] != OPERATOR or d["capability"] != CAPABILITY:
            return None
        if d.get("mission_id") not in (None, "") or d.get("node_id") not in (None, ""):
            return None                                          # a token bound to a mission or node is for the runtime's operator contract, not for this route
        if not hmac.compare_digest(str(d["inputs_sha256"]), inputs_hash({"run_id": run_id, "approved": approved, "estimate_digest": estimate_digest})):
            return None
        marker = d["marker"]
        if not isinstance(marker, dict) or marker.get("approved") is not approved or marker.get("via") != "projects":
            return None
        by = marker.get("by")
        if not isinstance(by, str) or not by.startswith(EXTERNAL_ACTOR_PREFIX) or len(by) > 120 or len(by) == len(EXTERNAL_ACTOR_PREFIX):
            return None
        if not nonces.consume(str(d["nonce"]), float(d["exp"]), t):
            return None
        return marker
    except Exception:  # noqa: BLE001 - a malformed token of any shape fails closed
        return None


class ActorLinks:
    """``actor-links.json``: which local user an external actor (``projects:<principal>``) is. A link is made by an admin (for anyone) or by a signed-in user (for themself) and removed by an admin;
    with no link the external actor can read and stage but never decide (403 ``actor_not_linked``)."""

    def __init__(self, data_dir: Path):
        self.path = data_dir / "actor-links.json"
        self._lock = threading.Lock()

    def _read(self) -> Dict[str, Dict[str, str]]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))["links"]
        except (OSError, ValueError, KeyError):
            return {}

    def list(self) -> list:
        return [{"external_actor": k, **v} for k, v in sorted(self._read().items())]

    def get(self, external_actor: str) -> Optional[Dict[str, str]]:
        return self._read().get(external_actor)

    def put(self, external_actor: str, user_id: str, created_by: str) -> None:
        with self._lock:
            links = self._read()
            links[external_actor] = {"user_id": user_id, "created_by": created_by}
            self._write(links)

    def delete(self, external_actor: str) -> bool:
        with self._lock:
            links = self._read()
            if links.pop(external_actor, None) is None:
                return False
            self._write(links)
            return True

    def _write(self, links: Dict[str, Dict[str, str]]) -> None:
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"version": 1, "links": links}, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, self.path)
