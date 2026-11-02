# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Plain-Python reference check: asks a running fixture app the two questions the seeded defects are about and says which answers
deviate from the documented behaviour.

It is deliberately independent of the app: it imports nothing from ``qa_fixture_app`` except this module's own code, restates the
documented seed data and rule in its own arithmetic and talks to the app over HTTP only. That is what makes it usable as a
reference when a test engine's verdict is compared with the truth (no circular proof). It changes the app's in-memory settings
(it saves one), so run it against an app instance you can throw away.

``python -m qa_fixture_app.reference_check URL`` prints ``{"deviations": [...], "checked": [...]}`` and exits 0 when nothing
deviates, 1 when something does, 2 when the app cannot be reached or the URL is not a loopback URL.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import sys
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

# The documented seed, restated here on purpose (README, "Seeded data"): order id -> list of (qty, unit_cents).
DOCUMENTED_ORDERS = {"101": [(2, 4000), (1, 2500)], "102": [(1, 4999), (1, 5000)], "103": [(1, 10000)], "104": [(1, 10005)]}
DOCUMENTED_EMAIL, DOCUMENTED_PASSWORD = "alice@example.test", "correct horse"
CHECKS = ("discount-rule", "settings-persistence")
MAX_RESPONSE_BYTES = 1024 * 1024          # one response of the app; the documented answers are a few hundred bytes
DEADLINE_SECONDS = 30.0                   # the whole check, not one socket operation


class CheckAborted(OSError):
    """The check ran out of time, was cancelled, or an answer was larger than the cap: nothing it saw is a result."""


def expected_totals(lines: List[Tuple[int, int]]) -> Dict[str, int]:
    """10 percent off, rounded down to the cent, when the subtotal is at least 100.00; integers only."""
    subtotal = sum(q * u for q, u in lines)
    discount = (subtotal // 10) if subtotal >= 10000 else 0
    return {"subtotal_cents": subtotal, "discount_cents": discount, "total_cents": subtotal - discount}


class _Client:
    def __init__(self, base_url: str, *, max_bytes: int = MAX_RESPONSE_BYTES, deadline_s: float = DEADLINE_SECONDS, cancelled: Optional[Callable[[], bool]] = None):
        parts = urlsplit(base_url)
        host = parts.hostname or ""
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if parts.scheme != "http" or not loopback or parts.port is None:
            raise ValueError("the reference check talks to a loopback http URL with a port only, got %r" % base_url)
        self.host, self.port = host, parts.port
        self.cookie = ""
        self.max_bytes, self.cancelled = max_bytes, cancelled
        self.end = time.monotonic() + deadline_s
        self.stop_reason: Optional[str] = None
        self._conn: Optional[http.client.HTTPConnection] = None
        self._done = threading.Event()
        threading.Thread(target=self._watch, name="reference-check-watch", daemon=True).start()

    def _watch(self) -> None:
        """Ends the connection in use when the total deadline passes or the run is cancelled: a blocked socket read cannot notice either by itself (a server that sends a byte every few seconds
        would keep every per-operation timeout from firing)."""
        while not self._done.wait(0.1):
            if time.monotonic() > self.end:
                self.stop_reason = "the total deadline passed"
            elif self.cancelled is not None and self.cancelled():
                self.stop_reason = "the run was cancelled"
            if self.stop_reason:
                conn = self._conn
                try:
                    if conn is not None and conn.sock is not None:
                        conn.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                return

    def close(self) -> None:
        self._done.set()

    def _check(self) -> None:
        if self.stop_reason or time.monotonic() > self.end or (self.cancelled is not None and self.cancelled()):
            raise CheckAborted(self.stop_reason or "the total deadline passed or the run was cancelled")

    def request(self, method: str, target: str, form: Optional[str] = None) -> Tuple[int, Dict[str, str], bytes]:
        self._check()
        conn = http.client.HTTPConnection(self.host, self.port, timeout=max(0.1, min(10.0, self.end - time.monotonic())))      # no proxy: http.client never reads proxy variables
        self._conn = conn
        try:
            headers = {"Cookie": self.cookie} if self.cookie else {}
            body = None
            if form is not None:
                body = form.encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            try:
                conn.request(method, target, body=body, headers=headers)
                resp = conn.getresponse()
                chunks, total = [], 0
                while True:
                    block = resp.read1(65536)
                    if not block:
                        break
                    total += len(block)
                    if total > self.max_bytes:
                        raise CheckAborted("an answer is larger than %d bytes" % self.max_bytes)
                    chunks.append(block)
                    self._check()
                self._check()                          # a connection ended by the watcher looks like a clean end of the answer: it is not one
                if resp.length:
                    raise CheckAborted("an answer ended before its declared length")
                data = b"".join(chunks)
            except (OSError, http.client.HTTPException):
                self._check()                      # a connection ended by the watcher is reported as what it was
                raise
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            if "set-cookie" in hdrs:
                self.cookie = hdrs["set-cookie"].split(";")[0]
            return resp.status, hdrs, data
        finally:
            conn.close()
            self._conn = None

    def json(self, target: str) -> Tuple[int, object]:
        status, _, data = self.request("GET", target)
        return status, json.loads(data)


def run_checks(base_url: str, *, max_bytes: int = MAX_RESPONSE_BYTES, deadline_s: float = DEADLINE_SECONDS, cancelled: Optional[Callable[[], bool]] = None) -> Dict[str, object]:
    """The check, bounded: no answer larger than ``max_bytes``, the whole run within ``deadline_s`` (not per socket operation), and ``cancelled()`` (when given) ends it between and during requests.
    ``CheckAborted`` (an ``OSError``) is raised for any of the three."""
    c = _Client(base_url, max_bytes=max_bytes, deadline_s=deadline_s, cancelled=cancelled)
    try:
        return _run(c)
    finally:
        c.close()


def _run(c: "_Client") -> Dict[str, object]:
    deviations: List[Dict[str, object]] = []

    for order_id, lines in sorted(DOCUMENTED_ORDERS.items()):
        status, body = c.json("/api/orders/" + order_id)
        want = expected_totals(lines)
        got = {k: body.get(k) for k in want} if isinstance(body, dict) else body
        if status != 200 or got != want:
            deviations.append({"check": "discount-rule", "where": "/api/orders/" + order_id, "expected": want, "actual": got})
    for subtotal in (9999, 10000, 10005, 10500):
        status, body = c.json("/api/discount?subtotal_cents=%d" % subtotal)
        want_discount = expected_totals([(1, subtotal)])["discount_cents"]
        got_discount = body.get("discount_cents") if isinstance(body, dict) else body
        if status != 200 or got_discount != want_discount:
            deviations.append({"check": "discount-rule", "where": "/api/discount?subtotal_cents=%d" % subtotal,
                               "expected": want_discount, "actual": got_discount})

    status, _, _ = c.request("POST", "/login", "email=%s&password=%s" % (DOCUMENTED_EMAIL.replace("@", "%40"), DOCUMENTED_PASSWORD.replace(" ", "+")))
    if status != 303 or not c.cookie:
        deviations.append({"check": "settings-persistence", "where": "/login", "expected": "303 and a session cookie", "actual": status})
    else:
        want_settings = {"notifications": True, "theme": "dark"}
        status, _, _ = c.request("POST", "/settings", "notifications=1&theme=dark")
        _, after = c.json("/api/me/settings")
        if status != 303 or after != want_settings:
            deviations.append({"check": "settings-persistence", "where": "/api/me/settings after POST /settings",
                               "expected": want_settings, "actual": after})
    return {"checked": list(CHECKS), "deviations": deviations}


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        sys.stderr.write("usage: python -m qa_fixture_app.reference_check http://127.0.0.1:PORT\n")
        return 2
    try:
        result = run_checks(argv[0])
    except (ValueError, OSError, http.client.HTTPException) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    sys.stdout.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return 1 if result["deviations"] else 0


if __name__ == "__main__":
    sys.exit(main())
