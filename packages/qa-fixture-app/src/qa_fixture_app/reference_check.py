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
import sys
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

# The documented seed, restated here on purpose (README, "Seeded data"): order id -> list of (qty, unit_cents).
DOCUMENTED_ORDERS = {"101": [(2, 4000), (1, 2500)], "102": [(1, 4999), (1, 5000)], "103": [(1, 10000)], "104": [(1, 10005)]}
DOCUMENTED_EMAIL, DOCUMENTED_PASSWORD = "alice@example.test", "correct horse"
CHECKS = ("discount-rule", "settings-persistence")


def expected_totals(lines: List[Tuple[int, int]]) -> Dict[str, int]:
    """10 percent off, rounded down to the cent, when the subtotal is at least 100.00; integers only."""
    subtotal = sum(q * u for q, u in lines)
    discount = (subtotal // 10) if subtotal >= 10000 else 0
    return {"subtotal_cents": subtotal, "discount_cents": discount, "total_cents": subtotal - discount}


class _Client:
    def __init__(self, base_url: str):
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

    def request(self, method: str, target: str, form: Optional[str] = None) -> Tuple[int, Dict[str, str], bytes]:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=10)      # no proxy: http.client never reads proxy variables
        try:
            headers = {"Cookie": self.cookie} if self.cookie else {}
            body = None
            if form is not None:
                body = form.encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            conn.request(method, target, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            if "set-cookie" in hdrs:
                self.cookie = hdrs["set-cookie"].split(";")[0]
            return resp.status, hdrs, data
        finally:
            conn.close()

    def json(self, target: str) -> Tuple[int, object]:
        status, _, data = self.request("GET", target)
        return status, json.loads(data)


def run_checks(base_url: str) -> Dict[str, object]:
    c = _Client(base_url)
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
