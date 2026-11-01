# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The fixture application itself: seeded data, routes, pages and the one switchable defect.

``FixtureApp.handle`` is a pure function of the app state and the request: it reads no clock, uses no randomness and touches no
file or socket, so a response is byte-identical for the same sequence of requests in any process on any operating system. The HTTP
transport (``server.py``) only moves bytes in and out.

The application is a test target, not an example of how to write a secure application: there is no CSRF protection, the one
password is published in the documentation and session identifiers are a counter.
"""
from __future__ import annotations

import copy
import html
import json
import re
import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Mapping, Optional, Tuple
from urllib.parse import parse_qs

DEFECTS: Tuple[str, ...] = ("none", "discount", "settings")

DEFECT_DESCRIPTIONS: Dict[str, str] = {
    "none": "No defect: every behaviour follows the documented rules.",
    "discount": ("The order discount rule is not applied: discount_cents is always 0 and total_cents equals subtotal_cents, in the "
                 "orders API, on the order pages and in the discount rule endpoint. Nothing else changes."),
    "settings": ("Saving the user settings is acknowledged (redirect to /settings?saved=1, 'Settings saved' status) but nothing is "
                 "stored: the settings page and /api/me/settings keep showing the previous values. Nothing else changes."),
}

#: Business rule (documented in the README): 10 percent of the subtotal, rounded down to the cent, when the subtotal is at least
#: 100.00. Integer cents only.
DISCOUNT_THRESHOLD_CENTS = 10000
DISCOUNT_PERCENT = 10
RULE_TEXT = "10 percent of the subtotal, rounded down to the cent, when the subtotal is at least 10000 cents"

SESSION_COOKIE = "sid"
MAX_BODY_BYTES = 65536
THEMES = ("light", "dark")

# Seed data. Every FixtureApp starts from a deep copy of these, so no run can influence another.
_SEED_USERS = {
    "alice@example.test": {"password": "correct horse", "name": "alice", "settings": {"notifications": False, "theme": "light"}},
}
_SEED_ORDERS = {
    "101": [{"sku": "A-1", "qty": 2, "unit_cents": 4000}, {"sku": "B-2", "qty": 1, "unit_cents": 2500}],    # 10500: discount 1050
    "102": [{"sku": "A-1", "qty": 1, "unit_cents": 4999}, {"sku": "C-3", "qty": 1, "unit_cents": 5000}],    # 9999: just below the threshold
    "103": [{"sku": "D-4", "qty": 1, "unit_cents": 10000}],                                                  # 10000: exactly the threshold
    "104": [{"sku": "E-5", "qty": 1, "unit_cents": 10005}],                                                  # 10005: 1000.5 rounded down
}


@dataclass(frozen=True)
class Request:
    method: str
    target: str                     # the raw request target, path and query
    headers: Mapping[str, str] = field(default_factory=dict)      # lower-case names
    body: bytes = b""

    @property
    def path(self) -> str:
        return self.target.partition("?")[0]

    @property
    def query(self) -> Dict[str, List[str]]:
        return parse_qs(self.target.partition("?")[2], keep_blank_values=True)

    def query_value(self, name: str) -> Optional[str]:
        values = self.query.get(name)
        return values[0] if values else None

    @property
    def form(self) -> Dict[str, str]:
        return {k: v[0] for k, v in parse_qs(self.body.decode("utf-8", "replace"), keep_blank_values=True).items()}


@dataclass(frozen=True)
class Response:
    status: int
    headers: Tuple[Tuple[str, str], ...]
    body: bytes = b""

    @staticmethod
    def _standard(content_type: str) -> List[Tuple[str, str]]:
        return [("Content-Type", content_type), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff")]

    @classmethod
    def html(cls, status: int, title: str, body: str, extra: Tuple[Tuple[str, str], ...] = ()) -> "Response":
        page = ("<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>%s</title></head>\n<body>\n%s\n</body>\n</html>\n"
                % (html.escape(title), body))
        return cls(status, tuple(cls._standard("text/html; charset=utf-8")) + extra, page.encode("utf-8"))

    @classmethod
    def json(cls, status: int, value: object, extra: Tuple[Tuple[str, str], ...] = ()) -> "Response":
        text = json.dumps(value, sort_keys=True, indent=2) + "\n"
        return cls(status, tuple(cls._standard("application/json")) + extra, text.encode("utf-8"))

    @classmethod
    def redirect(cls, location: str, extra: Tuple[Tuple[str, str], ...] = ()) -> "Response":
        return cls(303, (("Location", location), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff")) + extra, b"")

    @classmethod
    def empty(cls, status: int) -> "Response":
        return cls(status, (("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff")), b"")


Handler = Callable[[Request], Response]


def money(cents: int) -> str:
    return "%d.%02d" % (cents // 100, cents % 100)


class FixtureApp:
    """One app instance is one process-worth of state: sessions and saved settings live here and nowhere else."""

    def __init__(self, defect: str = "none", extra_routes: Optional[Mapping[Tuple[str, str], Handler]] = None):
        if defect not in DEFECTS:
            raise ValueError("unknown defect %r; choose one of %s" % (defect, ", ".join(DEFECTS)))
        self.defect = defect
        self._users = copy.deepcopy(_SEED_USERS)
        self._orders = copy.deepcopy(_SEED_ORDERS)
        self._sessions: Dict[str, str] = {}
        self._session_counter = 0
        self._lock = threading.RLock()
        # Extension point (hostile-target pages, see the README): (METHOD, exact path) -> handler. Consulted before the built-in routes.
        self._extra = dict(extra_routes or {})
        self._routes: Dict[str, Dict[str, Handler]] = {
            "/": {"GET": self._index},
            "/health": {"GET": self._health},
            "/favicon.ico": {"GET": lambda r: Response.empty(204)},
            "/login": {"GET": self._login_page, "POST": self._login_submit},
            "/account": {"GET": self._account},
            "/settings": {"GET": self._settings_page, "POST": self._settings_submit},
            "/orders": {"GET": self._orders_page},
            "/api/me/settings": {"GET": self._api_settings},
            "/api/orders": {"GET": self._api_orders},
            "/api/discount": {"GET": self._api_discount},
        }

    # ------------------------------------------------------------------ rule

    def discount_cents(self, subtotal_cents: int) -> int:
        """The business rule. The ``discount`` defect is exactly this one early return."""
        if self.defect == "discount":
            return 0
        if subtotal_cents >= DISCOUNT_THRESHOLD_CENTS:
            return subtotal_cents * DISCOUNT_PERCENT // 100
        return 0

    def _order_summary(self, order_id: str) -> Dict[str, object]:
        lines = self._orders[order_id]
        subtotal = sum(line["qty"] * line["unit_cents"] for line in lines)
        discount = self.discount_cents(subtotal)
        return {"order_id": order_id, "lines": lines, "subtotal_cents": subtotal, "discount_cents": discount,
                "total_cents": subtotal - discount}

    # --------------------------------------------------------------- dispatch

    def handle(self, request: Request) -> Response:
        with self._lock:
            return self._handle(request)

    def _handle(self, request: Request) -> Response:
        method = "GET" if request.method == "HEAD" else request.method
        extra = self._extra.get((request.method, request.path))
        if extra is not None:
            return extra(request)
        path = request.path
        handlers = self._routes.get(path)
        if handlers is None:
            for prefix, handler in (("/api/orders/", self._api_order), ("/orders/", self._order_page)):
                if path.startswith(prefix) and "/" not in path[len(prefix):]:
                    handlers = {"GET": lambda r, h=handler, i=path[len(prefix):]: h(r, i)}
                    break
        if handlers is None:
            return self._error(request, 404, "not_found", "Not found")
        if method not in handlers:
            allowed = sorted(set(handlers) | ({"HEAD"} if "GET" in handlers else set()))
            return self._error(request, 405, "method_not_allowed", "Method not allowed", (("Allow", ", ".join(allowed)),))
        if method == "POST" and len(request.body) > MAX_BODY_BYTES:
            return self._error(request, 413, "payload_too_large", "Payload too large")
        return handlers[method](request)

    @staticmethod
    def _error(request: Request, status: int, code: str, title: str, extra: Tuple[Tuple[str, str], ...] = ()) -> Response:
        if request.path.startswith("/api/"):
            return Response.json(status, {"error": code}, extra)
        return Response.html(status, title, "<h1>%s</h1>" % html.escape(title), extra)

    # ----------------------------------------------------------------- session

    def _user(self, request: Request) -> Optional[Dict[str, object]]:
        for part in request.headers.get("cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE and value in self._sessions:
                return self._users[self._sessions[value]]
        return None

    # ------------------------------------------------------------------ pages

    def _index(self, request: Request) -> Response:
        return Response.html(200, "QA fixture app", (
            "<h1>QA fixture app</h1>\n<ul>\n<li><a href=\"/login\">Sign in</a></li>\n<li><a href=\"/settings\">Settings</a></li>\n"
            "<li><a href=\"/orders\">Orders</a></li>\n</ul>"))

    def _health(self, request: Request) -> Response:
        return Response.json(200, {"defect": self.defect, "status": "ok"})

    def _login_page(self, request: Request) -> Response:
        alert = "\n<p role=\"alert\">Wrong email or password</p>" if request.query_value("bad") == "1" else ""
        return Response.html(200, "Sign in", (
            "<h1>Sign in</h1>\n<form method=\"post\" action=\"/login\">\n<label for=\"email\">Email</label>\n"
            "<input id=\"email\" name=\"email\" type=\"text\">\n<label for=\"password\">Password</label>\n"
            "<input id=\"password\" name=\"password\" type=\"password\">\n<button type=\"submit\">Sign in</button>\n</form>" + alert))

    def _login_submit(self, request: Request) -> Response:
        form = request.form
        email = form.get("email", "")
        user = self._users.get(email)
        if user is None or user["password"] != form.get("password"):
            return Response.redirect("/login?bad=1")
        self._session_counter += 1
        sid = "sess-%04d" % self._session_counter
        self._sessions[sid] = email
        return Response.redirect("/account", (("Set-Cookie", "%s=%s; HttpOnly; Path=/; SameSite=Lax" % (SESSION_COOKIE, sid)),))

    def _account(self, request: Request) -> Response:
        user = self._user(request)
        if user is None:
            return Response.redirect("/login")
        return Response.html(200, "Account", "<h1>Welcome, %s</h1>\n<a href=\"/settings\">Settings</a>" % html.escape(str(user["name"])))

    def _settings_page(self, request: Request) -> Response:
        user = self._user(request)
        if user is None:
            return Response.redirect("/login")
        s = user["settings"]
        status = "\n<p role=\"status\" data-testid=\"save-status\">Settings saved</p>" if request.query_value("saved") == "1" else ""
        return Response.html(200, "Settings", (
            "<h1>Settings</h1>\n<form method=\"post\" action=\"/settings\">\n"
            "<label><input type=\"checkbox\" name=\"notifications\" value=\"1\"%s> Email notifications</label>\n"
            "<label for=\"theme\">Theme</label>\n<select id=\"theme\" name=\"theme\">\n<option value=\"light\"%s>light</option>\n"
            "<option value=\"dark\"%s>dark</option>\n</select>\n<button type=\"submit\">Save settings</button>\n</form>%s" % (
                " checked" if s["notifications"] else "", " selected" if s["theme"] == "light" else "",
                " selected" if s["theme"] == "dark" else "", status)))

    def _settings_submit(self, request: Request) -> Response:
        user = self._user(request)
        if user is None:
            return Response.redirect("/login")
        form = request.form
        theme = form.get("theme", "light")
        if theme not in THEMES:
            return Response.html(400, "Invalid settings", "<h1>Invalid settings</h1>\n<p role=\"alert\">Unknown theme</p>")
        if self.defect != "settings":       # seeded defect: the save is acknowledged below but nothing is stored
            user["settings"] = {"notifications": form.get("notifications") == "1", "theme": theme}
        return Response.redirect("/settings?saved=1")

    def _orders_page(self, request: Request) -> Response:
        items = []
        for order_id in sorted(self._orders):
            o = self._order_summary(order_id)
            items.append("<li><a href=\"/orders/%s\">Order %s</a>: total %s</li>" % (order_id, order_id, money(o["total_cents"])))
        return Response.html(200, "Orders", "<h1>Orders</h1>\n<ul>\n%s\n</ul>" % "\n".join(items))

    def _order_page(self, request: Request, order_id: str) -> Response:
        if order_id not in self._orders:
            return Response.html(404, "Order not found", "<h1>Order not found</h1>")
        o = self._order_summary(order_id)
        rows = "\n".join("<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>" % (
            html.escape(l["sku"]), l["qty"], money(l["unit_cents"]), money(l["qty"] * l["unit_cents"])) for l in o["lines"])
        return Response.html(200, "Order %s" % order_id, (
            "<h1>Order %s</h1>\n<table>\n<thead><tr><th>SKU</th><th>Qty</th><th>Unit</th><th>Line</th></tr></thead>\n<tbody>\n%s\n</tbody>\n</table>\n"
            "<dl>\n<dt>Subtotal</dt><dd data-testid=\"order-subtotal\">%s</dd>\n<dt>Discount</dt><dd data-testid=\"order-discount\">%s</dd>\n"
            "<dt>Total</dt><dd data-testid=\"order-total\">%s</dd>\n</dl>\n<a href=\"/orders\">All orders</a>" % (
                order_id, rows, money(o["subtotal_cents"]), money(o["discount_cents"]), money(o["total_cents"]))))

    # -------------------------------------------------------------------- API

    def _api_settings(self, request: Request) -> Response:
        user = self._user(request)
        if user is None:
            return Response.json(401, {"error": "unauthenticated"})
        return Response.json(200, user["settings"])

    def _api_orders(self, request: Request) -> Response:
        rows = []
        for order_id in sorted(self._orders):
            o = self._order_summary(order_id)
            rows.append({k: o[k] for k in ("order_id", "subtotal_cents", "discount_cents", "total_cents")})
        return Response.json(200, {"orders": rows})

    def _api_order(self, request: Request, order_id: str) -> Response:
        if order_id not in self._orders:
            return Response.json(404, {"error": "not_found"})
        return Response.json(200, self._order_summary(order_id))

    def _api_discount(self, request: Request) -> Response:
        raw = request.query_value("subtotal_cents")
        if raw is None or not re.fullmatch(r"[0-9]{1,9}", raw):
            return Response.json(400, {"error": "invalid_subtotal_cents"})
        subtotal = int(raw)
        discount = self.discount_cents(subtotal)
        return Response.json(200, {"discount_cents": discount, "rule": RULE_TEXT, "subtotal_cents": subtotal,
                                   "total_cents": subtotal - discount})
