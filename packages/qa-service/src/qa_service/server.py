# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The HTTP surface. One API (``/v1``) serves the browser UI (``/ui/``), scripts and other products; there is no second store.

Credentials, in the order they are tried: ``Authorization: Bearer <service token>`` (class ``service``: reads, estimates, starts runs that need no approval, cancels; never an approval, never
user management), ``Authorization: Basic`` with a local user (no cookie, no CSRF), and the ``qa_session`` cookie of a browser session (HttpOnly, SameSite=Strict; every write needs the session's
``X-CSRF-Token`` and an ``Origin`` that matches). Only ``/healthz``, ``/readyz``, the static ``/ui/`` files and the login call need no credential, and none of them carries data.

Roles of a local user: viewer (every read), operator (viewer + estimates, starting, approving and cancelling runs), admin (operator + targets, users, deleting runs). See docs/standalone/README.md
and release-state/qa-api-contract.md for every route and body."""
from __future__ import annotations

import base64
import binascii
import hmac
import http.cookies
import json
import re
import sys
import tarfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

from . import __version__, catalog
from .config import Config
from .runs import DEFECTS, EXIT_MEANING, PLANS, Busy, Refused, RunStore
from .sessions import Sessions
from .users import RANK, ROLES, UserError, UserStore

RUN = r"(r[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6})"
UI_DIR = Path(__file__).with_name("ui")
UI_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
HTML_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
COOKIE = "qa_session"
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".txt": "text/plain; charset=utf-8"}


class ApiError(Exception):
    def __init__(self, status: int, code: str, detail: str, headers: Optional[Dict[str, str]] = None, **extra: Any):
        super().__init__(detail)
        self.status, self.code, self.detail, self.headers, self.extra = status, code, detail, headers or {}, extra


class Principal:
    def __init__(self, kind: str, name: str, role: str, via: str, user_id: Optional[str] = None, csrf: Optional[str] = None, session: Optional[str] = None):
        self.kind, self.name, self.role, self.via, self.user_id, self.csrf, self.session = kind, name, role, via, user_id, csrf, session

    def at_least(self, role: str) -> bool:
        # the service credential works as an operator for staging and reading; it is never human (approvals) and never an admin of users
        rank = RANK["operator"] if self.kind == "service" else RANK[self.role]
        return rank >= RANK[role]

    @property
    def human(self) -> bool:
        return self.kind == "user"


class QAServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, cfg: Config, store: Optional[RunStore] = None):
        self.cfg = cfg
        self.store = store or RunStore(cfg)
        self.users = UserStore(cfg.data_dir)
        self.sessions = Sessions()
        self.failures: Dict[str, List[float]] = {}
        self.failures_lock = threading.Lock()
        self.static = {p.name: p for p in UI_DIR.iterdir() if p.is_file()} if UI_DIR.is_dir() else {}
        super().__init__((cfg.bind, cfg.port), Handler)

    def handle_error(self, request, client_address) -> None:     # a client that went away or timed out: one line, no traceback, nothing of the request
        print(json.dumps({"client": client_address[0], "event": "connection_error", "kind": type(sys.exc_info()[1]).__name__}, sort_keys=True), file=sys.stderr, flush=True)

    def too_many_failures(self, key: str) -> bool:
        now = time.time()
        with self.failures_lock:
            recent = [t for t in self.failures.get(key, []) if now - t < 60]
            self.failures[key] = recent
            return len(recent) >= 8

    def note_failure(self, key: str) -> None:
        with self.failures_lock:
            self.failures.setdefault(key, []).append(time.time())


class Handler(BaseHTTPRequestHandler):
    server: QAServer
    protocol_version = "HTTP/1.1"
    server_version = "redevops-qa-service"
    sys_version = ""

    # ------------------------------------------------------------------ plumbing
    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.server.cfg.request_timeout)

    def log_message(self, fmt: str, *args: Any) -> None:       # never the query string, never a header
        pass

    def _log(self, status: int) -> None:
        who = getattr(self, "principal", None)
        line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "client": self.client_address[0], "method": self.command, "path": urlsplit(self.path).path[:120], "status": status,
                "user": who.name if who else None}
        print(json.dumps(line, sort_keys=True), file=sys.stderr, flush=True)

    def _send(self, status: int, body: bytes = b"", ctype: str = "application/json", extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self._log(status)

    def _json(self, status: int, doc: Any, extra: Optional[Dict[str, str]] = None) -> None:
        self._send(status, (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8"), extra=extra)

    def _error(self, e: ApiError) -> None:
        doc = {"error": e.code, "detail": e.detail, "message": e.detail, "request_id": self.request_id}
        doc.update(e.extra)
        self._json(e.status, doc, e.headers)

    # ------------------------------------------------------------------ authentication
    def _principal(self) -> Principal:
        srv = self.server
        header = self.headers.get("Authorization", "")
        scheme, _, value = header.partition(" ")
        scheme = scheme.lower()
        deny = ApiError(401, "unauthenticated", "a valid credential is required", {"WWW-Authenticate": 'Bearer realm="redevops-qa"'})
        key = self.client_address[0]
        if scheme == "bearer" and value:
            if hmac.compare_digest(value.strip().encode("utf-8", "replace"), srv.cfg.token):
                return Principal("service", "service", "service", "service")
            time.sleep(0.25)                                   # a failed guess costs the guesser time
            raise deny
        if scheme == "basic" and value:
            if srv.too_many_failures(key):
                raise ApiError(429, "too_many_attempts", "too many failed sign-ins; wait a minute")
            try:
                name, _, password = base64.b64decode(value.strip()).decode("utf-8").partition(":")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                raise deny from None
            user = srv.users.authenticate(name, password)
            if user is None:
                srv.note_failure(key)
                time.sleep(0.25)
                raise deny
            return Principal("user", user["name"], user["role"], "basic", user["user_id"])
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            raise deny from None
        if COOKIE in cookie:
            sess = srv.sessions.get(cookie[COOKIE].value)
            user = srv.users.get(sess["user_id"]) if sess else None
            if sess and user and not user["disabled"]:
                return Principal("user", user["name"], user["role"], "session", user["user_id"], csrf=sess["csrf"], session=cookie[COOKIE].value)
        raise deny

    def _check_csrf(self, p: Principal) -> None:
        if p.via != "session" or self.command in ("GET", "HEAD"):
            return
        sent = self.headers.get("X-CSRF-Token", "")
        if not sent or not hmac.compare_digest(sent.encode("utf-8", "replace"), (p.csrf or "").encode()):
            raise ApiError(403, "csrf_required", "a write from a browser session needs the session's X-CSRF-Token")
        origin = self.headers.get("Origin")
        host = self.headers.get("Host", "")
        if origin is not None and urlsplit(origin).netloc != host:
            raise ApiError(403, "csrf_required", "the Origin of the request is not this service")

    def need(self, p: Principal, role: str) -> None:
        if not p.at_least(role):
            raise ApiError(403, "forbidden", f"this needs the {role} role")

    def need_human(self, p: Principal, role: str = "operator") -> None:
        if not p.human or not p.at_least(role):
            raise ApiError(403, "forbidden", f"a decision needs a signed-in user with the {role} role; the service token never decides")

    # ------------------------------------------------------------------ body
    def _body(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > self.server.cfg.max_body:
            self.close_connection = True
            raise ApiError(413 if length > 0 else 400, "bad_body", f"the body must be JSON of at most {self.server.cfg.max_body} bytes")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "bad_body", "the body is not JSON") from None
        if not isinstance(doc, dict):
            raise ApiError(400, "bad_body", "the body must be a JSON object")
        return doc

    # ------------------------------------------------------------------ dispatch
    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def do_DELETE(self) -> None:
        self._dispatch()

    def do_PATCH(self) -> None:
        self._dispatch()

    def do_PUT(self) -> None:
        self._dispatch()

    def _dispatch(self) -> None:
        self.request_id = uuid.uuid4().hex[:16]
        url = urlsplit(self.path)
        path, query = url.path, {k: v[0] for k, v in parse_qs(url.query).items()}
        try:
            if self.command in ("GET", "HEAD"):
                if path == "/healthz":
                    return self._json(200, {"status": "ok"})
                if path == "/readyz":
                    return self._ready()
                if path == "/":
                    return self._send(302, b"", "text/plain", {"Location": "/ui/"})
                if path == "/ui" or path.startswith("/ui/"):
                    return self._static(path)
            if path == "/v1/session" and self.command == "POST":
                return self._login()
            if path == "/v1/session" and self.command in ("GET", "HEAD"):
                try:
                    self.principal = self._principal()
                except ApiError:
                    return self._json(200, {"principal": None, "user": None, "csrf": None})     # "who am I" before signing in is an answer, not an error
                return self._session(self.principal, query)
            self.principal = self._principal()
            self._check_csrf(self.principal)
            handler = self._route(path)
            if handler is None:
                raise ApiError(404, "not_found", "no such path")
            fn, groups, methods = handler
            if self.command not in methods:
                raise ApiError(405, "method_not_allowed", "no such method on this path")
            fn(self.principal, query, *groups)
        except ApiError as e:
            self._error(e)
        except Refused as e:
            body = {"error": e.code, "detail": str(e), "message": str(e), "request_id": self.request_id, **e.extra}
            if e.unavailable is not None:
                body["unavailable"] = e.unavailable
            self._json(e.status, body)
        except Busy as e:
            self._error(ApiError(409, "busy", f"run {e.args[0]} is still going; one run at a time", active_run_id=e.args[0]))
        except catalog.CatalogError as e:
            self._error(ApiError(e.status, e.code, str(e), **e.extra))
        except UserError as e:
            self._error(ApiError({"not_found": 404, "exists": 409, "last_admin": 409}.get(e.code, 422), e.code, str(e)))
        except KeyError:
            self._error(ApiError(404, "not_found", "no such run"))

    def _route(self, path: str) -> Optional[Tuple[Callable, Tuple[str, ...], Tuple[str, ...]]]:
        table: List[Tuple[str, Callable, Tuple[str, ...]]] = [
            (r"/v1/info", self._info, ("GET", "HEAD")),
            (r"/v1/session", self._session, ("GET", "HEAD", "DELETE")),
            (r"/v1/users", self._users, ("GET", "HEAD", "POST")),
            (r"/v1/users/(usr-[0-9a-f]{8})", self._user, ("PATCH",)),
            (r"/v1/targets", self._targets, ("GET", "HEAD", "POST")),
            (r"/v1/targets/(tgt-[0-9a-f]{12})", self._target, ("GET", "HEAD", "DELETE")),
            (r"/v1/profiles", self._profiles, ("GET", "HEAD")),
            (r"/v1/estimates", self._estimates, ("POST",)),
            (r"/v1/runs", self._runs, ("GET", "HEAD", "POST")),
            (RUN_PATH("") , self._run, ("GET", "HEAD", "DELETE")),
            (RUN_PATH("/events"), self._events, ("GET", "HEAD")),
            (RUN_PATH("/output"), self._output, ("GET", "HEAD")),
            (RUN_PATH("/approval"), self._approval, ("POST",)),
            (RUN_PATH("/cancel"), self._cancel, ("POST",)),
            (RUN_PATH("/evidence"), self._evidence, ("GET", "HEAD")),
            (RUN_PATH(r"/evidence/files/([0-9]{1,4})"), self._evidence_file, ("GET", "HEAD")),
            (RUN_PATH("/verify"), self._verify, ("GET", "HEAD")),
            (RUN_PATH("/report"), self._report, ("GET", "HEAD")),
            (RUN_PATH(r"/bundle\.tar"), self._tar, ("GET", "HEAD")),
        ]
        for pattern, fn, methods in table:
            m = re.fullmatch(pattern, path)
            if m:
                return fn, m.groups(), methods
        return None

    # ------------------------------------------------------------------ probes and static files
    def _ready(self) -> None:
        import os
        problems = []
        try:
            probe = self.server.cfg.data_dir / "runs" / ".ready"
            probe.write_text("1", encoding="utf-8")
            probe.unlink()
        except OSError:
            problems.append("data_dir")
        if not os.access(self.server.cfg.cli, os.X_OK):
            problems.append("cli")
        if problems:
            return self._json(503, {"status": "not_ready", "failing": problems})
        self._json(200, {"status": "ready"})

    def _static(self, path: str) -> None:
        name = path[len("/ui"):].lstrip("/") or "index.html"
        f = self.server.static.get(name)
        if f is None:
            if "." in name.rsplit("/", 1)[-1] or ".." in name:            # a missing asset is a 404; any other path under /ui/ is a view of the single-page app
                return self._json(404, {"error": "not_found", "detail": "no such file", "request_id": self.request_id})
            f = self.server.static.get("index.html")
        if f is None:
            return self._json(404, {"error": "not_found", "detail": "the interface is not installed", "request_id": self.request_id})
        body = f.read_bytes()
        headers = {"Content-Security-Policy": UI_CSP, "X-Frame-Options": "DENY", "Cache-Control": "no-cache"}
        self._send(200, body, CONTENT_TYPES.get(f.suffix, "application/octet-stream"), headers)

    # ------------------------------------------------------------------ session and users
    def _login(self) -> None:
        srv = self.server
        key = self.client_address[0]
        if srv.too_many_failures(key):
            return self._error(ApiError(429, "too_many_attempts", "too many failed sign-ins; wait a minute"))
        try:
            doc = self._body()
            name, password = doc.get("username"), doc.get("password")
            if not isinstance(name, str) or not isinstance(password, str):
                raise ApiError(422, "invalid", "username and password are strings", field="username")
            user = srv.users.authenticate(name, password)
            if user is None:
                srv.note_failure(key)
                time.sleep(0.25)
                raise ApiError(401, "unauthenticated", "the user name or the password is wrong")
        except ApiError as e:
            return self._error(e)
        s = srv.sessions.create(user["user_id"])
        cookie = f"{COOKIE}={s['token']}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200" + ("; Secure" if self.headers.get("X-Forwarded-Proto") == "https" and False else "")
        self._json(200, {"user": UserStore.public(user), "csrf": s["csrf"]}, {"Set-Cookie": cookie})

    def _session(self, p: Principal, q: Dict[str, str]) -> None:
        if self.command == "DELETE":
            if p.session:
                self.server.sessions.revoke(p.session)
            return self._send(204, b"", "text/plain", {"Set-Cookie": f"{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
        user = self.server.users.get(p.user_id) if p.user_id else None
        self._json(200, {"principal": {"kind": p.kind, "name": p.name, "role": p.role if p.kind == "user" else "service", "via": p.via}, "user": UserStore.public(user) if user else None, "csrf": p.csrf})

    def _users(self, p: Principal, q: Dict[str, str]) -> None:
        self.need_human(p, "admin")
        if self.command == "POST":
            d = self._body()
            if set(d) - {"name", "role", "password", "display_name"}:
                raise ApiError(400, "unknown_field", "only name, role, password and display_name are accepted")
            user = self.server.users.add(d.get("name"), d.get("role"), d.get("password"), display_name=d.get("display_name", ""), created_by=p.name)
            return self._json(201, user)
        self._json(200, {"items": self.server.users.list(), "next_cursor": None})

    def _user(self, p: Principal, q: Dict[str, str], user_id: str) -> None:
        self.need_human(p, "admin")
        d = self._body()
        if set(d) - {"role", "disabled", "password"}:
            raise ApiError(400, "unknown_field", "only role, disabled and password are accepted")
        user = self.server.users.update(user_id, role=d.get("role"), disabled=d.get("disabled"), password=d.get("password"))
        if d.get("disabled") or "password" in d or "role" in d:
            self.server.sessions.revoke_user(user_id)
        self._json(200, user)

    # ------------------------------------------------------------------ info, targets, profiles, estimates
    def _info(self, p: Principal, q: Dict[str, str]) -> None:
        import platform
        store = self.server.store
        plans = store.availability()
        self._json(200, {"service": "redevops-qa-service", "version": __version__, "machine": platform.machine(), "defects": list(DEFECTS), "capabilities": store.facts.as_dict(),
                         "plans": {k: dict(plans[k], command=PLANS[k][0]) for k in sorted(PLANS)}, "profiles": store.profiles(), "levels": {"fixture_ceiling": "VERIFIED", "external_ceiling": "CORROBORATED"},
                         "run_timeout_seconds": self.server.cfg.run_timeout, "target": "the bundled fixture app, or an operator-registered loopback Edge Sentinel fixture target (its runs are not enabled in this release)",
                         "auth": {"users": self.server.users.count() > 0, "roles": list(ROLES)}})

    def _targets(self, p: Principal, q: Dict[str, str]) -> None:
        store = self.server.store
        if self.command == "POST":
            self.need_human(p, "admin")
            return self._json(201, store.targets.register(self._body(), user=p.name, estimate=store.estimator))
        self.need(p, "viewer")
        self._json(200, {"items": store.targets.list(), "next_cursor": None})

    def _target(self, p: Principal, q: Dict[str, str], target_id: str) -> None:
        store = self.server.store
        if self.command == "DELETE":
            self.need_human(p, "admin")
            store.targets.delete(target_id, in_use=store.uses_target(target_id))
            return self._send(204)
        t = store.targets.get(target_id)
        if t is None:
            raise ApiError(404, "not_found", "no such target")
        self._json(200, t)

    def _profiles(self, p: Principal, q: Dict[str, str]) -> None:
        store = self.server.store
        target = store.targets.get(q["target_id"]) if q.get("target_id") else None
        if q.get("target_id") and target is None:
            raise ApiError(404, "not_found", "no such target")
        self._json(200, {"items": store.profiles(target), "next_cursor": None})

    def _estimates(self, p: Principal, q: Dict[str, str]) -> None:
        self.need(p, "operator")
        d = self._body()
        if set(d) - {"target_id", "profile"}:
            raise ApiError(400, "unknown_field", "only target_id and profile are accepted")
        store = self.server.store
        target = store.targets.get(d.get("target_id") or catalog.FIXTURE_TARGET_ID)
        profile = d.get("profile")
        if target is None:
            raise ApiError(404, "not_found", "no such target")
        if not isinstance(profile, str) or profile not in catalog.PROFILES:
            raise ApiError(422, "invalid", "profile is one of " + ", ".join(sorted(catalog.PROFILES)), field="profile")
        if target["kind"] not in catalog.PROFILES[profile]["targets"]:
            raise ApiError(422, "invalid", f"profile {profile} does not run against a {target['kind']} target", field="profile")
        est = store.estimator.create(target, profile, store.profile_unavailable(profile, target))
        self._json(201, est)

    # ------------------------------------------------------------------ runs
    def _runs(self, p: Principal, q: Dict[str, str]) -> None:
        store = self.server.store
        if self.command == "POST":
            self.need(p, "operator")
            d = self._body()
            unknown = sorted(set(d) - {"plan", "defect", "target_id", "profile", "estimate_digest"})
            if unknown:
                raise ApiError(400, "unknown_field", "only plan, defect, target_id, profile and estimate_digest are accepted")
            for k in ("plan", "defect", "target_id", "profile", "estimate_digest"):
                if k in d and not isinstance(d[k], str):
                    raise ApiError(400, "bad_body", f"{k} is a string")
            if "profile" not in d and "plan" not in d:
                d["plan"] = "demo"
            rec = store.start(d.get("plan"), d.get("defect", "none"), target_id=d.get("target_id"), profile=d.get("profile"), estimate_digest=d.get("estimate_digest"), user=p.name, via=p.via)
            return self._json(202, rec, {"Location": "/v1/runs/" + rec["id"]})
        self.need(p, "viewer")
        try:
            limit = max(1, min(200, int(q.get("limit", "100"))))
        except ValueError:
            raise ApiError(422, "invalid", "limit is a number from 1 to 200", field="limit") from None
        res = store.list(limit, cursor=q.get("cursor"), state=q.get("state"), target_id=q.get("target_id"), profile=q.get("profile"), outcome=q.get("outcome"))
        self._json(200, {"runs": res["items"], **res})

    def _rec(self, run_id: str) -> Dict[str, Any]:
        return self.server.store.get(run_id)

    def _run(self, p: Principal, q: Dict[str, str], run_id: str) -> None:
        store = self.server.store
        if self.command == "DELETE":
            self.need(p, "admin") if p.kind == "user" else self.need(p, "operator")
            store.get(run_id)
            store.delete(run_id)
            return self._send(204)
        self.need(p, "viewer")
        self._json(200, self._rec(run_id))

    def _events(self, p: Principal, q: Dict[str, str], run_id: str) -> None:
        try:
            after, limit = max(0, int(q.get("after", "0"))), max(1, min(200, int(q.get("limit", "100"))))
        except ValueError:
            raise ApiError(422, "invalid", "after and limit are numbers", field="after") from None
        self._json(200, self.server.store.events(run_id, after, limit))

    def _output(self, p: Principal, q: Dict[str, str], run_id: str) -> None:
        self._rec(run_id)
        self._send(200, self.server.store.output(run_id), "text/plain; charset=utf-8")

    def _approval(self, p: Principal, q: Dict[str, str], run_id: str) -> None:
        self.need_human(p, "operator")
        d = self._body()
        if set(d) - {"approved", "estimate_digest", "rationale"} or not isinstance(d.get("approved"), bool) or not isinstance(d.get("estimate_digest"), str):
            raise ApiError(422, "invalid", "approved (boolean) and estimate_digest (string) are required; rationale is optional", field="approved")
        rec = self.server.store.approve(run_id, d["approved"], d["estimate_digest"], user=p.name, role=p.role, via=p.via, rationale=d.get("rationale", ""),
                                        two_person=bool(self.server.cfg.two_person))
        self._json(200, rec)

    def _cancel(self, p: Principal, q: Dict[str, str], run_id: str) -> None:
        self.need(p, "operator")
        self._json(200, self.server.store.cancel(run_id, p.name))

    def _bundle(self, run_id: str) -> Tuple[Dict[str, Any], Path]:
        rec = self._rec(run_id)
        bundle = self.server.store.bundle_dir(run_id)
        if rec.get("state") == "running" or bundle is None:
            raise ApiError(409, "no_bundle", "the run has not finished or wrote no evidence bundle (see /output)")
        return rec, bundle

    def _evidence(self, p: Principal, q: Dict[str, str], run_id: str) -> None:
        rec, bundle = self._bundle(run_id)
        code, out = self.server.store.command(["report", str(bundle), "--format", "json"])
        try:
            doc = json.loads(out.decode("utf-8")) if out else None
        except ValueError:
            doc = None
        if not doc or code not in (0, 1, 3, 4):
            raise ApiError(502, "evidence_unreadable", f"the report command exited {code} ({EXIT_MEANING.get(code, 'UNKNOWN')}); the evidence is not shown when it does not verify")
        summary, rec_doc = doc.get("summary") or {}, doc.get("recomputation") or {}
        external = rec["level_ceiling"] != "VERIFIED"
        self._json(200, {"run_id": run_id, "bundle_id": bundle.name, "level": rec.get("level"), "ceiling": rec["level_ceiling"], "outcome": rec.get("outcome"),
                         "independent_restatement": not external, "restatement_note": "an external target has no independent restatement: its assertions are corroborated by the engines only" if external
                         else "the fixture app's reference check restates the seed data and the rule independently of the engines for the assertions the plan ties to it",
                         "lanes": summary.get("lanes", []), "accounting": summary.get("accounting"), "assertions": summary.get("assertions", []), "manifest_digest": rec_doc.get("anchor", {}).get("recomputed_manifest_digest"),
                         "plan_digest": summary.get("plan_digest"), "verification": {"accepted": rec_doc.get("accepted"), "agreeing_assertions": rec_doc.get("agreeing_assertions"),
                         "findings": rec_doc.get("findings", []), "assurance": rec_doc.get("assurance")},
                         "files": [{"index": i, "path": f["path"], "role": f.get("role"), "size": f.get("size"), "sha256": f.get("digest")} for i, f in enumerate(doc.get("files", []))]})

    def _evidence_file(self, p: Principal, q: Dict[str, str], run_id: str, index: str) -> None:
        rec, bundle = self._bundle(run_id)
        code, out = self.server.store.command(["report", str(bundle), "--format", "json"])
        files = (json.loads(out.decode("utf-8")) if out else {}).get("files", [])
        i = int(index)
        if i >= len(files):
            raise ApiError(404, "not_found", "no such file")
        target = (bundle / files[i]["path"]).resolve()
        if bundle.resolve() not in target.parents or target.is_symlink() or not target.is_file():
            raise ApiError(404, "not_found", "no such file")
        if target.stat().st_size > 16 * 1024 * 1024:
            raise ApiError(413, "too_large", "the file is larger than 16 MiB; download the bundle instead")
        name = re.sub(r"[^A-Za-z0-9._-]", "_", target.name)[:80]
        self._send(200, target.read_bytes(), "application/octet-stream", {"Content-Disposition": f'attachment; filename="{name}"'})

    def _verify(self, p: Principal, q: Dict[str, str], run_id: str) -> None:
        rec, bundle = self._bundle(run_id)
        code, out = self.server.store.command(["verify", str(bundle), "--json"])
        try:
            parsed = json.loads(out.decode("utf-8")) if out else None
        except ValueError:
            parsed = None
        self._json(200, {"exit_code": code, "meaning": EXIT_MEANING.get(code, "UNKNOWN"), "result": parsed, "independent": "re-verification in a separate process by redevops-qa verify; the bundle stays the authority"})

    def _report(self, p: Principal, q: Dict[str, str], run_id: str) -> None:
        rec, bundle = self._bundle(run_id)
        fmt = q.get("format", "text")
        if fmt not in ("text", "json", "html"):
            raise ApiError(400, "bad_format", "format must be text, json or html")
        code, out = self.server.store.command(["report", str(bundle), "--format", fmt])
        if code not in (0, 1, 3, 4) or not out:
            raise ApiError(502, "report_failed", f"the report command exited {code} ({EXIT_MEANING.get(code, 'UNKNOWN')}); the evidence is not shown when it does not verify")
        if fmt == "html":
            return self._send(200, out, "text/html; charset=utf-8", {"Content-Security-Policy": HTML_CSP})
        self._send(200, out, "application/json" if fmt == "json" else "text/plain; charset=utf-8")

    def _tar(self, p: Principal, q: Dict[str, str], run_id: str) -> None:
        rec, bundle = self._bundle(run_id)
        self.send_response(200)
        self.send_header("Content-Type", "application/x-tar")
        self.send_header("Content-Disposition", f'attachment; filename="{bundle.name}.tar"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        with tarfile.open(fileobj=self.wfile, mode="w|") as tar:
            tar.add(str(bundle), arcname=bundle.name)
        self._log(200)


def RUN_PATH(suffix: str) -> str:
    return r"/v1/runs/" + RUN + suffix
