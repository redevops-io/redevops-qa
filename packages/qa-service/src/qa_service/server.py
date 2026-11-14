# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The HTTP surface. Every path but ``/healthz`` and ``/readyz`` needs ``Authorization: Bearer <token>``; the token is compared in constant time and is never logged.

    GET    /healthz                       process is up (no authentication, no information)
    GET    /readyz                        data directory writable and the redevops-qa command present (no authentication, no information beyond ready / not ready)
    GET    /v1/info                       version, plans and whether each can start in this image
    POST   /v1/runs                       {"plan": "demo|browser|robot|robot-not-enforced", "defect": "none|discount|settings"} -> 202; one run at a time (409 while busy)
    GET    /v1/runs                       the newest runs
    GET    /v1/runs/<id>                  state, exit code, outcome
    GET    /v1/runs/<id>/output           what the command printed
    GET    /v1/runs/<id>/report?format=text|json|html     `redevops-qa report` of the evidence bundle (it re-verifies the bundle first)
    GET    /v1/runs/<id>/verify           `redevops-qa verify --json` of the evidence bundle
    GET    /v1/runs/<id>/bundle.tar       the evidence bundle, for `redevops-qa verify` elsewhere
    DELETE /v1/runs/<id>                  remove a run that is not going
"""
from __future__ import annotations

import hmac
import json
import re
import sys
import tarfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .config import Config
from .runs import DEFECTS, EXIT_MEANING, PLANS, Busy, Refused, RunStore

RUN_PATH = re.compile(r"^/v1/runs/(r[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6})(?:/(output|report|verify|bundle\.tar))?$")
HTML_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


class QAServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, cfg: Config, store: Optional[RunStore] = None):
        self.cfg = cfg
        self.store = store or RunStore(cfg)
        super().__init__((cfg.bind, cfg.port), Handler)

    def handle_error(self, request, client_address) -> None:     # a client that went away or timed out: one line, no traceback, nothing of the request
        print(json.dumps({"client": client_address[0], "event": "connection_error", "kind": type(sys.exc_info()[1]).__name__}, sort_keys=True), file=sys.stderr, flush=True)


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
        line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "client": self.client_address[0], "method": self.command, "path": urlsplit(self.path).path[:120], "status": status}
        print(json.dumps(line, sort_keys=True), file=sys.stderr, flush=True)

    def _send(self, status: int, body: bytes = b"", ctype: str = "application/json", extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self._log(status)

    def _json(self, status: int, doc: Any, extra: Optional[Dict[str, str]] = None) -> None:
        self._send(status, (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8"), extra=extra)

    def _error(self, status: int, code: str, message: str, extra: Optional[Dict[str, str]] = None) -> None:
        self._json(status, {"error": code, "message": message}, extra)

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        scheme, _, value = header.partition(" ")
        ok = scheme.lower() == "bearer" and bool(value) and hmac.compare_digest(value.strip().encode("utf-8", "replace"), self.server.cfg.token)
        if not ok:
            time.sleep(0.25)                                   # a failed guess costs the guesser time
            self._error(401, "unauthorized", "a valid bearer token is required", {"WWW-Authenticate": 'Bearer realm="redevops-qa"'})
        return ok

    def _body(self) -> Optional[Dict[str, Any]]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > self.server.cfg.max_body:
            self._error(413 if length > 0 else 400, "bad_body", f"the body must be JSON of at most {self.server.cfg.max_body} bytes")
            self.close_connection = True
            return None
        raw = self.rfile.read(length) if length else b"{}"
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._error(400, "bad_body", "the body is not JSON")
            return None
        if not isinstance(doc, dict):
            self._error(400, "bad_body", "the body must be a JSON object")
            return None
        return doc

    # ------------------------------------------------------------------ verbs
    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        path = url.path
        if path == "/healthz":
            return self._json(200, {"status": "ok"})
        if path == "/readyz":
            return self._ready()
        if not self._authorized():
            return
        if path == "/v1/info":
            return self._info()
        if path == "/v1/runs":
            return self._json(200, {"runs": self.server.store.list()})
        m = RUN_PATH.match(path)
        if not m:
            return self._error(404, "not_found", "no such path")
        run_id, sub = m.group(1), m.group(2)
        try:
            record = self.server.store.get(run_id)
        except KeyError:
            return self._error(404, "not_found", "no such run")
        if sub is None:
            return self._json(200, record)
        if sub == "output":
            return self._send(200, self.server.store.output(run_id), "text/plain; charset=utf-8")
        bundle = self.server.store.bundle_dir(run_id)
        if record.get("state") == "running" or bundle is None:
            return self._error(409, "no_bundle", "the run has not finished or wrote no evidence bundle (see /output)")
        if sub == "bundle.tar":
            return self._tar(bundle)
        if sub == "verify":
            code, out = self.server.store.command(["verify", str(bundle), "--json"])
            try:
                parsed = json.loads(out.decode("utf-8")) if out else None
            except ValueError:
                parsed = None
            return self._json(200, {"exit_code": code, "meaning": EXIT_MEANING.get(code, "UNKNOWN"), "result": parsed})
        fmt = parse_qs(url.query).get("format", ["text"])[0]
        if fmt not in ("text", "json", "html"):
            return self._error(400, "bad_format", "format must be text, json or html")
        code, out = self.server.store.command(["report", str(bundle), "--format", fmt])
        if code not in (0, 1, 3, 4) or not out:
            return self._error(502, "report_failed", f"the report command exited {code} ({EXIT_MEANING.get(code, 'UNKNOWN')}); the evidence is not shown when it does not verify")
        if fmt == "html":
            return self._send(200, out, "text/html; charset=utf-8", {"Content-Security-Policy": HTML_CSP})
        return self._send(200, out, "application/json" if fmt == "json" else "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        if not self._authorized():
            return
        if urlsplit(self.path).path != "/v1/runs":
            return self._error(404, "not_found", "no such path")
        doc = self._body()
        if doc is None:
            return
        unknown = sorted(set(doc) - {"plan", "defect"})
        if unknown:
            return self._error(400, "unknown_field", "only plan and defect are accepted")
        plan, defect = doc.get("plan", "demo"), doc.get("defect", "none")
        if not isinstance(plan, str) or not isinstance(defect, str):
            return self._error(400, "bad_body", "plan and defect are strings")
        try:
            record = self.server.store.start(plan, defect)
        except Refused as exc:
            if exc.unavailable is not None:
                return self._json(422, {"error": exc.code, "message": str(exc), "unavailable": exc.unavailable})
            return self._error(400, exc.code, str(exc))
        except Busy as exc:
            return self._error(409, "busy", f"run {exc.args[0]} is still going; one run at a time")
        self._json(202, record, {"Location": "/v1/runs/" + record["id"]})

    def do_DELETE(self) -> None:
        if not self._authorized():
            return
        m = RUN_PATH.match(urlsplit(self.path).path)
        if not m or m.group(2):
            return self._error(404, "not_found", "no such path")
        try:
            self.server.store.delete(m.group(1))
        except KeyError:
            return self._error(404, "not_found", "no such run")
        except Busy:
            return self._error(409, "busy", "the run is still going")
        self._send(204)

    def do_PUT(self) -> None:
        self._method_not_allowed()

    do_PATCH = do_PUT

    def _method_not_allowed(self) -> None:
        if self._authorized():
            self._error(405, "method_not_allowed", "no such method on this path")

    # ------------------------------------------------------------------ handlers
    def _ready(self) -> None:
        problems = []
        try:
            probe = self.server.cfg.data_dir / "runs" / ".ready"
            probe.write_text("1", encoding="utf-8")
            probe.unlink()
        except OSError:
            problems.append("data_dir")
        import os
        if not os.access(self.server.cfg.cli, os.X_OK):
            problems.append("cli")
        if problems:
            return self._json(503, {"status": "not_ready", "failing": problems})
        self._json(200, {"status": "ready"})

    def _info(self) -> None:
        import platform
        plans = self.server.store.availability()
        self._json(200, {"service": "redevops-qa-service", "version": __version__, "machine": platform.machine(), "defects": list(DEFECTS),
                         "capabilities": self.server.store.facts.as_dict(),
                         "plans": {k: dict(plans[k], command=PLANS[k][0]) for k in sorted(PLANS)}, "run_timeout_seconds": self.server.cfg.run_timeout,
                         "target": "the fixture app that ships with the runner (no external target)"})

    def _tar(self, bundle) -> None:
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
