# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Shared helpers of the fixture-app tests: the fixed request scenario, its byte-exact rendering, and a subprocess launcher."""
import contextlib
import http.client
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

PKG = Path(__file__).resolve().parents[1]
SRC = PKG / "src"
GOLDEN = Path(__file__).resolve().parent / "golden"
MODES = ("none", "discount", "settings")

# (step id, method, target, form body or None). One fixed scenario; the numeric prefix is the golden file prefix. The cookie jar
# (the session started by the successful login) is sent on every later request, as a browser would.
SCENARIO: List[Tuple[str, str, str, Optional[str]]] = [
    ("health", "GET", "/health", None),
    ("index", "GET", "/", None),
    ("favicon", "GET", "/favicon.ico", None),
    ("login-page", "GET", "/login", None),
    ("account-anonymous", "GET", "/account", None),
    ("settings-anonymous", "GET", "/settings", None),
    ("api-settings-anonymous", "GET", "/api/me/settings", None),
    ("settings-post-anonymous", "POST", "/settings", "theme=dark"),
    ("login-wrong-password", "POST", "/login", "email=alice%40example.test&password=wrong"),
    ("login-wrong-password-page", "GET", "/login?bad=1", None),
    ("login-ok", "POST", "/login", "email=alice%40example.test&password=correct+horse"),
    ("account", "GET", "/account", None),
    ("settings-initial", "GET", "/settings", None),
    ("api-settings-initial", "GET", "/api/me/settings", None),
    ("settings-invalid-theme", "POST", "/settings", "theme=purple"),
    ("settings-save", "POST", "/settings", "notifications=1&theme=dark"),
    ("settings-saved-page", "GET", "/settings?saved=1", None),
    ("api-settings-saved", "GET", "/api/me/settings", None),
    ("settings-reload", "GET", "/settings", None),
    ("orders-page", "GET", "/orders", None),
    ("order-page-101", "GET", "/orders/101", None),
    ("order-page-102", "GET", "/orders/102", None),
    ("order-page-103", "GET", "/orders/103", None),
    ("order-page-104", "GET", "/orders/104", None),
    ("order-page-missing", "GET", "/orders/999", None),
    ("api-orders", "GET", "/api/orders", None),
    ("api-order-101", "GET", "/api/orders/101", None),
    ("api-order-102", "GET", "/api/orders/102", None),
    ("api-order-103", "GET", "/api/orders/103", None),
    ("api-order-104", "GET", "/api/orders/104", None),
    ("api-order-missing", "GET", "/api/orders/999", None),
    ("api-discount-9999", "GET", "/api/discount?subtotal_cents=9999", None),
    ("api-discount-10000", "GET", "/api/discount?subtotal_cents=10000", None),
    ("api-discount-10005", "GET", "/api/discount?subtotal_cents=10005", None),
    ("api-discount-10500", "GET", "/api/discount?subtotal_cents=10500", None),
    ("api-discount-0", "GET", "/api/discount?subtotal_cents=0", None),
    ("api-discount-invalid", "GET", "/api/discount?subtotal_cents=abc", None),
    ("api-discount-missing", "GET", "/api/discount", None),
    ("not-found", "GET", "/nope", None),
    ("not-found-api", "GET", "/api/nope", None),
    ("api-order-nested", "GET", "/api/orders/101/lines", None),
    ("post-not-found", "POST", "/nope", "a=1"),
    ("post-health", "POST", "/health", "a=1"),
    ("head-health", "HEAD", "/health", None),
    ("put-settings", "PUT", "/settings", "theme=dark"),
]
STEP_IDS = [s[0] for s in SCENARIO]


def golden_name(index: int, step_id: str) -> str:
    return "%02d-%s.http" % (index + 1, step_id)


def run_scenario(base_url: str, scenario=SCENARIO) -> Dict[str, bytes]:
    """Play the scenario against ``base_url`` and return step id -> rendered, byte-exact transcript of request and response."""
    host, _, port = base_url[len("http://"):].partition(":")
    cookie = ""
    out: Dict[str, bytes] = {}
    for step_id, method, target, form in scenario:
        conn = http.client.HTTPConnection(host, int(port), timeout=10)
        try:
            headers = {"Cookie": cookie} if cookie else {}
            body = None
            if form is not None:
                body = form.encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            conn.request(method, target, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            resp_headers = resp.getheaders()
            status = resp.status
        finally:
            conn.close()
        for k, v in resp_headers:
            if k.lower() == "set-cookie":
                cookie = v.split(";")[0]
        head = ["%s %s" % (method, target)] + (["form: " + form] if form is not None else []) + ["--- %d" % status]
        head += ["%s: %s" % kv for kv in resp_headers]
        out[step_id] = ("\n".join(head) + "\n\n").encode("utf-8") + data
    return out


def read_golden(mode: str) -> Dict[str, bytes]:
    """The expected transcript of a mode: the base files of ``none``, overlaid by the files of the mode (only what differs)."""
    base = {sid: (GOLDEN / "none" / golden_name(i, sid)).read_bytes() for i, sid in enumerate(STEP_IDS)}
    if mode != "none":
        for i, sid in enumerate(STEP_IDS):
            path = GOLDEN / mode / golden_name(i, sid)
            if path.exists():
                base[sid] = path.read_bytes()
    return base


def child_env(**extra: str) -> Dict[str, str]:
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(SRC), "PYTHONDONTWRITEBYTECODE": "1", "LANG": "C.UTF-8"}
    for name in ("SYSTEMROOT", "TMPDIR", "TEMP"):
        if name in os.environ:
            env[name] = os.environ[name]
    env.update(extra)
    return env


def run_cli(args: List[str], cwd: Path, timeout: float = 30) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "qa_fixture_app", *args], cwd=str(cwd), env=child_env(), capture_output=True, text=True,
                          timeout=timeout, stdin=subprocess.DEVNULL)


class Running:
    """A fixture-app subprocess that has printed its ready line."""

    def __init__(self, proc: subprocess.Popen, ready: dict):
        self.proc, self.ready = proc, ready

    @property
    def url(self) -> str:
        return self.ready["url"]

    @property
    def port(self) -> int:
        return self.ready["port"]


@contextlib.contextmanager
def spawn(cwd: Path, *args: str, defect: str = "none", port: str = "0") -> Iterator[Running]:
    proc = subprocess.Popen([sys.executable, "-m", "qa_fixture_app", "--port", port, "--defect", defect, *args], cwd=str(cwd),
                            env=child_env(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    watchdog = threading.Timer(60, proc.kill)       # a hung child must fail the test, never hang the run
    watchdog.start()
    try:
        line = proc.stdout.readline()
        if not line:
            raise AssertionError("no ready line; stderr: %s" % proc.stderr.read())
        yield Running(proc, json.loads(line))
    finally:
        watchdog.cancel()
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe is not None:
                pipe.close()
