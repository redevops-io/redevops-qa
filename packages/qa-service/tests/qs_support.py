# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Helpers of the qa-service tests: a real server on an ephemeral loopback port and a fake ``redevops-qa`` command (a small script) that writes what the real one writes
(an evidence directory) and exits with a status the test chooses. Nothing here starts a browser or reaches a host other than loopback."""
import json
import os
import stat
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

TOKEN = "t0ken-" + "Zx9Qw3Lm7Rk2Vb8Nc5Hd1Jf6Gs4Ap0Yu"      # a test token: generated for the test, 40 characters

FAKE_CLI = r'''#!%(python)s
import json, os, sys, time
a = sys.argv[1:]
cmd = a[0]
if cmd in ("run", "demo"):
    out = a[a.index("--out") + 1]
    run_id = a[a.index("--run-id") + 1]
    defect = a[a.index("--defect") + 1]
    control = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "control.json")))
    time.sleep(control.get("sleep", 0))
    os.makedirs(os.path.join(out, run_id))
    with open(os.path.join(out, run_id, "bundle-manifest.json"), "w") as fh:
        json.dump({"run": run_id, "defect": defect, "argv": a, "env": sorted(os.environ)}, fh)
    print("run %%s: VERIFIED (ALL_ASSERTIONS_VERIFIED)" %% run_id)
    sys.exit(control["exit"] if "exit" in control else (1 if defect != "none" else 0))
if cmd == "report":
    fmt = a[a.index("--format") + 1]
    body = {"text": "report text\n", "json": "{\"ok\": true}\n", "html": "<html><body>report</body></html>\n"}[fmt]
    sys.stdout.write(body)
    sys.exit(0)
if cmd == "verify":
    print(json.dumps({"ok": True, "assurance": "internally-consistent"}))
    sys.exit(0)
sys.exit(2)
'''


def make_env(tmp_path: Path, **extra):
    (tmp_path / "bin").mkdir(exist_ok=True)
    control = tmp_path / "bin" / "control.json"
    if not control.exists():
        control.write_text("{}")
    cli = tmp_path / "bin" / "redevops-qa"
    cli.parent.mkdir(exist_ok=True)
    cli.write_text(FAKE_CLI % {"python": sys.executable})
    cli.chmod(cli.stat().st_mode | stat.S_IXUSR)
    plans = tmp_path / "plans"
    plans.mkdir(exist_ok=True)
    for name in ("golden-plan.json", "robot-plan.json", "robot-plan-not-enforced.json"):
        (plans / name).write_text("{}")
    env = {"QA_SERVICE_TOKEN": TOKEN, "QA_SERVICE_BIND": "127.0.0.1", "QA_SERVICE_PORT": "0", "QA_SERVICE_DATA_DIR": str(tmp_path / "data"), "QA_SERVICE_CLI": str(cli),
           "QA_SERVICE_PLANS_DIR": str(plans), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    env.update(extra)
    return env


class Client:
    def __init__(self, port: int):
        self.base = f"http://127.0.0.1:{port}"

    def call(self, method, path, body=None, token=TOKEN, raw=None):
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read(), dict(exc.headers)

    def json(self, *a, **k):
        status, body, headers = self.call(*a, **k)
        return status, (json.loads(body) if body else None), headers
