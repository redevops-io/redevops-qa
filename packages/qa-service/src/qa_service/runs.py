# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Runs of the ``redevops-qa`` command, one at a time, and what they leave on disk.

Layout under the data directory::

    runs/<run id>/status.json     state, plan, defect, exit code (written atomically)
    runs/<run id>/output.txt      standard output and error of the command
    runs/<run id>/evidence/<id>/  the evidence bundle the command wrote

Only the plans listed in ``PLANS`` can be started, only against the fixture app that ships with the runner; there is no way to name a file, a URL or a target."""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import capabilities as caps
from .config import Config

RUN_ID_RE = re.compile(r"^r[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$")
DEFECTS = ("none", "discount", "settings")
PLANS = {k: v[:3] for k, v in caps.PLANS.items()}
#: the runner's exit status table (packages/qa-runner/README.md)
EXIT_MEANING = {0: "VERIFIED", 1: "FAILED", 2: "REFUSED", 3: "NOT_COMPLETED", 4: "INCONCLUSIVE", 5: "EVIDENCE_REJECTED", 6: "RUNNER_ERROR", 7: "VERIFIER_UNAVAILABLE"}
OUTPUT_LIMIT = 1 << 20


class Busy(Exception):
    pass


class Refused(Exception):
    def __init__(self, code: str, message: str, unavailable: Optional[Dict[str, str]] = None):
        super().__init__(message)
        self.code = code
        self.unavailable = unavailable


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("r%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)


class RunStore:
    def __init__(self, cfg: Config, facts: Optional[caps.Facts] = None):
        self.cfg = cfg
        self.facts = facts if facts is not None else caps.collect()
        self.root = cfg.data_dir / "runs"
        self._lock = threading.Lock()
        self._active: Optional[str] = None
        self.root.mkdir(parents=True, exist_ok=True)
        self._mark_interrupted()

    # ------------------------------------------------------------------ state files
    def _dir(self, run_id: str) -> Path:
        if not RUN_ID_RE.fullmatch(run_id):
            raise KeyError(run_id)
        return self.root / run_id

    def _write_status(self, run_id: str, record: Dict[str, Any]) -> None:
        d = self.root / run_id
        tmp = d / "status.json.tmp"
        tmp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, d / "status.json")

    def get(self, run_id: str) -> Dict[str, Any]:
        try:
            d = self._dir(run_id)
            return json.loads((d / "status.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise KeyError(run_id) from None

    def list(self, limit: int = 100) -> List[Dict[str, Any]]:
        ids = sorted((p.name for p in self.root.iterdir() if RUN_ID_RE.fullmatch(p.name)), reverse=True)[:limit]
        out = []
        for i in ids:
            try:
                out.append(self.get(i))
            except KeyError:
                continue
        return out

    def _mark_interrupted(self) -> None:
        """A run that was going when the service stopped cannot be resumed: say so instead of leaving it 'running' for ever."""
        for rec in self.list(10000):
            if rec.get("state") in ("running", "queued"):
                rec.update(state="interrupted", finished=_now(), note="the service stopped while this run was going; its evidence directory, if any, is incomplete")
                self._write_status(rec["id"], rec)

    def availability(self) -> Dict[str, Dict[str, Any]]:
        """plan -> {"available": bool, "unavailable": None | {"code", "reason", "remedy"}}"""
        out: Dict[str, Dict[str, Any]] = {}
        for name in PLANS:
            why = caps.unavailable(name, self.facts, self.cfg.plans_dir)
            out[name] = {"available": why is None, "unavailable": why}
        return out

    # ------------------------------------------------------------------ starting a run
    def start(self, plan: str, defect: str) -> Dict[str, Any]:
        if plan not in PLANS:
            raise Refused("unknown_plan", "plan must be one of: " + ", ".join(sorted(PLANS)))
        if defect not in DEFECTS:
            raise Refused("unknown_defect", "defect must be one of: " + ", ".join(DEFECTS))
        why = caps.unavailable(plan, self.facts, self.cfg.plans_dir)
        if why is not None:
            raise Refused("plan_unavailable", why["reason"], why)
        with self._lock:
            if self._active is not None:
                raise Busy(self._active)
            run_id = new_run_id()
            d = self.root / run_id
            d.mkdir(parents=True)
            (d / "evidence").mkdir()
            record = {"id": run_id, "plan": plan, "defect": defect, "state": "running", "created": _now(), "started": _now(), "finished": None, "exit_code": None, "outcome": None}
            self._write_status(run_id, record)
            self._active = run_id
        threading.Thread(target=self._run, args=(run_id, plan, defect), name="run-" + run_id, daemon=True).start()
        return record

    def _argv(self, run_id: str, plan: str, defect: str) -> List[str]:
        command, plan_file, _ = PLANS[plan]
        d = self.root / run_id
        argv = [self.cfg.cli, command]
        if plan_file is not None:
            argv.append(str(self.cfg.plans_dir / plan_file))
        return argv + ["--out", str(d / "evidence"), "--run-id", run_id, "--defect", defect]

    def child_env(self, home: Path) -> Dict[str, str]:
        """The environment of the command: no variable of the service (the token is one) is passed on."""
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        for key in ("TMPDIR", "REDEVOPS_QA_PINS", "PLAYWRIGHT_BROWSERS_PATH"):
            if key in os.environ:
                env[key] = os.environ[key]
        return env

    def _run(self, run_id: str, plan: str, defect: str) -> None:
        d = self.root / run_id
        record = self.get(run_id)
        exit_code: Optional[int] = None
        try:
            home = d / "home"
            home.mkdir()
            with open(d / "output.txt", "wb") as out:
                proc = subprocess.Popen(self._argv(run_id, plan, defect), stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT, cwd=str(d), env=self.child_env(home),
                                        start_new_session=True)
                try:
                    exit_code = proc.wait(timeout=self.cfg.run_timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                    record["note"] = f"killed after {self.cfg.run_timeout} seconds (QA_SERVICE_RUN_TIMEOUT)"
                    exit_code = None
            record["state"] = "finished" if exit_code is not None else "timed_out"
        except OSError as exc:
            record["state"] = "failed_to_start"
            record["note"] = f"the command could not be started ({type(exc).__name__})"
        shutil.rmtree(d / "home", ignore_errors=True)
        record.update(finished=_now(), exit_code=exit_code, outcome=EXIT_MEANING.get(exit_code) if exit_code is not None else None)
        bundle = self.bundle_dir(run_id)
        record["bundle"] = bundle.name if bundle else None
        self._write_status(run_id, record)
        with self._lock:
            self._active = None

    # ------------------------------------------------------------------ reading a run
    def bundle_dir(self, run_id: str) -> Optional[Path]:
        ev = self._dir(run_id) / "evidence"
        try:
            kids = [p for p in ev.iterdir() if p.is_dir() and not p.is_symlink()]
        except OSError:
            return None
        return kids[0] if len(kids) == 1 else None

    def output(self, run_id: str) -> bytes:
        try:
            with open(self._dir(run_id) / "output.txt", "rb") as fh:
                return fh.read(OUTPUT_LIMIT)
        except OSError:
            return b""

    def delete(self, run_id: str) -> None:
        rec = self.get(run_id)
        if rec.get("state") == "running":
            raise Busy(run_id)
        shutil.rmtree(self._dir(run_id))

    def command(self, argv_tail: List[str], timeout: int = 130) -> Tuple[int, bytes]:
        """Run a read-only subcommand (``report``, ``verify``) of the same command in a scratch home."""
        scratch = self.cfg.data_dir / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        home = Path(os.environ.get("TMPDIR") or scratch)
        try:
            done = subprocess.run([self.cfg.cli] + argv_tail, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, env=self.child_env(home), cwd=str(scratch), check=False)
        except subprocess.TimeoutExpired:
            return 124, b""
        return done.returncode, done.stdout


def wait_idle(store: RunStore, seconds: float = 30.0) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if store._active is None:
            return True
        time.sleep(0.05)
    return False
