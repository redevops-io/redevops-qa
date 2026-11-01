# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Child processes of a run: the environment they get, how they are started and supervised, and the fixture app's lifecycle.

Every child leads its own session and is ended as a group (so a browser a lane started goes with the lane). The environment is built from
nothing: ``PATH`` and ``HOME`` are fixed, what to import from and where the pins and the browser are is passed explicitly, and no other
variable of this process reaches a child."""
from __future__ import annotations

import importlib.util
import json
import os
import queue
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from qa_adapter_kit.models import Limits
from qa_adapter_kit.supervisor import CancelToken, ProcessOutcome, run_supervised

from .deps import child_environment_keys
from .errors import EnvironmentFault

CHILD_MODULES = ("qa_runner", "qa_evidence", "qa_playwright", "qa_egress", "qa_adapter_kit", "qa_fixture_app", "redevops_qa_bridge", "qa_robot", "redevops_qa_checks")


def module_roots(modules: Sequence[str] = CHILD_MODULES) -> List[str]:
    """The directories the named top-level modules are imported from (what a child needs on ``PYTHONPATH`` in a checkout)."""
    roots: List[str] = []
    for name in modules:
        spec = importlib.util.find_spec(name)
        if spec is None or not spec.submodule_search_locations:
            continue
        root = str(Path(next(iter(spec.submodule_search_locations))).resolve().parent)
        if root not in roots:
            roots.append(root)
    return roots


def child_env(home: str, *, extra: Optional[Mapping[str, str]] = None, modules: Sequence[str] = CHILD_MODULES) -> Dict[str, str]:
    env = {"PATH": "/usr/bin:/bin", "HOME": home, "TMPDIR": home, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "NO_COLOR": "1",
           "PYTHONPATH": os.pathsep.join(module_roots(modules))}
    env.update(child_environment_keys())
    env.update(extra or {})
    return env


def run_child(argv: Sequence[str], *, cwd: str, env: Mapping[str, str], deadline_s: float, cancel: Optional[CancelToken] = None,
              output_limit_bytes: int = 1_000_000) -> ProcessOutcome:
    return run_supervised(list(argv), cwd=cwd, env=env, limits=Limits(deadline_s=deadline_s, output_limit_bytes=output_limit_bytes, kill_grace_s=2.0), cancel=cancel)


def _kill_group(pid: int, sig: int) -> None:
    try:
        os.killpg(pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


class FixtureApp:
    """The fixture app as a child process on loopback, started with the defect the run names. It exits on a signal and when its standard input closes,
    so a parent that dies cannot leave it behind."""

    def __init__(self, defect: str, request_log: str, *, home: str):
        self.defect = defect
        self.request_log = request_log
        self._home = home
        self._proc: Optional[subprocess.Popen] = None
        self.origin: Optional[str] = None
        self.pid: Optional[int] = None

    def start(self, timeout_s: float = 20.0) -> str:
        argv = [sys.executable, "-s", "-m", "qa_fixture_app", "--defect", self.defect, "--port", "0", "--request-log", self.request_log, "--shutdown-on-stdin-eof"]
        try:
            self._proc = subprocess.Popen(argv, env=child_env(self._home, modules=("qa_fixture_app",)), cwd=self._home, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        except OSError as exc:
            raise EnvironmentFault("FIXTURE_APP_NOT_STARTED", f"the fixture app could not be started ({type(exc).__name__})") from None
        self.pid = self._proc.pid
        lines: "queue.Queue[bytes]" = queue.Queue()
        threading.Thread(target=lambda: lines.put(self._proc.stdout.readline()), daemon=True).start()
        try:
            line = lines.get(timeout=timeout_s)
            ready = json.loads(line.decode("utf-8"))
            if ready.get("event") != "ready" or not str(ready.get("url", "")).startswith("http://127.0.0.1:"):
                raise ValueError("not a ready line")
        except Exception:
            self.stop()
            raise EnvironmentFault("FIXTURE_APP_NOT_READY", "the fixture app did not report a loopback address within the time allowed") from None
        self.origin = str(ready["url"])
        return self.origin

    def stop(self) -> None:
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _kill_group(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        _kill_group(proc.pid, signal.SIGKILL)          # anything of the group that outlived the leader
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        if proc.stdout:
            proc.stdout.close()
        self._proc = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def __enter__(self) -> "FixtureApp":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


def make_workdir(prefix: str = "redevops-qa-") -> str:
    return tempfile.mkdtemp(prefix=prefix)
