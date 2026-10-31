# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Helpers shared by the adapter-kit tests. Secret-looking values are generated at run time, never written into the repository."""
import os
import secrets
import subprocess
import time
from pathlib import Path

from qa_adapter_kit import Limits, SuiteRunRequest, SuiteRunner
from qa_adapter_kit.testing.fakes import FakeSuiteAdapter, suite_manifest


def fresh_secret(prefix: str = "") -> str:
    return prefix + secrets.token_hex(12)


def dirs(tmp_path: Path):
    ws, out = tmp_path / "workspace", tmp_path / "output"
    (ws / "suite").mkdir(parents=True)
    out.mkdir()
    (ws / "suite" / "tests.fake").write_text("x")
    return ws, out


def request(tmp_path: Path, **kw) -> SuiteRunRequest:
    ws, out = dirs(tmp_path) if not (tmp_path / "workspace").exists() else (tmp_path / "workspace", tmp_path / "output")
    base = dict(run_id="run-1", adapter_id="fake-suite", workspace=str(ws), suite_path="suite/tests.fake", output_dir=str(out))
    base.update(kw)
    return SuiteRunRequest(**base)


def run(tmp_path: Path, scenario: str, *, manifest=None, cancel=None, adapter_kw=None, **req):
    adapter = FakeSuiteAdapter(scenario, manifest or suite_manifest(), **(adapter_kw or {}))
    result = SuiteRunner(adapter).run(request(tmp_path, **req), cancel)
    return result, adapter


def pid_gone(pid: int, wait: float = 3.0) -> bool:
    """True once the process no longer runs (a zombie that nobody reaped counts as gone)."""
    end = time.monotonic() + wait
    while time.monotonic() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        state = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        if not state or state.startswith("Z"):
            return True
        time.sleep(0.05)
    return False


def wait_for_file(path: Path, wait: float = 5.0) -> bool:
    end = time.monotonic() + wait
    while time.monotonic() < end:
        if path.exists() and path.read_text().strip():
            return True
        time.sleep(0.02)
    return False
