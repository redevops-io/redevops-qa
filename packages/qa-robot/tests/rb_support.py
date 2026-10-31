# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import dataclasses
import sys
from pathlib import Path

from qa_adapter_kit import Limits, SuiteRunRequest, SuiteRunner
from qa_robot import RobotConfig, RobotSuiteAdapter, suite_manifest

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures" / "output"
FAKE = str(HERE / "fake_robot.py")
LIMITS = Limits(deadline_s=120, output_limit_bytes=200_000, kill_grace_s=2)
SIMPLE = "*** Settings ***\nLibrary    Collections\n\n*** Test Cases ***\nT1\n    Log    x\n"


def workspace(tmp_path, text=SIMPLE, name="suite.robot"):
    ws, out = tmp_path / "workspace", tmp_path / "output"
    (ws / "suite").mkdir(parents=True)
    out.mkdir()
    (ws / "suite" / name).write_text(text)
    return ws, out


def run_fake(tmp_path, fixture, *, exit_code=None, write=True, config=None, text=SIMPLE, selectors=(), mapping=None, required=(), secret_names=(), **kw):
    ws, out = workspace(tmp_path, text)
    launcher = [FAKE, "--fixture", str(FIXTURES / fixture)] + (["--exit", str(exit_code)] if exit_code is not None else []) + ([] if write else ["--write-nothing"])
    manifest = dataclasses.replace(suite_manifest(sys.executable, limits=LIMITS), secret_env_allowlist=tuple(secret_names))
    adapter = RobotSuiteAdapter(sys.executable, config=config, manifest=manifest, launcher=launcher)
    req = SuiteRunRequest(run_id="run-1", adapter_id="robot-suite", workspace=str(ws), suite_path="suite", output_dir=str(out), selectors=tuple(selectors),
                          assertion_mapping=mapping or {}, required_assertions=tuple(required), **kw)
    return SuiteRunner(adapter).run(req), ws, out
