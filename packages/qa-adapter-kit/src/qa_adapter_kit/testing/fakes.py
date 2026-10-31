# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Fake adapters that exercise the shared runner offline: a suite adapter that runs ``fake_child.py`` scenarios and imports the
small JSON report it writes, and an interactive adapter driven by a script of behaviours. No framework, browser, emulator or
network is involved, so every status, a cancel, a timeout, a malformed result, a missing artifact and a prohibited path can be
produced on demand."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..adapter import (ActionOutcome, ArtifactRef, ImportedReport, InteractiveLayout, MalformedReport, RunLayout)
from ..errors import AdapterFault, AdapterUnavailable
from ..models import (AdapterManifest, FrameworkRef, InteractiveActionRequest, InteractiveObservation, Limits, NativeAssertion, SuiteRunRequest)
from ..status import AdapterClass, Status
from ..supervisor import CommandSpec, ProcessOutcome

CHILD = str(Path(__file__).with_name("fake_child.py"))


def suite_manifest(*, limits: Optional[Limits] = None, executables: Optional[List[str]] = None, env_allowlist=(), secret_env_allowlist=(),
                   adapter_id: str = "fake-suite", downloads: bool = False, pinned_files=()) -> AdapterManifest:
    return AdapterManifest(
        adapter_id=adapter_id, adapter_version="0.1.0", adapter_class=AdapterClass.SUITE,
        framework=FrameworkRef(name="fake", pinned_release="1.0.0", license_component="fake-framework"),
        capabilities=("run_suite", "import_native_report"), allowed_executables=tuple(executables or [sys.executable]),
        env_allowlist=tuple(env_allowlist), secret_env_allowlist=tuple(secret_env_allowlist), pinned_files=tuple(pinned_files),
        limits=limits or Limits(deadline_s=20, output_limit_bytes=65536, kill_grace_s=0.5), report_formats=("json",), downloads=downloads)


class FakeSuiteAdapter:
    def __init__(self, scenario: str, manifest: Optional[AdapterManifest] = None, *, raise_in_import: bool = False, wrong_return: bool = False,
                 argv_override: Optional[List[str]] = None, extra_env: Optional[Dict[str, str]] = None):
        self.scenario = scenario
        self.manifest = manifest or suite_manifest()
        self.raise_in_import = raise_in_import
        self.wrong_return = wrong_return
        self.argv_override = argv_override
        self.extra_env = extra_env or {}
        self.builds = 0

    def build_command(self, request: SuiteRunRequest, layout: RunLayout) -> CommandSpec:
        self.builds += 1
        argv = tuple(self.argv_override) if self.argv_override else (sys.executable, "-I", CHILD, self.scenario, str(layout.output_dir))
        return CommandSpec(argv=argv, cwd=str(layout.workspace), extra_env=self.extra_env)

    def import_report(self, request: SuiteRunRequest, layout: RunLayout, outcome: ProcessOutcome) -> ImportedReport:
        if self.raise_in_import:
            raise RuntimeError("boom with a secret-looking value hunter2hunter2")
        if self.wrong_return:
            return {"assertions": []}       # type: ignore[return-value]
        path = layout.output_dir / "native.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            tests, artifacts = data["tests"], data.get("artifacts", [])
            if not isinstance(tests, list):
                raise TypeError("tests is not a list")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise MalformedReport(f"native.json cannot be read ({type(exc).__name__})") from None
        out: List[Any] = []
        for item in tests:
            # Deliberately hands raw mappings to the runner: a missing id or an unknown status must surface as MALFORMED_RESULT there.
            out.append({"native_id": item.get("id", ""), "name": item.get("name", ""), "status": str(item.get("status", "")).upper(),
                        "message": item.get("message", ""), "duration_s": item.get("duration", 0.0),
                        "declared_assertion_ids": tuple(tag.split(":", 1)[1] for tag in item.get("tags", []) if tag.startswith("qa-assert:"))})
        return ImportedReport(assertions=out, artifacts=[ArtifactRef(path=a, media_type="text/plain") for a in artifacts])


def interactive_manifest(*, limits: Optional[Limits] = None, adapter_id: str = "fake-interactive") -> AdapterManifest:
    return AdapterManifest(
        adapter_id=adapter_id, adapter_version="0.1.0", adapter_class=AdapterClass.INTERACTIVE,
        framework=FrameworkRef(name="fake", pinned_release="1.0.0", license_component="fake-framework"),
        capabilities=("open", "click", "type", "read", "check"), limits=limits or Limits(deadline_s=10, max_steps=5, max_retries=2))


class FakeInteractiveAdapter:
    """Behaviour is chosen by the action's ``target``: ``ok``, ``slow``, ``flaky:N`` (retryable failure N times, then ok), ``always_flaky``,
    ``fault``, ``crash``, ``unavailable``, ``bad_observation``, ``bad_return``, ``missing_artifact``, ``echo_value``, ``assert_pass``,
    ``assert_fail``, ``assert_error``."""

    def __init__(self, manifest: Optional[AdapterManifest] = None):
        self.manifest = manifest or interactive_manifest()
        self.calls: List[str] = []
        self.flaky_left: Dict[str, int] = {}
        self.aborted = False
        self.closed = False
        self.release = threading.Event()

    def perform(self, request: InteractiveActionRequest, layout: InteractiveLayout) -> ActionOutcome:
        target = request.target
        self.calls.append(target)
        if target == "ok":
            return ActionOutcome(observations=[InteractiveObservation(kind="read", summary="page title: Home")])
        if target == "slow":
            self.release.wait(5)
            return ActionOutcome()
        if target.startswith("flaky:"):
            left = self.flaky_left.setdefault(f"{request.step_index}", int(target.split(":")[1]))
            if left > 0:
                self.flaky_left[f"{request.step_index}"] = left - 1
                raise AdapterFault("element not ready", retryable=True)
            return ActionOutcome(observations=[InteractiveObservation(kind="read", summary="ready")])
        if target == "always_flaky":
            raise AdapterFault("element not ready", retryable=True)
        if target == "fault":
            raise AdapterFault("element not found", retryable=False)
        if target == "crash":
            raise RuntimeError("driver exploded")
        if target == "unavailable":
            raise AdapterUnavailable("no browser is installed on this worker")
        if target == "bad_observation":
            return ActionOutcome(observations=["not an observation"])      # type: ignore[list-item]
        if target == "bad_return":
            return {"observations": []}                                    # type: ignore[return-value]
        if target == "missing_artifact":
            return ActionOutcome(artifacts=[ArtifactRef(path="shots/none.png", media_type="image/png", role="screenshot")])
        if target == "echo_value":
            value = request.secret_value or request.value or ""
            return ActionOutcome(observations=[InteractiveObservation(kind="read", summary=f"typed {value}")])
        if target.startswith("assert_"):
            status = {"assert_pass": "PASS", "assert_fail": "FAIL", "assert_error": "ERROR"}[target]
            return ActionOutcome(assertions=[NativeAssertion(native_id=f"S{request.step_index}", name=target, status=Status(status),
                                                            declared_assertion_ids=("A-1",))])
        raise AdapterFault("unknown target", retryable=False)

    def abort(self) -> None:
        self.aborted = True
        self.release.set()

    def close(self) -> None:
        self.closed = True
