# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Runners: turn a request into an ``AdapterResult`` and never raise for a problem of the run.

``SuiteRunner`` validates the request against the manifest, resolves every path through the allowlist, builds the command and
the environment, runs it under the supervisor, imports the native report, validates and redacts what came back and hashes the
artifacts. ``InteractiveSession`` does the same for one bounded action at a time, with step, retry and deadline budgets.

Every failure is an ``ERROR`` with a closed ``ErrorCode``. A result is never ``PASS`` unless the native report said so for every
test and the process exited 0.
"""
from __future__ import annotations

import dataclasses
import hashlib
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, List, Optional, Sequence, Tuple

from .adapter import (ActionOutcome, ArtifactRef, ImportedReport, InteractiveAdapter, InteractiveLayout, MalformedReport, RunLayout,
                      SuiteAdapter)
from .boundedread import UnsafeRead, read_regular
from .errors import AdapterFault, AdapterKitError, AdapterUnavailable, ModelError, PathRefused, PolicyRefused
from .models import (AdapterManifest, AdapterResult, EvidenceArtifact, InteractiveActionRequest, InteractiveObservation, Limits, NativeAssertion,
                     SuiteRunRequest, aggregate_status)
from .paths import PathPolicy
from .redact import Redactor
from .status import AdapterClass, ErrorCode, Status
from .supervisor import CancelToken, ProcessOutcome, build_env, check_command, run_supervised

RETRYABLE = frozenset({ErrorCode.SPAWN_FAILED})      # a run that merely failed to start; never a FAIL, a timeout or a cancel
_TEXT_MEDIA = ("text/", "application/json", "application/xml", "application/x-ndjson")
_TAIL = 4096


def _error(*, run_id: str, manifest: AdapterManifest, code: ErrorCode, message: str, redactor: Redactor, outcome: Optional[ProcessOutcome] = None,
           attempts: int = 1, adapter_class: Optional[AdapterClass] = None, duration_s: float = 0.0) -> AdapterResult:
    return AdapterResult(
        run_id=run_id, adapter_id=manifest.adapter_id, adapter_class=adapter_class or manifest.adapter_class, status=Status.ERROR,
        error_code=code, error_message=redactor.text(message)[:4096], attempts=attempts,
        exit_code=outcome.exit_code if outcome else None, duration_s=outcome.duration_s if outcome else duration_s,
        stdout_tail=redactor.data(outcome.stdout, limit=_TAIL) if outcome else "", stderr_tail=redactor.data(outcome.stderr, limit=_TAIL) if outcome else "")


def _sanitise_assertion(raw: Any, redactor: Redactor) -> NativeAssertion:
    a = raw if isinstance(raw, NativeAssertion) else NativeAssertion.from_dict(raw)       # ModelError on a malformed one
    return dataclasses.replace(a, name=redactor.text(a.name)[:512], message=redactor.text(a.message)[:4096], source=redactor.text(a.source)[:512])


def _collect_artifacts(refs: Sequence[ArtifactRef], policy: PathPolicy, output_dir: Path, limits: Limits, redactor: Redactor,
                       secrets: Sequence[str]) -> List[EvidenceArtifact]:
    out: List[EvidenceArtifact] = []
    for ref in refs:
        if not isinstance(ref, ArtifactRef):
            raise MalformedReport("an artifact reference is not an ArtifactRef")
        try:
            real = policy.resolve(ref.path, base=output_dir)
        except PathRefused:
            raise PathRefused(f"artifact {ref.path!r} is outside the output directory or on the prohibited list") from None
        if output_dir != real and output_dir not in real.parents:
            raise PathRefused(f"artifact {ref.path!r} is not inside the output directory")
        try:
            data = read_regular(str(real), max_bytes=limits.max_artifact_bytes, deadline_s=30.0, follow_symlinks=False, root=str(output_dir))     # one descriptor: a FIFO or a link is refused, never waited for
        except UnsafeRead as exc:
            if exc.code == "TOO_LARGE":
                raise AdapterKitError(f"artifact {ref.path!r} is larger than {limits.max_artifact_bytes} bytes", ErrorCode.ARTIFACT_REFUSED) from None
            raise AdapterKitError(f"declared artifact {ref.path!r} was not produced as a regular file", ErrorCode.MISSING_ARTIFACT) from None
        size = len(data)
        if ref.media_type.startswith(_TEXT_MEDIA) and any(s.encode() in data for s in secrets if s):
            raise AdapterKitError(f"artifact {ref.path!r} contains a secret value and is not kept as evidence", ErrorCode.ARTIFACT_REFUSED)
        out.append(EvidenceArtifact(path=str(real.relative_to(output_dir)), media_type=ref.media_type, sha256=hashlib.sha256(data).hexdigest(),
                                    size_bytes=size, role=ref.role))
    return out


class SuiteRunner:
    def __init__(self, adapter: SuiteAdapter, *, clock: Callable[[], float] = time.monotonic):
        self.adapter = adapter
        self.manifest = adapter.manifest
        self.clock = clock

    def run(self, request: SuiteRunRequest, cancel: Optional[CancelToken] = None) -> AdapterResult:
        redactor = Redactor(request.secret_env.values())
        started = self.clock()
        try:
            return self._run(request, cancel, redactor)
        except AdapterKitError as exc:
            return _error(run_id=request.run_id, manifest=self.manifest, code=exc.code, message=str(exc), redactor=redactor,
                          duration_s=self.clock() - started)
        except Exception as exc:        # an adapter bug is an ERROR of the run, with the class name only
            return _error(run_id=request.run_id, manifest=self.manifest, code=ErrorCode.ADAPTER_CRASH,
                          message=f"adapter raised {type(exc).__name__}", redactor=redactor, duration_s=self.clock() - started)

    def _run(self, request: SuiteRunRequest, cancel: Optional[CancelToken], redactor: Redactor) -> AdapterResult:
        m = self.manifest
        if m.adapter_class is not AdapterClass.SUITE:
            raise ModelError("this runner runs suite adapters only")
        if request.adapter_id != m.adapter_id:
            raise ModelError("the request is for a different adapter")
        limits = (request.limits or m.limits).clamp(m.limits)
        workspace, output = Path(os.path.realpath(request.workspace)), Path(os.path.realpath(request.output_dir))
        if not workspace.is_dir() or not output.is_dir():
            raise PathRefused("workspace and output directory must exist")
        home = tempfile.mkdtemp(prefix="qa-adapter-home-")
        try:
            policy = PathPolicy([workspace, output, home])
            suite = policy.resolve(request.suite_path, base=workspace, must_exist=True)
            if workspace != suite and workspace not in suite.parents:
                raise PathRefused("the suite path leaves the workspace")
            layout = RunLayout(workspace=workspace, suite=suite, output_dir=output, home=Path(home))
            spec = self.adapter.build_command(request, layout)
            check_command(m, spec, PathPolicy([workspace, output, home]), sealed=request.sealed)
            env = build_env(m, env=request.env, secret_env=request.secret_env, extra=spec.extra_env, home=home, sealed=request.sealed)
            secrets = tuple(request.secret_env.values())
            attempts, outcome = 0, None
            t0 = self.clock()
            while True:
                attempts += 1
                remaining = max(limits.deadline_s - (self.clock() - t0), 0.05)
                outcome = run_supervised(spec.argv, cwd=spec.cwd, env=env, limits=dataclasses.replace(limits, deadline_s=remaining), cancel=cancel,
                                         clock=self.clock)
                if outcome.error_code in RETRYABLE and attempts <= limits.max_retries:
                    continue
                break
            if outcome.error_code is not None:
                return _error(run_id=request.run_id, manifest=m, code=outcome.error_code, message=outcome.error_message, redactor=redactor,
                              outcome=outcome, attempts=attempts)
            try:
                try:
                    report = self.adapter.import_report(request, layout, outcome)
                    if not isinstance(report, ImportedReport):
                        raise MalformedReport("the adapter returned something other than an ImportedReport")
                    assertions = tuple(_sanitise_assertion(a, redactor) for a in report.assertions)
                except ModelError as exc:
                    raise MalformedReport(f"the native report has a malformed entry: {exc}") from None
                artifacts = tuple(_collect_artifacts(report.artifacts, policy, output, limits, redactor, secrets))
                status = aggregate_status(assertions)
                error_code, message = None, ""
                if status is Status.ERROR:
                    error_code, message = ErrorCode.NATIVE_ERROR, "the framework reported an error"
                elif outcome.exit_code != 0 and status in (Status.PASS, Status.UNKNOWN):
                    status, error_code = Status.ERROR, ErrorCode.NATIVE_ERROR
                    message = f"the process exited {outcome.exit_code} without a failing result"
                return AdapterResult(run_id=request.run_id, adapter_id=m.adapter_id, adapter_class=m.adapter_class, status=status,
                                     native_assertions=assertions, artifacts=artifacts, error_code=error_code, error_message=message,
                                     exit_code=outcome.exit_code, duration_s=outcome.duration_s, attempts=attempts,
                                     stdout_tail=redactor.data(outcome.stdout, limit=_TAIL), stderr_tail=redactor.data(outcome.stderr, limit=_TAIL))
            except AdapterKitError as exc:      # the run happened: keep its exit code and output next to the error
                return _error(run_id=request.run_id, manifest=m, code=exc.code, message=str(exc), redactor=redactor, outcome=outcome, attempts=attempts)
            except Exception as exc:
                return _error(run_id=request.run_id, manifest=m, code=ErrorCode.ADAPTER_CRASH, message=f"adapter raised {type(exc).__name__}",
                              redactor=redactor, outcome=outcome, attempts=attempts)
        finally:
            shutil.rmtree(home, ignore_errors=True)


class InteractiveSession:
    """Bounded actions one at a time. The budget is the manifest's limits, cut by ``limits`` when given."""

    def __init__(self, adapter: InteractiveAdapter, *, output_dir: os.PathLike | str, limits: Optional[Limits] = None,
                 secrets: Sequence[str] = (), clock: Callable[[], float] = time.monotonic):
        self.adapter = adapter
        self.manifest = adapter.manifest
        if self.manifest.adapter_class is not AdapterClass.INTERACTIVE:
            raise ModelError("this session runs interactive adapters only")
        self.limits = (limits or self.manifest.limits).clamp(self.manifest.limits)
        self.output = Path(os.path.realpath(output_dir))
        if not self.output.is_dir():
            raise PathRefused("the output directory must exist")
        self.policy = PathPolicy([self.output])
        self.secrets = tuple(secrets)
        self.clock = clock
        self.started = clock()
        self.steps_used = 0
        self.closed: Optional[str] = None

    def perform(self, request: InteractiveActionRequest) -> AdapterResult:
        secrets = self.secrets + ((request.secret_value,) if request.secret_value else ())
        redactor = Redactor(secrets)
        cls = AdapterClass.INTERACTIVE

        def fail(code: ErrorCode, message: str, attempts: int = 1) -> AdapterResult:
            return _error(run_id=request.session_id, manifest=self.manifest, code=code, message=message, redactor=redactor, attempts=attempts,
                          adapter_class=cls, duration_s=self.clock() - self.started)

        if self.closed:
            return fail(ErrorCode.INVALID_REQUEST, f"the session is closed ({self.closed})")
        if request.adapter_id != self.manifest.adapter_id:
            return fail(ErrorCode.INVALID_REQUEST, "the request is for a different adapter")
        if request.kind not in self.manifest.capabilities:
            return fail(ErrorCode.INVALID_REQUEST, f"{request.kind!r} is not a capability of this adapter")
        if request.step_index != self.steps_used:
            return fail(ErrorCode.INVALID_REQUEST, f"expected step {self.steps_used}, got {request.step_index}")
        if self.steps_used >= self.limits.max_steps:
            self.closed = "step limit reached"
            return fail(ErrorCode.STEP_LIMIT, f"the session is limited to {self.limits.max_steps} steps")
        self.steps_used += 1
        attempts = 0
        while True:
            attempts += 1
            remaining = self.limits.deadline_s - (self.clock() - self.started)
            if remaining <= 0:
                self.closed = "deadline passed"
                return fail(ErrorCode.TIMEOUT, f"the session deadline of {self.limits.deadline_s:g}s passed", attempts)
            outcome = self._attempt(request, min(request.timeout_s, remaining))
            if isinstance(outcome, ActionOutcome):
                break
            kind, exc = outcome
            if kind == "timeout":
                self.closed = "an action timed out"
                try:
                    self.adapter.abort()
                except Exception:
                    pass
                return fail(ErrorCode.TIMEOUT, "the action did not finish within its deadline", attempts)
            if isinstance(exc, AdapterUnavailable):
                return fail(ErrorCode.UNAVAILABLE, str(exc), attempts)
            if isinstance(exc, AdapterFault) and exc.retryable:
                if attempts > self.limits.max_retries:
                    return fail(ErrorCode.RETRY_LIMIT, f"still failing after {attempts} attempt(s): {exc}", attempts)
                continue
            if isinstance(exc, AdapterKitError):
                return fail(exc.code, str(exc), attempts)
            return fail(ErrorCode.ADAPTER_CRASH, f"adapter raised {type(exc).__name__}", attempts)
        try:
            assertions = tuple(_sanitise_assertion(a, redactor) for a in outcome.assertions)
            observations = tuple(dataclasses.replace(o, summary=redactor.text(o.summary)[:4096]) if isinstance(o, InteractiveObservation)
                                 else _bad_observation() for o in outcome.observations)
            artifacts = tuple(_collect_artifacts(outcome.artifacts, self.policy, self.output, self.limits, redactor, secrets))
        except ModelError as exc:
            return fail(ErrorCode.MALFORMED_RESULT, f"the action result is malformed: {exc}", attempts)
        except AdapterKitError as exc:
            return fail(exc.code, str(exc), attempts)
        status = aggregate_status(assertions) if assertions else Status.PASS
        code = ErrorCode.NATIVE_ERROR if status is Status.ERROR else None
        return AdapterResult(run_id=request.session_id, adapter_id=self.manifest.adapter_id, adapter_class=cls, status=status,
                             native_assertions=assertions, artifacts=artifacts, observations=observations, error_code=code,
                             error_message="the framework reported an error" if code else "", duration_s=self.clock() - self.started,
                             attempts=attempts)

    def _attempt(self, request: InteractiveActionRequest, timeout: float):
        box: dict = {}

        def work() -> None:
            try:
                box["ok"] = self.adapter.perform(request, InteractiveLayout(output_dir=self.output))
            except BaseException as exc:      # noqa: BLE001 - reported by class name only
                box["exc"] = exc

        thread = threading.Thread(target=work, daemon=True)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            return ("timeout", None)
        if "exc" in box:
            return ("error", box["exc"])
        result = box.get("ok")
        if not isinstance(result, ActionOutcome):
            return ("error", MalformedReport("the adapter returned something other than an ActionOutcome"))
        return result

    def close(self) -> None:
        self.closed = self.closed or "closed"
        try:
            self.adapter.close()
        except Exception:
            pass


def _bad_observation():
    raise ModelError("an observation is not an InteractiveObservation")
