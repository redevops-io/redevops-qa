# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Running a frozen plan: start the target, run each lane as a supervised child process, collect what each wrote, build the bundle.

Lanes run one after the other (R0). Every lane is accounted for whatever happens to it: a lane that cannot start, times out, is cancelled or crashes is recorded
with a native status that says so and its assertions are INCONCLUSIVE, so the run can never be VERIFIED. The target and every child are stopped in ``finally``
blocks and as process groups, and the temporary directory is removed in a ``finally`` block. What is tested: a deadline, a cancel (SIGINT, SIGTERM, SIGHUP) and a SIGKILL of
this process each leave no process of the run behind (the lane child watches its parent and ends its own process group; the target ends when its standard input closes). What is not:
an unclean death of the whole machine, and a process that leaves the process group of its lane deliberately."""
from __future__ import annotations

import datetime
import importlib.metadata
import json
import os
import platform
import base64
import dataclasses
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from qa_adapter_kit.status import ErrorCode
from qa_adapter_kit.supervisor import CancelToken
from qa_evidence.build import BuiltBundle
from qa_evidence.canon import CanonError, dumps_canonical, loads_strict

from . import constants as K
from qa_evidence.build import BuildError
from .bundle import LaneOutcome, RunInputs, build_run_bundle
from .deps import Upstreams
from .egress import policy_config
from .errors import EnvironmentFault, PlanError
from .corroborate import REFERENCE_CHECK_PATH, request_log_path
from .judge import observation_document, observation_path
from .exits import exit_code_for  # noqa: F401  (kept importable from here)
from .natives import native_from_harness
from .safe_read import Budget, UnsafeRead, read_regular
from .plan import FrozenLane, FrozenPlan, materialise_spec
from .procs import FixtureApp, child_env, make_workdir, run_child

MAX_BLOBS = 400
MAX_BLOB_BYTES = 4 * 1024 * 1024
_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_id() -> str:
    return "r0-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + base64.b32encode(os.urandom(8)).decode().rstrip("=").lower()
    # 64 random bits as 13 base-32 characters: two runs never share an id by chance (not hex: a bare 16-hex token in a run record is read by the harness as a cut-off digest)


def describe_environment(chromium: Optional[str] = None) -> Dict[str, str]:
    env = {"os": platform.system().lower() or "unknown", "arch": platform.machine().lower() or "unknown", "python": platform.python_version()}
    if chromium and re.fullmatch(r"[A-Za-z0-9 ._()-]{1,80}", chromium):
        env["chromium"] = chromium.replace(" ", "-").lower()
    try:
        env["playwright"] = importlib.metadata.version("playwright")
    except importlib.metadata.PackageNotFoundError:
        pass
    return env


@dataclass(frozen=True)
class RunOptions:
    defect: str = "none"
    run_id: Optional[str] = None
    lane_deadline_s: Optional[float] = None            # overrides the plan's deadlines (a ceiling; never raises one)
    cancel: Optional[CancelToken] = None
    clock: Callable[[], str] = utc_now
    max_evidence_bytes: Optional[int] = None            # the total a run keeps of its lanes' output (default: REDEVOPS_QA_MAX_EVIDENCE_BYTES, else 128 MiB); over it, the rest is not kept and the run is incomplete
    lane_command: Optional[Callable[[FrozenLane, str], List[str]]] = None       # test seam: the argv of a lane child. A lane run this way is a TEST DOUBLE: it can never carry a verdict
    robot_launcher: Optional[Sequence[str]] = None                              # test seam: replaces "-m robot" in the Robot adapter's command (offline tests); also a test double


@dataclass(frozen=True)
class RunSummary:
    run_id: str
    bundle: BuiltBundle
    outcome: str
    reason_code: str
    exit_code: int
    plan_digest: str
    manifest_digest: str
    lanes: Tuple[Tuple[str, str], ...]                 # (lane id, native status)
    cancelled: bool


def _read_bounded(path: Path, limit: int) -> Optional[bytes]:
    """A file a lane or the target wrote: read through ``safe_read`` (one descriptor, regular files only, no symlink, byte and time caps), or ``None``."""
    try:
        return read_regular(str(path), max_bytes=limit, deadline_s=10.0, follow_symlinks=False)
    except UnsafeRead:
        return None


def lane_input(fl: FrozenLane, *, run_id: str, origin: str, out_dir: str) -> Dict[str, Any]:
    return {"schema": K.LANE_INPUT_SCHEMA, "schema_version": K.SCHEMA_VERSION, "run_id": f"{run_id}.{fl.lane_id}", "lane_id": fl.lane_id, "origin": origin,
            "spec": materialise_spec(fl.spec_template, origin), "assertions": [dict(a) for a in fl.assertions], "harness_pin": fl.harness_pin,
            "egress_policy": policy_config(fl.egress, origin), "out_dir": out_dir, "parent_pid": os.getpid()}


def _unavailable(fl: FrozenLane, engine_version: str, raw: str, status: str = "NATIVE_UNAVAILABLE") -> LaneOutcome:
    return LaneOutcome(lane_id=fl.lane_id, engine_name=fl.engine, engine_version=engine_version, native_status=status, raw_status=raw, exit_code=None)


def run_browser_lane(fl: FrozenLane, *, run_id: str, origin: Optional[str], workdir: str, opts: RunOptions, log: List[str], budget: Optional[Budget] = None) -> LaneOutcome:
    budget = budget if budget is not None else Budget(_evidence_cap(opts))
    dropped_before = len(budget.dropped)
    try:
        version = importlib.metadata.version("playwright")
    except importlib.metadata.PackageNotFoundError:
        version = "not-installed"
    if origin is None:
        log.append(f"lane {fl.lane_id}: not started: the target did not start")
        return _unavailable(fl, version, "target-not-started")
    if opts.cancel is not None and opts.cancel.cancelled:
        log.append(f"lane {fl.lane_id}: not started: the run was cancelled")
        return _unavailable(fl, version, "cancelled-before-start", "NATIVE_SKIPPED")
    lane_dir = Path(workdir) / "lanes" / fl.lane_id
    out_dir = lane_dir / "out"
    home = lane_dir / "home"
    home.mkdir(parents=True)
    spec_in = lane_dir / "input.json"
    cfg = lane_input(fl, run_id=run_id, origin=origin, out_dir=str(out_dir))
    spec_in.write_bytes(dumps_canonical(cfg))
    argv = opts.lane_command(fl, str(spec_in)) if opts.lane_command else [sys.executable, "-s", "-m", "qa_runner.lane_browser", str(spec_in)]
    deadline = float(fl.deadline_s if opts.lane_deadline_s is None else min(opts.lane_deadline_s, fl.deadline_s))
    proc = run_child(argv, cwd=str(lane_dir), env=child_env(str(home)), deadline_s=deadline, cancel=opts.cancel)
    stdout_tail, stderr_tail = proc.stdout[-K.MAX_LOG_TAIL_BYTES:], proc.stderr[-K.MAX_LOG_TAIL_BYTES:]
    files: Dict[str, Tuple[bytes, str]] = {f"logs/{fl.lane_id}.stdout.txt": (stdout_tail, "log"), f"logs/{fl.lane_id}.stderr.txt": (stderr_tail, "log"),
                                           f"lanes/{fl.lane_id}/egress-profile.json": (dumps_canonical(cfg["egress_policy"]), "record")}
    native: Dict[str, bytes] = {}
    result: Optional[Dict[str, Any]] = None
    for name, blob in list(files.items()):
        budget.keep(name, blob[0]) or files.pop(name)
    raw = budget.read(out_dir / "lane-result.json", K.MAX_CHILD_JSON_BYTES, "lane-result.json")
    if raw is not None:
        try:
            parsed = loads_strict(raw)
            if isinstance(parsed, dict) and parsed.get("schema") == K.LANE_RESULT_SCHEMA:
                result = parsed
                native["lane-result.json"] = raw
        except CanonError:
            result = None
    for name in ("run-record.json",):
        data = budget.read(out_dir / name, 64 * 1024 * 1024, name)
        if data is not None:
            native[name] = data
    blob_dir = out_dir / "blobs"
    too_many = False
    names = _blob_names(blob_dir)
    if len(names) > MAX_BLOBS:
        too_many = True
    for n in names[:MAX_BLOBS]:
        data = budget.read(blob_dir / n, MAX_BLOB_BYTES, f"blobs/{n}")
        if data is not None:
            native[f"blobs/{n}"] = data
    for name in ("gateway-log.jsonl", "browser-guard-log.jsonl"):
        data = budget.read(out_dir / name, 16 * 1024 * 1024, name)
        if data is not None:
            files[f"lanes/{fl.lane_id}/{name}"] = (data, "log")
    over = len(budget.dropped) > dropped_before                  # this lane's own files, not an earlier lane's
    if over:
        log.append(f"lane {fl.lane_id}: the evidence budget of {budget.total} bytes is used up: not kept: {len(budget.dropped) - dropped_before} file(s) ({', '.join(sorted(budget.dropped)[:5])}...); what was kept is in the bundle")
    status, raw_status, exit_code, counts = "NATIVE_ERROR", "error", proc.exit_code, None
    harness_verdicts: Dict[str, str] = {}
    egress: Dict[str, int] = {}
    chromium: Optional[str] = None
    if proc.error_code == ErrorCode.TIMEOUT:
        status, raw_status = "NATIVE_TIMEOUT", "timeout"
    elif proc.error_code == ErrorCode.CANCELLED:
        status, raw_status = "NATIVE_ERROR", "cancelled"
    elif proc.error_code == ErrorCode.OUTPUT_LIMIT:
        status, raw_status = "NATIVE_ERROR", "output-limit"
    elif proc.error_code == ErrorCode.SPAWN_FAILED:
        status, raw_status = "NATIVE_UNAVAILABLE", "spawn-failed"
    elif result is not None and result.get("status") == "COMPLETED" and proc.exit_code == 0 and not too_many and not over:
        status, raw_status = native_from_harness(str(result.get("outcome")), result.get("reason"))
        exit_code = result.get("exit_code") if isinstance(result.get("exit_code"), int) else None
        rows = result.get("observations") if isinstance(result.get("observations"), list) else []
        if rows and all(isinstance(r, dict) and isinstance(r.get("assertion_id"), str) for r in rows):
            # recorded exactly as the lane returned them: a row with a field it should not have (a verdict, an expected value) is not repaired or dropped here,
            # the judge refuses the whole file as unusable evidence
            doc = observation_document(fl.lane_id, f"{run_id}.{fl.lane_id}", fl.engine, rows)
            files[observation_path(fl.lane_id)] = (dumps_canonical(doc), "observation")
        for v in result.get("harness_verdicts") or []:
            if isinstance(v, dict) and isinstance(v.get("assertion_id"), str) and v.get("verdict") in ("PASS", "FAIL", "INDETERMINATE"):
                harness_verdicts[v["assertion_id"]] = v["verdict"]
        for key, source in (("gateway_denied", result.get("gateway")), ("gate_denied", result.get("browser_guard"))):
            if isinstance(source, dict) and isinstance(source.get("denied"), int):
                egress[key] = source["denied"]
        chromium = result.get("browser") if isinstance(result.get("browser"), str) else None
        if status == "NATIVE_FAIL" and not exit_code:
            exit_code = 1
        if status == "NATIVE_PASS":
            exit_code = 0
    elif over:
        raw_status = "evidence-over-cap"
    elif too_many:
        raw_status = "too-many-artifacts"
    elif result is not None and result.get("status") == "ERROR":
        raw_status = "lane-error"
    else:
        raw_status = f"child-exit-{proc.exit_code}" if proc.exit_code is not None else f"child-signal-{proc.signal}"
    if status in ("NATIVE_ERROR", "NATIVE_TIMEOUT", "NATIVE_UNAVAILABLE") and exit_code == 0:
        exit_code = None
    if status == "NATIVE_ERROR" and exit_code is None and proc.exit_code not in (None, 0):
        exit_code = proc.exit_code
    log.append(f"lane {fl.lane_id}: native {status} ({_SAFE.sub('_', raw_status)[:40]}), exit {exit_code}")
    return LaneOutcome(lane_id=fl.lane_id, engine_name=fl.engine, engine_version=version, native_status=status, raw_status=raw_status, exit_code=exit_code,
                       native_files=native, files=files, counts=counts, harness_verdicts=harness_verdicts, double=opts.lane_command is not None, egress=egress, chromium=chromium)


def _evidence_cap(opts: RunOptions) -> int:
    if opts.max_evidence_bytes is not None:
        return opts.max_evidence_bytes
    env = os.environ.get("REDEVOPS_QA_MAX_EVIDENCE_BYTES", "")
    return int(env) if env.isdigit() and int(env) > 0 else K.DEFAULT_MAX_EVIDENCE_BYTES


def _blob_names(blob_dir: Path) -> List[str]:
    """The blob names of a lane's output, at most MAX_BLOBS + 1 of them (a directory with millions of entries is not listed in full)."""
    found: List[str] = []
    try:
        with os.scandir(blob_dir) as it:
            for entry in it:
                if re.fullmatch(r"[0-9a-f]{64}", entry.name):
                    found.append(entry.name)
                    if len(found) > MAX_BLOBS:
                        break
    except OSError:
        return []
    return sorted(found)


def _log_lines(path: Path) -> List[bytes]:
    data = _read_bounded(path, 16 * 1024 * 1024)
    return data.splitlines() if data else []


def run_plan(up: Upstreams, frozen: FrozenPlan, opts: RunOptions = RunOptions()) -> RunSummary:
    run_id = new_run_id() if opts.run_id is None else opts.run_id
    if not K.RUN_ID_RE.fullmatch(run_id):
        raise PlanError("BAD_RUN_ID", "a run id is 1 to 40 characters: letters, digits, '.', '_' and '-', starting with a letter or digit")
    if opts.defect not in K.DEFECTS:
        raise PlanError("BAD_DEFECT", f"defect must be one of {list(K.DEFECTS)}")
    if opts.lane_deadline_s is not None and not 1 <= opts.lane_deadline_s <= 3600:
        raise PlanError("BAD_DEADLINE", "a lane deadline is between 1 and 3600 seconds")
    workdir = make_workdir()
    try:
        return _run_in(up, frozen, opts, run_id, workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)         # on success and on every failure: nothing of the run is left in the temporary directory


def _run_in(up: Upstreams, frozen: FrozenPlan, opts: RunOptions, run_id: str, workdir: str) -> RunSummary:
    log: List[str] = [f"run {run_id}", f"plan {frozen.plan_id} digest {frozen.plan_digest}", f"target fixture-app defect {opts.defect}"]
    started = opts.clock()
    req_path = Path(workdir) / "requests.jsonl"
    app = FixtureApp(opts.defect, str(req_path), home=workdir)
    origin: Optional[str] = None
    outcomes: List[LaneOutcome] = []
    reference: Optional[Dict[str, Any]] = None
    budget = Budget(_evidence_cap(opts))                       # one budget for everything the run keeps of its lanes: over it, the rest is not kept, the run says so, nothing is deleted
    try:
        try:
            origin = app.start()
            log.append("target started on loopback")
        except EnvironmentFault as exc:
            log.append(f"target not started: {exc.code}")
        for fl in frozen.lanes:
            deadline = float(fl.deadline_s if opts.lane_deadline_s is None else min(opts.lane_deadline_s, fl.deadline_s))
            before = len(_log_lines(req_path))
            if fl.engine == K.ENGINE_PLAYWRIGHT:
                out = run_browser_lane(fl, run_id=run_id, origin=origin, workdir=workdir, opts=opts, log=log, budget=budget)
            elif fl.engine == K.ENGINE_ROBOT:
                from .lane_robot import run_robot_lane
                out = run_robot_lane(fl, run_id=run_id, origin=origin, workdir=workdir, cancel=opts.cancel, deadline_s=deadline, log=log, launcher=opts.robot_launcher, budget=budget)
            else:
                raise PlanError("UNSUPPORTED_ENGINE", f"no runner for engine {fl.engine!r}")
            window = b"".join(l + b"\n" for l in _log_lines(req_path)[before:])       # what the target itself served while this lane ran
            kept = dict(out.files)
            if budget.keep(request_log_path(fl.lane_id), window):
                kept[request_log_path(fl.lane_id)] = (window, "log")
            outcomes.append(dataclasses.replace(out, files=kept))
        if origin is not None and not (opts.cancel is not None and opts.cancel.cancelled) and any(f != "ui-only" for l in frozen.lanes for f in l.probes.values()):
            reference = _reference_check(origin, log, opts.cancel)          # after every lane: the check saves one setting in the (throwaway) target
    finally:
        app.stop()
    request_log = budget.read(req_path, 16 * 1024 * 1024, "logs/target-requests.jsonl") or b""
    cancelled = bool(opts.cancel is not None and opts.cancel.cancelled)
    if cancelled:
        log.append("the run was cancelled")
    finished = opts.clock()
    chromium = next((o.chromium for o in outcomes if o.chromium), None)
    env = describe_environment(chromium)
    logs = {"logs/orchestrator.log": ("\n".join(log) + "\n").encode("utf-8"), "logs/target-requests.jsonl": request_log}
    if reference is not None:
        logs[REFERENCE_CHECK_PATH] = dumps_canonical(reference)
    extensions: Dict[str, Any] = {"target_defect": opts.defect, "target": "fixture-app"}
    ui_only = sorted(f"{l.lane_id}:{aid}" for l in frozen.lanes for aid, fact in l.probes.items() if fact == "ui-only")
    if ui_only:
        extensions["no_independent_probe"] = ",".join(ui_only)[:500]           # assertions the plan declares ui-only: what the browser shows, nothing independent behind them
    if any(o.double for o in outcomes):
        extensions["test_double"] = "lane-command"
    for key in ("gateway_denied", "gate_denied"):
        if any(key in o.egress for o in outcomes):
            extensions["egress_" + key] = sum(o.egress.get(key, 0) for o in outcomes)
    if budget.dropped:
        extensions["evidence_incomplete"] = f"{len(budget.dropped)} file(s) not kept: the evidence budget of {budget.total} bytes was used up"
    inputs = RunInputs(frozen=frozen, run_id=run_id, started_at=started, finished_at=finished, environment=env, lanes=tuple(outcomes), logs=logs, extensions=extensions)
    try:
        built = build_run_bundle(up, inputs)
    except BuildError as exc:
        # The bundle format refused what was collected (a cap of its own: file count or total size). The evidence is not thrown away and the run does not end as a crash: every lane's bulk (blobs) is left out,
        # the lane is an engine error with the reason, and the bundle that is built says so.
        log.append("the bundle format refused the evidence as collected (" + ", ".join(sorted({c for c, _, _ in exc.problems})[:3]) + "): the blobs of every lane were left out")
        slim = tuple(dataclasses.replace(o, native_files={k: v for k, v in o.native_files.items() if not k.startswith("blobs/")}, native_status="NATIVE_ERROR", raw_status="evidence-over-cap") for o in outcomes)
        logs["logs/orchestrator.log"] = ("\n".join(log) + "\n").encode("utf-8")
        extensions["evidence_incomplete"] = "the bundle format refused the evidence as collected; the blobs were left out"
        built = build_run_bundle(up, dataclasses.replace(inputs, lanes=slim, logs=logs, extensions=extensions))
    report = json.loads(built.files["report.json"])
    code = exit_code_for(report, cancelled)
    return RunSummary(run_id=run_id, bundle=built, outcome=report["verdict"]["outcome"], reason_code=report["verdict"]["reason_code"], exit_code=code,
                      plan_digest=frozen.plan_digest, manifest_digest=built.manifest_digest,
                      lanes=tuple((l["lane_id"], l["native"]["status"]) for l in report["lanes"]), cancelled=cancelled)


def _reference_check(origin: str, log: List[str], cancel: Any = None) -> Optional[Dict[str, Any]]:
    """The independent probe of the target: ``qa_fixture_app.reference_check`` restates the seed data and the rule on its own and talks plain HTTP. ``None`` when it cannot run."""
    try:
        from qa_fixture_app.reference_check import run_checks
        result = run_checks(origin, cancelled=(lambda: cancel.cancelled) if cancel is not None else None)       # bounded in bytes and in total time, and ended by a cancel
        return json.loads(json.dumps(result))
    except Exception as exc:
        log.append(f"the reference check of the target could not run ({type(exc).__name__})")
        return None
