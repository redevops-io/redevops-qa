# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The Robot Framework lane: a reviewed suite run by the kit supervisor through the Robot adapter, its ``output.xml`` kept as the native result, and the observation
record the independent verifier reads derived from that report.

Robot records observations (``qa-observe`` tags); it never judges them for the verifier. The engine's own result (``NATIVE_PASS``/``NATIVE_FAIL``: did the suite's own
checks hold) is kept apart from the verdict, which comes from comparing the record with the value frozen in the plan.

Not enforced here, and stated in the lane's egress profile: network egress of a Robot library. The reviewed library connects to the target's loopback origin by
itself; nothing makes that traffic pass the gateway."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import os
import signal
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from qa_adapter_kit import ErrorCode, Limits, Status, SuiteRunRequest, SuiteRunner
from qa_adapter_kit.status import ErrorCode as KitError
from qa_adapter_kit.supervisor import CancelToken
from qa_evidence.canon import CanonError, dumps_canonical, loads_strict
from qa_robot import RobotConfig, RobotSuiteAdapter, observation_document, parse_observations, suite_manifest

from . import constants as K, suites, watchdog
from .bundle import LaneOutcome
from .judge import observation_path
from .natives import native_from_adapter_result
from .plan import FrozenLane
from .procs import child_env, run_child

EGRESS_NOT_ENFORCED = {"profile": "not-enforced", "note": "a Robot library opens its own sockets: nothing makes this lane's traffic pass the egress gateway; the "
                                                          "reviewed library connects to the target's loopback origin only"}


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _outcome(fl: FrozenLane, version: str, status: str, raw: str, **kw: Any) -> LaneOutcome:
    return LaneOutcome(lane_id=fl.lane_id, engine_name=fl.engine, engine_version=version, native_status=status, raw_status=raw, exit_code=kw.pop("exit_code", None), **kw)


def _run_inner(fl: Any, *, run_id: str, origin: str, workdir: str, cancel: Any, deadline_s: float, log: List[str],
               launcher: Optional[Sequence[str]] = None) -> LaneOutcome:
    try:
        version = importlib.metadata.version("robotframework")
    except importlib.metadata.PackageNotFoundError:
        version = "not-installed"
    egress_file = (f"lanes/{fl.lane_id}/egress-profile.json", (dumps_canonical(EGRESS_NOT_ENFORCED), "record"))
    lane_dir = Path(workdir) / "lanes" / fl.lane_id
    ws, out = lane_dir / "workspace", lane_dir / "output"
    (ws / "suite").mkdir(parents=True)
    out.mkdir(parents=True)
    spec = suites.SUITES[fl.suite]
    copies: Dict[str, bytes] = {}
    for rel, data in suites.suite_files(fl.suite).items():
        (ws / "suite" / rel).write_bytes(data)
        copies[rel] = data
    if {rel: _sha(d) for rel, d in copies.items()} != fl.suite_files:
        log.append(f"lane {fl.lane_id}: not started: the suite files are not the frozen ones")
        return _outcome(fl, version, "NATIVE_ERROR", "suite-hash-mismatch", files={egress_file[0]: egress_file[1]})
    library = str(spec["library"])
    config = RobotConfig(allowed_library_files={f"suite/{library}": hashlib.sha256(copies[library]).hexdigest()}, keep_raw_output=True)
    manifest = suite_manifest(sys.executable, limits=Limits(deadline_s=deadline_s, output_limit_bytes=2_000_000, kill_grace_s=5))
    adapter = RobotSuiteAdapter(sys.executable, config=config, manifest=manifest, **({"launcher": tuple(launcher)} if launcher else {}))
    request = SuiteRunRequest(run_id=f"{run_id}.{fl.lane_id}", adapter_id=manifest.adapter_id, workspace=str(ws), suite_path="suite", output_dir=str(out),
                              env={"QA_BASE_URL": origin})
    result = SuiteRunner(adapter).run(request, cancel)

    native: Dict[str, bytes] = {}
    for name in ("output.xml", "robot-summary.json"):
        p = out / name
        if p.is_file() and not p.is_symlink() and p.stat().st_size <= 32 * 1024 * 1024:
            native[name] = p.read_bytes()
    native["adapter-result.json"] = (json.dumps(result.to_dict(), sort_keys=True, indent=2) + "\n").encode("utf-8")
    files: Dict[str, Tuple[bytes, str]] = {egress_file[0]: egress_file[1]}
    for rel, data in sorted(copies.items()):
        files[f"lanes/{fl.lane_id}/suite/{rel}"] = (data, "record")
    files[f"logs/{fl.lane_id}.stdout.txt"] = (result.stdout_tail.encode("utf-8", "replace")[-65536:], "log")
    files[f"logs/{fl.lane_id}.stderr.txt"] = (result.stderr_tail.encode("utf-8", "replace")[-65536:], "log")

    mapped = native_from_adapter_result(result.status.value, result.error_code.value if result.error_code else None)
    status, raw = mapped if mapped is not None else ("NATIVE_ERROR", "error")
    counts = None
    if status in ("NATIVE_PASS", "NATIVE_FAIL", "NATIVE_SKIPPED") and result.native_assertions:
        n = result.native_assertions
        counts = {"passed": sum(1 for a in n if a.status is Status.PASS), "failed": sum(1 for a in n if a.status is Status.FAIL),
                  "errored": sum(1 for a in n if a.status is Status.ERROR), "skipped": sum(1 for a in n if a.status is Status.SKIP)}
    exit_code = result.exit_code
    if status == "NATIVE_PASS":
        exit_code = 0
    elif status == "NATIVE_FAIL" and not exit_code:
        exit_code = 1
    elif status in ("NATIVE_ERROR", "NATIVE_TIMEOUT", "NATIVE_UNAVAILABLE") and exit_code == 0:
        exit_code = None
    if status in ("NATIVE_PASS", "NATIVE_FAIL") and "output.xml" in native:
        try:
            obs = parse_observations(native["output.xml"])
            files[observation_path(fl.lane_id)] = (dumps_canonical(observation_document(obs, run_id=f"{run_id}.{fl.lane_id}", lane_id=fl.lane_id)), "observation")
        except Exception as exc:                # a report whose observations cannot be imported leaves no record: the assertions are then missing evidence
            log.append(f"lane {fl.lane_id}: the observations could not be imported ({type(exc).__name__})")
    log.append(f"lane {fl.lane_id}: native {status} ({raw}), exit {exit_code}")
    return LaneOutcome(lane_id=fl.lane_id, engine_name=fl.engine, engine_version=version, native_status=status, raw_status=raw, exit_code=exit_code,
                       native_files=native, files=files, counts=counts)


# ---- the lane as a supervised child process ------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class _Lane:
    """What the child needs of a frozen lane (the parent passes it in the lane input)."""

    lane_id: str
    engine: str
    suite: str
    suite_files: Mapping[str, str]


def _write_outcome(outcome: LaneOutcome, log: List[str], out: Path) -> None:
    data = out / "data"
    data.mkdir(parents=True, exist_ok=True)
    n = 0

    def put(blob: bytes) -> str:
        nonlocal n
        n += 1
        (data / f"{n}.bin").write_bytes(blob)
        return f"data/{n}.bin"
    doc = {"schema": K.LANE_RESULT_SCHEMA, "schema_version": K.SCHEMA_VERSION, "status": "COMPLETED", "engine_version": outcome.engine_version,
           "native_status": outcome.native_status, "raw_status": outcome.raw_status, "exit_code": outcome.exit_code, "counts": dict(outcome.counts) if outcome.counts else None,
           "log": log, "native": {rel: put(blob) for rel, blob in outcome.native_files.items()},
           "files": {path: {"role": role, "data": put(blob)} for path, (blob, role) in outcome.files.items()}}
    (out / "outcome.json").write_bytes(dumps_canonical(doc))


def _read_outcome(fl: Any, out: Path, limit: int = 64 * 1024 * 1024) -> Tuple[Optional[LaneOutcome], List[str]]:
    path = out / "outcome.json"
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > K.MAX_CHILD_JSON_BYTES:
            return None, []
        doc = loads_strict(path.read_bytes())
        if not isinstance(doc, dict) or doc.get("schema") != K.LANE_RESULT_SCHEMA or doc.get("status") != "COMPLETED":
            return None, []

        def get(rel: str) -> bytes:
            p = (out / rel).resolve()
            if out.resolve() not in p.parents or not p.is_file() or p.stat().st_size > limit:
                raise ValueError("a file the lane named is not inside its output directory")
            return p.read_bytes()
        outcome = LaneOutcome(lane_id=fl.lane_id, engine_name=fl.engine, engine_version=str(doc["engine_version"]), native_status=str(doc["native_status"]),
                              raw_status=str(doc["raw_status"]), exit_code=doc["exit_code"] if isinstance(doc["exit_code"], int) else None,
                              native_files={str(rel): get(ref) for rel, ref in doc["native"].items()},
                              files={str(p): (get(m["data"]), str(m["role"])) for p, m in doc["files"].items()},
                              counts=doc["counts"] if isinstance(doc["counts"], dict) else None)
        return outcome, [str(x)[:300] for x in doc.get("log", [])][:50]
    except (OSError, ValueError, KeyError, TypeError, CanonError):
        return None, []


def run_robot_lane(fl: FrozenLane, *, run_id: str, origin: Optional[str], workdir: str, cancel: Any, deadline_s: float, log: List[str],
                   launcher: Optional[Sequence[str]] = None) -> LaneOutcome:
    """Run the Robot lane in a child process under the kit supervisor, like the browser lane: the same deadline, cancel, output limit and process-group kill, and a child that
    ends itself (and the engine it started) if this process dies. The engine itself runs under its own supervisor inside the child."""
    try:
        version = importlib.metadata.version("robotframework")
    except importlib.metadata.PackageNotFoundError:
        version = "not-installed"
    if origin is None:
        log.append(f"lane {fl.lane_id}: not started: the target did not start")
        return _outcome(fl, version, "NATIVE_UNAVAILABLE", "target-not-started")
    if cancel is not None and cancel.cancelled:
        log.append(f"lane {fl.lane_id}: not started: the run was cancelled")
        return _outcome(fl, version, "NATIVE_SKIPPED", "cancelled-before-start")
    lane_dir = Path(workdir) / "lanes" / fl.lane_id
    home, out = lane_dir / "home", lane_dir / "out"
    home.mkdir(parents=True)
    out.mkdir(parents=True)
    cfg = {"schema": K.LANE_INPUT_SCHEMA, "schema_version": K.SCHEMA_VERSION, "lane_id": fl.lane_id, "engine": fl.engine, "suite": fl.suite, "suite_files": dict(fl.suite_files),
           "run_id": run_id, "origin": origin, "deadline_s": max(1, math.ceil(deadline_s)), "out_dir": str(out), "workdir": str(workdir), "suite_dir": str(suites.SUITE_DIR),
           "launcher": list(launcher) if launcher else None, "parent_pid": os.getpid()}
    spec_in = lane_dir / "input.json"
    spec_in.write_bytes(dumps_canonical(cfg))
    proc = run_child([sys.executable, "-s", "-m", "qa_runner.lane_robot", str(spec_in)], cwd=str(lane_dir), env=child_env(str(home)), deadline_s=max(1, math.ceil(deadline_s)) + 20, cancel=cancel, kill_grace_s=12.0)   # the engine runs in its own session: give the child time to end it first
    status, raw = "NATIVE_ERROR", "error"
    if proc.error_code == KitError.TIMEOUT:
        status, raw = "NATIVE_TIMEOUT", "timeout"
    elif proc.error_code == KitError.CANCELLED:
        raw = "cancelled"
    elif proc.error_code == KitError.OUTPUT_LIMIT:
        raw = "output-limit"
    elif proc.error_code == KitError.SPAWN_FAILED:
        status, raw = "NATIVE_UNAVAILABLE", "spawn-failed"
    else:
        outcome, lines = _read_outcome(fl, out)
        if outcome is not None and proc.exit_code == 0:
            log.extend(lines)
            return outcome
        raw = f"child-exit-{proc.exit_code}" if proc.exit_code is not None else f"child-signal-{proc.signal}"
    log.append(f"lane {fl.lane_id}: native {status} ({raw}), exit {proc.exit_code}")
    return _outcome(fl, version, status, raw, exit_code=proc.exit_code if status == "NATIVE_ERROR" and proc.exit_code else None,
                    files={f"logs/{fl.lane_id}.stdout.txt": (proc.stdout[-65536:], "log"), f"logs/{fl.lane_id}.stderr.txt": (proc.stderr[-65536:], "log")})


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        cfg = loads_strict(Path(argv[0]).read_bytes())
        if cfg.get("schema") != K.LANE_INPUT_SCHEMA:
            raise ValueError("not a lane input")
    except (OSError, CanonError, ValueError, IndexError) as exc:
        print(f"lane input unreadable: {type(exc).__name__}", file=sys.stderr)
        return 2
    cancel = CancelToken()
    signal.signal(signal.SIGTERM, lambda *_: cancel.cancel())                   # the parent's supervisor asks first: let the engine's own supervisor end its process group
    signal.signal(signal.SIGINT, lambda *_: cancel.cancel())
    if isinstance(cfg.get("parent_pid"), int):
        watchdog.start(cfg["parent_pid"], lambda: (cancel.cancel(), watchdog.kill_after(8.0)()))
    suites.SUITE_DIR = Path(cfg["suite_dir"])
    lane = _Lane(lane_id=cfg["lane_id"], engine=cfg["engine"], suite=cfg["suite"], suite_files=dict(cfg["suite_files"]))
    lines: List[str] = []
    try:
        outcome = _run_inner(lane, run_id=cfg["run_id"], origin=cfg["origin"], workdir=cfg["workdir"], cancel=cancel, deadline_s=float(cfg["deadline_s"]), log=lines,
                             launcher=cfg.get("launcher"))
        _write_outcome(outcome, lines, Path(cfg["out_dir"]))
        return 0
    except Exception as exc:
        print(f"lane failed: {type(exc).__name__}: {str(exc)[:500]}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
