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
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from qa_adapter_kit import ErrorCode, Limits, Status, SuiteRunRequest, SuiteRunner
from qa_evidence.canon import dumps_canonical
from qa_robot import RobotConfig, RobotSuiteAdapter, observation_document, parse_observations, suite_manifest

from . import suites
from .bundle import LaneOutcome
from .judge import observation_path
from .plan import FrozenLane

EGRESS_NOT_ENFORCED = {"profile": "not-enforced", "note": "a Robot library opens its own sockets: nothing makes this lane's traffic pass the egress gateway; the "
                                                          "reviewed library connects to the target's loopback origin only"}


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _outcome(fl: FrozenLane, version: str, status: str, raw: str, **kw: Any) -> LaneOutcome:
    return LaneOutcome(lane_id=fl.lane_id, engine_name=fl.engine, engine_version=version, native_status=status, raw_status=raw, exit_code=kw.pop("exit_code", None), **kw)


def run_robot_lane(fl: FrozenLane, *, run_id: str, origin: Optional[str], workdir: str, cancel: Any, deadline_s: float, log: List[str],
                   launcher: Optional[Sequence[str]] = None) -> LaneOutcome:
    try:
        version = importlib.metadata.version("robotframework")
    except importlib.metadata.PackageNotFoundError:
        version = "not-installed"
    egress_file = (f"lanes/{fl.lane_id}/egress-profile.json", (dumps_canonical(EGRESS_NOT_ENFORCED), "record"))
    if origin is None:
        log.append(f"lane {fl.lane_id}: not started: the target did not start")
        return _outcome(fl, version, "NATIVE_UNAVAILABLE", "target-not-started")
    if cancel is not None and cancel.cancelled:
        log.append(f"lane {fl.lane_id}: not started: the run was cancelled")
        return _outcome(fl, version, "NATIVE_SKIPPED", "cancelled-before-start")
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

    status, raw = "NATIVE_ERROR", "error"
    if result.status is Status.PASS:
        status, raw = "NATIVE_PASS", "PASS"
    elif result.status is Status.FAIL:
        status, raw = "NATIVE_FAIL", "FAIL"
    elif result.status is Status.SKIP:
        status, raw = "NATIVE_SKIPPED", "SKIP"
    elif result.status is Status.ERROR:
        if result.error_code is ErrorCode.TIMEOUT:
            status, raw = "NATIVE_TIMEOUT", "timeout"
        elif result.error_code is ErrorCode.CANCELLED:
            raw = "cancelled"
        elif result.error_code is ErrorCode.SPAWN_FAILED:
            status, raw = "NATIVE_UNAVAILABLE", "spawn-failed"
        else:
            raw = ("error-" + str(result.error_code.value if result.error_code else "unknown")).lower()[:60]
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
