# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The evidence bundle of a run, built by a pure function: collected lane outcomes in, ``qa_evidence`` bundle out. No clock, no environment, no file system,
no process: everything it needs is in ``RunInputs``, so the same inputs give the same bytes (a CI job, an installer or a test can call it with recorded inputs).

What goes in a bundle (paths are bundle-relative):

* ``plan.lock.json`` (record): the frozen plan, its digests and the pins;
* ``lanes/<lane>/native/...`` (native-artifact): what the lane's engine wrote, byte for byte;
* ``lanes/<lane>/observations.json`` (observation), ``egress-profile.json`` (record), ``gateway-log.jsonl`` (log): what the verdicts were computed from and
  the network decisions;
* ``logs/...`` (log): the orchestration log and the target's request log.

Verdicts are computed here by ``judge_lane`` over the observation files that are in the bundle, so what the report says is what ``verify`` will recompute."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

from qa_evidence import __version__ as EVIDENCE_VERSION
from qa_evidence.build import BuiltBundle, build_bundle
from qa_evidence.canon import sha256_bytes
from qa_evidence.report import assemble_report

from . import constants as K
from .deps import Upstreams
from .judge import judge_lane
from .plan import FrozenPlan

NATIVE_STATUSES = ("NATIVE_PASS", "NATIVE_FAIL", "NATIVE_ERROR", "NATIVE_SKIPPED", "NATIVE_TIMEOUT", "NATIVE_UNAVAILABLE")
_HARNESS_FOR_STATE = {"VERIFIED": "PASS", "FAILED": "FAIL", "INCONCLUSIVE": "INDETERMINATE"}


@dataclass(frozen=True)
class LaneOutcome:
    """What one lane produced. ``native_*`` is the engine's own report; ``files`` are the lane's non-native files as ``bundle path -> (bytes, role)``."""

    lane_id: str
    engine_name: str
    engine_version: str
    native_status: str
    raw_status: str
    exit_code: Optional[int]
    native_files: Mapping[str, bytes] = field(default_factory=dict)           # relative to lanes/<lane>/native/
    files: Mapping[str, Tuple[bytes, str]] = field(default_factory=dict)
    counts: Optional[Mapping[str, int]] = None
    harness_verdicts: Mapping[str, str] = field(default_factory=dict)         # in-run verdicts of the harness verifier (a cross-check, never the source)


@dataclass(frozen=True)
class RunInputs:
    frozen: FrozenPlan
    run_id: str
    started_at: str
    finished_at: str
    environment: Mapping[str, str]
    lanes: Tuple[LaneOutcome, ...]
    logs: Mapping[str, bytes] = field(default_factory=dict)                   # bundle path -> bytes, all role "log"
    extensions: Mapping[str, Any] = field(default_factory=dict)


REDACTION = {"applied": False, "rules": [], "notes": [
    "artifacts captured by the browser pass the harness pattern redactor before they are stored; the harness run record, the gateway log and the logs of this "
    "bundle are not redacted: do not put a secret in a plan that is run for evidence"]}


def _lane_entry(run_id: str, lane: LaneOutcome) -> Dict[str, Any]:
    arts = [{"path": f"lanes/{lane.lane_id}/native/{rel}", "digest": sha256_bytes(data), "size": len(data)} for rel, data in sorted(lane.native_files.items())]
    native: Dict[str, Any] = {"status": lane.native_status, "raw_status": lane.raw_status[:64], "exit_code": lane.exit_code, "artifacts": arts}
    if lane.counts is not None:
        native["counts"] = dict(lane.counts)
    return {"lane_id": lane.lane_id, "run_id": f"{run_id}.{lane.lane_id}", "engine": {"name": lane.engine_name, "version": lane.engine_version}, "native": native}


def build_run_bundle(up: Upstreams, inputs: RunInputs) -> BuiltBundle:
    frozen = inputs.frozen
    files: Dict[str, Tuple[bytes, str]] = {"plan.lock.json": (frozen.lock_bytes(), "record")}
    by_lane = {l.lane_id: l for l in inputs.lanes}
    if sorted(by_lane) != sorted(l.lane_id for l in frozen.lanes) or len(by_lane) != len(inputs.lanes):
        raise ValueError("every lane of the plan needs exactly one outcome")
    for lane in inputs.lanes:
        for rel, data in lane.native_files.items():
            files[f"lanes/{lane.lane_id}/native/{rel}"] = (bytes(data), "native-artifact")
        for path, (data, role) in lane.files.items():
            files[path] = (bytes(data), role)
    for path, data in inputs.logs.items():
        files[path] = (bytes(data), "log")
    plain = {p: d for p, (d, _) in files.items()}
    results: List[Dict[str, Any]] = []
    lanes_report = []
    for fl in frozen.lanes:                                    # plan order
        lane = by_lane[fl.lane_id]
        lanes_report.append(_lane_entry(inputs.run_id, lane))
        for r in judge_lane(up, fl, run_id=inputs.run_id, files=plain):
            seen = lane.harness_verdicts.get(r["assertion_id"])
            if seen is not None and r["state"] in ("VERIFIED", "FAILED") and seen != _HARNESS_FOR_STATE[r["state"]]:
                # the in-run verifier and the recomputation disagree about a verdict: nothing is certified
                r = {**r, "state": "INCONCLUSIVE", "reason_code": "VERIFIER_ERROR"}
            results.append({"assertion_id": r["assertion_id"], "native_status": lane.native_status, "state": r["state"], "reason_code": r["reason_code"],
                            "evidence": r["evidence"]})
    report = assemble_report(run_id=inputs.run_id, started_at=inputs.started_at, finished_at=inputs.finished_at, plan_digest=frozen.plan_digest,
                             environment=dict(inputs.environment), lanes=lanes_report, frozen=frozen.rows, results=results,
                             verifier={"id": K.VERIFIER_NAME, "version": K.RUNNER_VERSION}, redaction=dict(REDACTION), extensions=dict(inputs.extensions) or None)
    pins = frozen.pins
    tools = {"redevops-qa-runner": K.RUNNER_VERSION, "qa-evidence": EVIDENCE_VERSION, "agent-harness": pins["harness"], "runtime-contracts": pins["contracts"]}
    return build_bundle(report=report, files=files, tools=tools, producer={"name": "redevops-qa", "version": K.RUNNER_VERSION})
