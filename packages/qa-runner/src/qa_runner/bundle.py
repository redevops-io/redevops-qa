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
from qa_evidence.constants import COMPLETING_STATUSES
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
    double: bool = False                                                      # produced by a test double (a test seam): such a lane can never carry a verdict
    egress: Mapping[str, int] = field(default_factory=dict)                   # denials counted by the egress layers (gateway, in-browser gate, the Robot lane's kernel layers), when the lane has them
    chromium: Optional[str] = None                                            # the browser build the lane reports (informational)


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
    "artifacts captured by a browser lane pass the harness pattern redactor before they are stored; the harness run record, a Robot output.xml, the gateway "
    "log and the logs of this bundle are not redacted: do not put a secret in a plan that is run for evidence"]}


def _lane_entry(run_id: str, lane: LaneOutcome) -> Dict[str, Any]:
    arts = [{"path": f"lanes/{lane.lane_id}/native/{rel}", "digest": sha256_bytes(data), "size": len(data)} for rel, data in sorted(lane.native_files.items())]
    native: Dict[str, Any] = {"status": lane.native_status, "raw_status": lane.raw_status[:64], "exit_code": lane.exit_code, "artifacts": arts}
    if lane.counts is not None:
        native["counts"] = dict(lane.counts)
    return {"lane_id": lane.lane_id, "run_id": f"{run_id}.{lane.lane_id}", "engine": {"name": lane.engine_name, "version": lane.engine_version}, "native": native}


def extra_limitations(frozen: FrozenPlan) -> List[Dict[str, str]]:
    """The limitations a run's report carries beyond the standard ones: what limits the egress of the plan's Robot lanes, per profile. A lane that names ``not-enforced`` gets the statement that egress is not
    enforced for it; a lane that names ``origin-only`` gets the statement of the kernel layers and of what they do not stop. Both are derived from the PLAN (the lanes that name the Robot engine and
    their profile), so ``verify`` can require exactly this text from the same plan."""
    robot = [l for l in frozen.lanes if l.engine == K.ENGINE_ROBOT]
    open_lanes = [l.lane_id for l in robot if l.egress == "not-enforced"]
    fenced = [l.lane_id for l in robot if l.egress == "origin-only"]
    out: List[Dict[str, str]] = []
    if open_lanes:
        out.append({"id": K.ROBOT_EGRESS_LIMITATION_ID, "text": K.robot_egress_limitation_text(open_lanes)})
    if fenced:
        out.append({"id": K.ROBOT_EGRESS_LAYERS_ID, "text": K.robot_egress_layers_text(fenced)})
    return out


def finalize_results(judged: List[Dict[str, Any]], native_status: str, double: bool, harness_verdicts: Mapping[str, str], incomplete: bool = False) -> List[Dict[str, Any]]:
    """What the recomputed verdicts of a lane become once the lane's own status is taken into account. ``verify`` applies the same rules to the same inputs read back from a bundle.

    * a lane produced by a test double never carries a verdict: every assertion is INCONCLUSIVE with the reason TEST_DOUBLE;
    * an engine that did not run to completion (error, timeout, cancelled, unavailable, skipped) never carries a VERIFIED or FAILED assertion: INCONCLUSIVE at most;
    * the in-run verifier's verdicts are a cross-check, never the source: where the recomputation says VERIFIED or FAILED and the in-run verdict differs, nothing is certified;
    * a run whose evidence is incomplete (the evidence budget kept ANYTHING out, a run-level file included) is never VERIFIED: a VERIFIED assertion becomes INCONCLUSIVE with the reason
      EVIDENCE_INCOMPLETE. The rule only lowers a verdict; a FAILED one, which rests on evidence that was kept, stays."""
    out = []
    for r in judged:
        if double:
            r = {**r, "state": "INCONCLUSIVE", "reason_code": "TEST_DOUBLE"}
        else:
            seen = harness_verdicts.get(r["assertion_id"])
            if seen is not None and r["state"] in ("VERIFIED", "FAILED") and seen != _HARNESS_FOR_STATE[r["state"]]:
                r = {**r, "state": "INCONCLUSIVE", "reason_code": "VERIFIER_ERROR"}
            if native_status not in COMPLETING_STATUSES and r["state"] in ("VERIFIED", "FAILED"):
                r = {**r, "state": "INCONCLUSIVE", "reason_code": "EVIDENCE_UNUSABLE"}
            if incomplete and r["state"] == "VERIFIED":
                r = {**r, "state": "INCONCLUSIVE", "reason_code": "EVIDENCE_INCOMPLETE"}
        out.append(r)
    return out


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
        for r in finalize_results(judge_lane(up, fl, run_id=inputs.run_id, files=plain), lane.native_status, lane.double, lane.harness_verdicts, "evidence_incomplete" in (inputs.extensions or {})):
            results.append({"assertion_id": r["assertion_id"], "native_status": lane.native_status, "state": r["state"], "reason_code": r["reason_code"],
                            "evidence": r["evidence"]})
    report = assemble_report(run_id=inputs.run_id, started_at=inputs.started_at, finished_at=inputs.finished_at, plan_digest=frozen.plan_digest,
                             environment=dict(inputs.environment), lanes=lanes_report, frozen=frozen.rows, results=results,
                             verifier={"id": K.VERIFIER_NAME, "version": K.RUNNER_VERSION}, redaction=dict(REDACTION), extra_limitations=extra_limitations(frozen),
                             extensions=dict(inputs.extensions) or None)
    pins = frozen.pins
    tools = {"redevops-qa-runner": K.RUNNER_VERSION, "qa-evidence": EVIDENCE_VERSION, "agent-harness": pins["harness"], "runtime-contracts": pins["contracts"]}
    return build_bundle(report=report, files=files, tools=tools, producer={"name": "redevops-qa", "version": K.RUNNER_VERSION})
