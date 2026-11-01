# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Verdicts: recorded observations against frozen assertions. Nothing here runs an engine, reads a page or trusts an engine's own status.

``judge_lane`` is the one place verdicts are computed. The run calls it right after the lanes finish and ``verify`` calls it again, in a fresh
process, over the files of a bundle; the two must agree. It uses the harness ``DeterministicVerifier`` (the same comparison code the in-run
verifier uses): for a ``PLAYWRIGHT`` assertion the 'adapter' the verifier reads is a reader over the recorded observation of that assertion, so
the only things that reach ``evaluate_predicate`` are a recorded value and the frozen predicate. The expected value is never in the observation
file and the observation file has no field for a verdict: an unknown field is refused as unusable evidence.
"""
from __future__ import annotations

import copy
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from qa_evidence.canon import CanonError, dumps_canonical, loads_strict, sha256_bytes

from . import constants as K
from .deps import Upstreams
from .plan import FrozenLane

OBS_KEYS = {"schema", "schema_version", "lane_id", "run_id", "engine", "observations"}
ROW_KEYS = {"assertion_id", "resolution", "match_count", "value", "value_digest"}


class EvidenceUnusable(Exception):
    """An observation file that cannot be used as evidence (``code`` says why; the message never repeats file content)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def observation_path(lane_id: str) -> str:
    return f"lanes/{lane_id}/observations.json"


def parse_observations(data: bytes, lane_id: str, run_id: str) -> Dict[str, Dict[str, Any]]:
    """``assertion_id -> row`` of a browser lane's observation file, strictly: unknown fields (a 'verdict', a 'verified', an expected value) are refused."""
    try:
        doc = loads_strict(data)
    except CanonError as exc:
        raise EvidenceUnusable("NOT_STRICT_JSON", f"observation file: {exc.code}") from None
    if not isinstance(doc, dict) or set(doc) != OBS_KEYS:
        raise EvidenceUnusable("UNKNOWN_FIELD", "an observation file has exactly the fields " + ", ".join(sorted(OBS_KEYS)))
    if doc["schema"] != K.OBSERVATIONS_SCHEMA or doc["schema_version"] != K.SCHEMA_VERSION:
        raise EvidenceUnusable("UNSUPPORTED_VERSION", "not a redevops-qa/observations 1.0 file")
    if doc["lane_id"] != lane_id or doc["run_id"] != run_id:
        raise EvidenceUnusable("WRONG_CONTEXT", "the observation file was recorded for another lane or run")
    rows = doc["observations"]
    if not isinstance(rows, list):
        raise EvidenceUnusable("UNKNOWN_FIELD", "observations must be a list")
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != ROW_KEYS:
            raise EvidenceUnusable("UNKNOWN_FIELD", "an observation row has exactly the fields " + ", ".join(sorted(ROW_KEYS)))
        if not isinstance(row["assertion_id"], str) or row["assertion_id"] in out:
            raise EvidenceUnusable("DUPLICATE_ID", "an observation row names an assertion twice or has no id")
        out[row["assertion_id"]] = row
    return out


def observation_document(lane_id: str, run_id: str, engine: str, rows: List[Mapping[str, Any]]) -> Dict[str, Any]:
    return {"schema": K.OBSERVATIONS_SCHEMA, "schema_version": K.SCHEMA_VERSION, "lane_id": lane_id, "run_id": run_id, "engine": engine,
            "observations": sorted((dict(r) for r in rows), key=lambda r: r["assertion_id"])}


class _RecordedReader:
    """The verifier's only read of a page, answered from the recording (one assertion at a time)."""

    def __init__(self) -> None:
        self.current: Any = None

    def assert_(self, session: Any, subject: Any) -> Any:
        return self.current


def _result(assertion_id: str, state: str, reason: str, evidence: Optional[Dict[str, str]], harness_verdict: Optional[str] = None) -> Dict[str, Any]:
    return {"assertion_id": assertion_id, "state": state, "reason_code": reason, "evidence": evidence, "harness_verdict": harness_verdict}


def _all(lane: FrozenLane, state: str, reason: str, evidence: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    return [_result(a["assertion_id"], state, reason, evidence) for a in lane.assertions]


def _state(verdict: str, reason: Optional[str], op: str) -> Tuple[str, str]:
    if verdict == "PASS":
        return "VERIFIED", "EQUALS_EXPECTED" if op == "EQUALS" else "PREDICATE_HOLDS"
    if verdict == "FAIL":
        return "FAILED", "EXPECTED_VALUE_DIFFERS" if op == "EQUALS" else "PREDICATE_VIOLATED"
    return "INCONCLUSIVE", "EVIDENCE_UNUSABLE"


def native_output_path(lane_id: str) -> str:
    return f"lanes/{lane_id}/native/output.xml"


def derived_record(native_output: bytes, lane_id: str, run_id: str) -> Dict[str, Any]:
    """The Robot observation record as the importer derives it from the engine's own ``output.xml``. Raises ``EvidenceUnusable`` if the report cannot be imported."""
    from qa_adapter_kit import MalformedReport
    from qa_robot import observation_document, parse_observations
    try:
        return observation_document(parse_observations(native_output), run_id=run_id, lane_id=lane_id)
    except MalformedReport:
        raise EvidenceUnusable("NATIVE_REPORT_REFUSED", "the engine's report cannot be imported") from None


def _programs(up: Upstreams, lane: FrozenLane):
    if lane.engine == K.ENGINE_ROBOT:
        from redevops_qa_checks.registry import evidence_registry
        return evidence_registry()
    return up.harness.specstore.InMemoryProgramRegistry({})


def judge_lane(up: Upstreams, lane: FrozenLane, *, run_id: str, files: Mapping[str, bytes]) -> List[Dict[str, Any]]:
    """One result per frozen assertion of ``lane``, in assertion-id order: ``state`` (VERIFIED, FAILED, INCONCLUSIVE), a reason code from the closed list, and
    the evidence file (path and digest) the verdict was computed from. ``files`` maps bundle-relative paths to bytes; a file that is not there is missing evidence."""
    h = up.harness
    docs = [copy.deepcopy(a) for a in lane.assertions]
    try:
        pin = lane.harness_pin
        programs = _programs(up, lane)
        frozen = h.verifier.load_frozen_assertions(h.specstore.InMemorySpecStore({pin: docs}), pin, lineage=h.verifier.ApprovedLineage([pin]), programs=programs)
    except Exception:
        return _all(lane, "INCONCLUSIVE", "ASSERTION_INTEGRITY")
    executors = {a.assertion_id: a.executor.value for a in frozen.assertions}
    wanted = "SCRIPT" if lane.engine == K.ENGINE_ROBOT else "PLAYWRIGHT"
    if any(e != wanted for e in executors.values()):
        return _all(lane, "INCONCLUSIVE", "VERIFIER_ERROR")          # a lane holds the assertions of its own kind of engine only
    if lane.engine == K.ENGINE_ROBOT:
        return _judge_script(up, lane, frozen, programs, run_id, files)
    path = observation_path(lane.lane_id)
    data = files.get(path)
    if data is None:
        return _all(lane, "INCONCLUSIVE", "EVIDENCE_MISSING")
    evidence = {"path": path, "digest": sha256_bytes(data)}
    try:
        rows = parse_observations(data, lane.lane_id, f"{run_id}.{lane.lane_id}")
    except EvidenceUnusable:
        return _all(lane, "INCONCLUSIVE", "EVIDENCE_UNUSABLE", evidence)
    reader = _RecordedReader()
    verifier = h.verifier.DeterministicVerifier(programs=h.specstore.InMemoryProgramRegistry({}), qa_adapter=reader)
    out: List[Dict[str, Any]] = []
    for a in sorted(frozen.assertions, key=lambda x: x.assertion_id):
        aid = a.assertion_id
        row = rows.get(aid)
        if row is None:
            out.append(_result(aid, "INCONCLUSIVE", "EVIDENCE_MISSING", evidence))
            continue
        try:
            reader.current = h.records.ObservedValue(resolution=h.records.Resolution(row["resolution"]), match_count=row["match_count"], value=row["value"],
                                                     value_digest=row["value_digest"])
            result = verifier.verify_assertion(frozen, aid, session=None)
        except Exception:
            out.append(_result(aid, "INCONCLUSIVE", "EVIDENCE_UNUSABLE", evidence))
            continue
        verdict = result.check.verdict.value
        state, reason = _state(verdict, result.reason_code, a.predicate.op.value)
        out.append(_result(aid, state, reason, evidence, harness_verdict=verdict))
    return out


def _judge_script(up: Upstreams, lane: FrozenLane, frozen: Any, programs: Any, run_id: str, files: Mapping[str, bytes]) -> List[Dict[str, Any]]:
    """The SCRIPT executor: the hash-pinned check program, run by the harness verifier over the lane's observation record, compared with the value frozen in the assertion.

    The record must be exactly what the importer derives from the engine's own ``output.xml`` that is in the bundle (so it names this run and this report and cannot be
    hand-written or carried over from another run), and it is the only file the check program can read: it is staged alone in a fresh case root."""
    h = up.harness
    path = observation_path(lane.lane_id)
    data, native = files.get(path), files.get(native_output_path(lane.lane_id))
    if data is None or native is None:
        return _all(lane, "INCONCLUSIVE", "EVIDENCE_MISSING")
    evidence = {"path": path, "digest": sha256_bytes(data)}
    full_run = f"{run_id}.{lane.lane_id}"
    try:
        if dumps_canonical(derived_record(native, lane.lane_id, full_run)) != data:
            raise EvidenceUnusable("NOT_DERIVED", "the observation record is not what the importer derives from the engine's report")
    except (EvidenceUnusable, CanonError):
        return _all(lane, "INCONCLUSIVE", "EVIDENCE_UNUSABLE", evidence)
    try:
        from redevops_qa_checks.adapter import CheckAdapter
        from redevops_qa_checks.manifests import tree_digest
        with tempfile.TemporaryDirectory(prefix="redevops-qa-judge-") as tmp:
            root = Path(tmp) / "case"
            target = root.joinpath(*path.split("/"))
            target.parent.mkdir(parents=True)
            target.write_bytes(data)
            adapter = CheckAdapter(root, registry=programs)
            workspace = adapter.open_workspace(h.records.CheckProfile(case_root_digest=tree_digest(root), tier=h.records.CheckTier("OFFLINE")))
            verifier = h.verifier.DeterministicVerifier(programs=programs, check_adapter=adapter)
            out: List[Dict[str, Any]] = []
            for a in sorted(frozen.assertions, key=lambda x: x.assertion_id):
                try:
                    result = verifier.verify_assertion(frozen, a.assertion_id, workspace=workspace)
                except Exception:
                    out.append(_result(a.assertion_id, "INCONCLUSIVE", "VERIFIER_ERROR", evidence))
                    continue
                verdict = result.check.verdict.value
                state, reason = _state(verdict, result.reason_code, a.predicate.op.value)
                out.append(_result(a.assertion_id, state, reason, evidence, harness_verdict=verdict))
            adapter.close_workspace(workspace)
            return out
    except Exception:
        return _all(lane, "INCONCLUSIVE", "VERIFIER_ERROR", evidence)
