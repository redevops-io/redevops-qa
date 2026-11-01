# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``redevops-qa verify``: re-verify a finished run from its bundle alone, offline, in a process of its own.

Nothing is taken from the run. The verifier reads the bundle (a directory or an archive), and

1. runs the ``qa-evidence`` offline verification (every file digest, the manifest, the report schema and accounting, the anchor and the plan digest if supplied);
2. re-freezes the plan carried in ``plan.lock.json`` with the pinned parsers and requires every assertion, expected value, digest, pin and check-program hash to be what that
   gives, and the report's frozen set to be exactly the lock's;
3. recomputes every verdict from the files in the bundle (``judge_lane``: the recorded observations against the frozen assertions, the Robot record against the engine's own
   ``output.xml``, the SCRIPT executor over the hash-pinned check program) and compares it with what the report says, assertion by assertion;
4. re-derives each lane's native status from the engine's own files and compares it with the report (a relabelled native result is a finding);
5. checks each browser lane's harness run record: the event and receipt chains, the manifest, the run id, the frozen assertion pin, the executed spec (rebuilt from the frozen
   template and the allowed origin), and that every observation equals what the run record says was read.

It imports no browser, no Robot Framework, no network client, and it opens no socket. What it can and cannot show is in the README: without an external anchor a bundle that was
rewritten consistently from start to finish verifies as INTERNALLY CONSISTENT only; with the manifest digest and the plan digest published elsewhere it does not.
"""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

from qa_evidence.build import BuildError, read_files
from qa_evidence.canon import CanonError, loads_strict, safe_text
from qa_evidence.report import engine_verifier_disagreements
from qa_evidence.sources import SourceError
from qa_evidence.verify import verify_bundle

from . import constants as K
from .bundle import finalize_results
from .corroborate import BundleBlobs, plain_json, lane_origin, record_contradicts_itself
from .deps import Upstreams, pin_summary, verified_bootstrap
from .errors import EnvironmentFault, PlanError
from .judge import judge_lane, observation_path
from .natives import native_from_adapter_result, native_from_harness
from .exits import exit_code_for
from .plan import FrozenPlan, materialise_spec, thaw_lock

LOCK_PATH = "plan.lock.json"


@dataclass(frozen=True)
class Finding:
    code: str
    where: str
    message: str

    def to_json(self) -> Dict[str, str]:
        return {"code": self.code, "where": self.where, "message": self.message}


@dataclass
class Verification:
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    qe: Any = None                                   # the qa-evidence VerifyResult
    outcome: Optional[Dict[str, str]] = None
    disagreements: List[Dict[str, Any]] = field(default_factory=list)
    recomputed: int = 0
    agreeing: int = 0
    run_exit_code: int = K.EXIT_INCONCLUSIVE
    unavailable: bool = False                        # the verifier itself could not run here (a pinned dependency, git): nothing was verified, which is not a verdict about the bundle

    def add(self, code: str, where: str, message: str) -> None:
        self.findings.append(Finding(code, where, message))

    @property
    def accepted(self) -> bool:
        return not self.unavailable and not self.findings and self.qe is not None and self.qe.ok

    @property
    def exit_code(self) -> int:
        if self.unavailable:
            return K.EXIT_VERIFIER_UNAVAILABLE
        return self.run_exit_code if self.accepted else K.EXIT_REJECTED

    @property
    def assurance(self) -> str:
        if self.unavailable:
            return "not-verified"
        if not self.accepted:
            return "rejected"
        return "matches-supplied-anchor" if self.qe.anchor.matches else "internal-consistency-only"

    def to_json(self) -> Dict[str, Any]:
        q = self.qe
        return {"schema": "redevops-qa/verify-result", "schema_version": K.SCHEMA_VERSION, "accepted": self.accepted, "assurance": self.assurance,
                "exit_code": self.exit_code, "run_outcome": self.outcome, "engine_verifier_disagreements": self.disagreements,
                "recomputed_assertions": self.recomputed, "agreeing_assertions": self.agreeing,
                "anchor": _anchor_json(q.anchor) if q is not None else None, "plan": q.plan.to_json() if q is not None and q.plan is not None else None,
                "findings": [f.to_json() for f in self.findings], "notes": list(self.notes)}


def _anchor_json(anchor: Any) -> Dict[str, Any]:
    """The anchor as qa-evidence reports it, with one word changed: a value that equals the manifest digest is ``matches-supplied-value``, not ``verified``. Nothing here authenticates where the
    supplied value came from (a digest copied from the same bundle matches too)."""
    doc = anchor.to_json()
    if doc.get("state") == "verified":
        doc["state"] = "matches-supplied-value"
    return doc


def _json(files: Mapping[str, bytes], path: str) -> Any:
    return loads_strict(files[path])


def _lane_files(files: Mapping[str, bytes], lane_id: str) -> Dict[str, bytes]:
    prefix = f"lanes/{lane_id}/native/"
    return {p[len(prefix):]: d for p, d in files.items() if p.startswith(prefix)}


def _check_lock(up: Upstreams, files: Mapping[str, bytes], report: Mapping[str, Any], v: Verification) -> Optional[FrozenPlan]:
    if LOCK_PATH not in files:
        v.add("LOCK_MISSING", LOCK_PATH, "the bundle carries no plan lock: the frozen assertions cannot be re-derived")
        return None
    try:
        doc = _json(files, LOCK_PATH)
        frozen = thaw_lock(up, doc, for_verification=True)
    except (CanonError, PlanError) as exc:
        v.add("LOCK_REJECTED", LOCK_PATH, f"the plan lock does not re-freeze to itself with the pinned parsers ({getattr(exc, 'code', type(exc).__name__)})")
        return None
    pins = pin_summary(up)
    given_pins, given_version = doc.get("pins"), doc.get("runner_version")
    if not (isinstance(given_pins, dict) and set(given_pins) == set(pins) and all(isinstance(x, str) and 0 < len(x) <= 200 for x in given_pins.values())):
        v.add("LOCK_METADATA_MALFORMED", LOCK_PATH, "the tool versions the lock names are missing or are not the kind of value a lock carries")
    elif given_pins != pins:
        v.notes.append("the tool versions in the lock differ from the ones loaded here (verification re-derived every digest with the tools loaded here; they agree)")
    if not (isinstance(given_version, str) and 0 < len(given_version) <= 64):
        v.add("LOCK_METADATA_MALFORMED", LOCK_PATH, "the runner version the lock names is missing or is not a short string")
    if frozen.plan_digest != report["plan_digest"]:
        v.add("LOCK_REPORT_MISMATCH", "plan_digest", "the plan digest of the re-frozen lock is not the report's")
    if files.get("assertion-lock.json") != frozen.assertion_lock_bytes():
        v.add("LOCK_ASSERTION_LOCK_MISMATCH", "assertion-lock.json", "the assertion lock in the bundle is not the one the plan lock gives")
    if report["assertion_set"]["assertions"] != sorted(frozen.rows, key=lambda r: r["assertion_id"]):
        v.add("FROZEN_SET_MISMATCH", "assertion_set", "the frozen assertions in the report are not exactly the ones the plan lock gives")
    if [(l["lane_id"], l["engine"]["name"]) for l in report["lanes"]] != [(l.lane_id, l.engine) for l in frozen.lanes]:
        v.add("LANES_MISMATCH", "lanes", "the lanes of the report (ids, engines, order) are not the lanes of the frozen plan")
    status = {l["lane_id"]: l["native"]["status"] for l in report["lanes"]}
    for lane in frozen.lanes:
        if lane.suite:
            try:
                from .suites import suite_digests
                if suite_digests(lane.suite) != dict(lane.suite_files):
                    v.notes.append(f"lane {safe_text(lane.lane_id, 20)}: the suite files this plan pins are not the ones this version of the runner ships (the run used older or other files; "
                                   "what the plan pins is what the bundle's copies are compared with, and the pins are part of the plan digest)")
            except PlanError:
                pass
            present = any(p.startswith(f"lanes/{lane.lane_id}/suite/") for p in files)
            for rel, digest in lane.suite_files.items():
                from qa_evidence.canon import sha256_bytes
                data = files.get(f"lanes/{lane.lane_id}/suite/{rel}")
                if data is None and not present and status.get(lane.lane_id) not in ("NATIVE_PASS", "NATIVE_FAIL"):
                    continue                                            # a lane that never started (cancelled, target down) has no copy of the suite to compare
                if data is None or sha256_bytes(data) != digest:
                    v.add("SUITE_FILE_MISMATCH", f"lanes/{lane.lane_id}/suite/{rel}", "the suite file in the bundle is not the one the plan lock froze")
    return frozen


def _harness_verdicts(files: Mapping[str, bytes], lane_id: str) -> Dict[str, str]:
    try:
        doc = loads_strict(files[f"lanes/{lane_id}/native/lane-result.json"])
    except (KeyError, CanonError):
        return {}
    out = {}
    for item in doc.get("harness_verdicts") or []:
        if isinstance(item, dict) and isinstance(item.get("assertion_id"), str) and item.get("verdict") in ("PASS", "FAIL", "INDETERMINATE"):
            out[item["assertion_id"]] = item["verdict"]
    return out


def _check_verdicts(up: Upstreams, frozen: FrozenPlan, files: Mapping[str, bytes], report: Mapping[str, Any], v: Verification) -> None:
    recorded = {r["assertion_id"]: r for r in report["accounting"]["results"]}
    status = {l["lane_id"]: l["native"]["status"] for l in report["lanes"]}          # the reported native status is itself re-derived from the engine's files by _check_native
    double = bool((report.get("extensions") or {}).get("test_double"))
    if double:
        v.add("TEST_DOUBLE_BUNDLE", "extensions", "this bundle says a lane was produced by a test double: it carries no verdict and is not evidence of a run of the engines")
    for lane in frozen.lanes:
        for r in finalize_results(judge_lane(up, lane, run_id=report["run_id"], files=files), status.get(lane.lane_id, ""), double, _harness_verdicts(files, lane.lane_id)):
            v.recomputed += 1
            got = recorded.get(r["assertion_id"])
            if got is None:
                v.add("VERDICT_NOT_RECORDED", r["assertion_id"], "a frozen assertion has no result in the report")
                continue
            prov = got["verdict"]["provenance"] or {}
            same = (got["verdict"]["state"] == r["state"] and got["verdict"]["reason_code"] == r["reason_code"] and prov.get("evidence") == r["evidence"]
                    and got["lane_id"] == lane.lane_id)
            if same:
                v.agreeing += 1
            else:
                v.add("VERDICT_RECOMPUTE_MISMATCH", r["assertion_id"], f"the report says {got['verdict']['state']} ({got['verdict']['reason_code']}); recomputed from the bundle: "
                      f"{r['state']} ({r['reason_code']})")


def _check_native(frozen: FrozenPlan, files: Mapping[str, bytes], report: Mapping[str, Any], v: Verification) -> None:
    for lane in report["lanes"]:
        lid, native = lane["lane_id"], lane["native"]
        got = (native["status"], native["raw_status"])
        mine = _lane_files(files, lid)
        derived: Optional[Tuple[str, str]] = None
        try:
            if lane["engine"]["name"] == K.ENGINE_PLAYWRIGHT:
                if "lane-result.json" in mine:
                    doc = loads_strict(mine["lane-result.json"])
                    if doc.get("status") == "COMPLETED":
                        derived = native_from_harness(str(doc.get("outcome")), doc.get("reason"))
                        if "run-record.json" in mine:
                            rec = loads_strict(mine["run-record.json"])
                            if rec.get("classification", {}).get("outcome") != doc.get("outcome") or rec.get("exit_code") != doc.get("exit_code"):
                                v.add("NATIVE_FILES_DISAGREE", f"lanes/{lid}/native", "the lane result and the harness run record do not name the same outcome and exit code")
            elif lane["engine"]["name"] == K.ENGINE_ROBOT:
                if "adapter-result.json" in mine:
                    doc = plain_json(mine["adapter-result.json"])
                    derived = native_from_adapter_result(doc.get("status"), doc.get("error_code"))
                    if derived is None:
                        v.add("NATIVE_STATUS_UNKNOWN", f"lanes/{lid}/native/adapter-result.json", "the engine result carries a status this verifier does not map (never read as a pass)")
                    if "output.xml" in mine and derived is not None and derived[0] in ("NATIVE_PASS", "NATIVE_FAIL"):
                        from qa_robot import parse_output_xml
                        tests = [a.status.value for a in parse_output_xml(mine["output.xml"]).assertions]
                        if (derived[0] == "NATIVE_PASS") != all(s == "PASS" for s in tests) or (derived[0] == "NATIVE_FAIL") != any(s == "FAIL" for s in tests):
                            v.add("NATIVE_FILES_DISAGREE", f"lanes/{lid}/native", "the engine result and the engine's own report do not tell the same story")
        except (CanonError, ValueError, UnicodeDecodeError, Exception) as exc:      # an unreadable native file is a finding, never a pass
            v.add("NATIVE_FILE_UNREADABLE", f"lanes/{lid}/native", f"a native file of this lane cannot be read ({type(exc).__name__})")
            continue
        if native["status"] in ("NATIVE_PASS", "NATIVE_FAIL") and derived is None:
            v.add("NATIVE_RESULT_MISSING", f"lanes/{lid}/native", "the lane is reported as completed but the engine's own result file is not in the bundle")
        elif derived is not None and derived != got:
            v.add("NATIVE_STATUS_RELABELLED", f"lanes/{lid}", f"the report says {got[0]} ({got[1]}); the engine's own files say {derived[0]} ({derived[1]})")


def _check_run_record(up: Upstreams, frozen: FrozenPlan, files: Mapping[str, bytes], report: Mapping[str, Any], v: Verification) -> None:
    h = up.harness
    for lane in frozen.lanes:
        if lane.engine != K.ENGINE_PLAYWRIGHT:
            continue
        lid = lane.lane_id
        path = f"lanes/{lid}/native/run-record.json"
        reported = next((l for l in report["lanes"] if l["lane_id"] == lid), None)
        if path not in files:
            if reported is not None and reported["native"]["status"] in ("NATIVE_PASS", "NATIVE_FAIL"):
                v.add("RUN_RECORD_MISSING", path, "a completed browser lane has no harness run record")
            continue
        try:
            rec = _json(files, path)
            receipts = [h.records.ActionReceipt.from_json(copy.deepcopy(r)) for r in rec["receipts"]]
            links = [h.receipts.ChainLink(**l) for l in rec["receipt_links"]]
            manifest = h.records.RunManifest.from_json(copy.deepcopy(rec["manifest"]))
        except Exception as exc:
            v.add("RUN_RECORD_UNREADABLE", path, f"the harness run record cannot be read ({type(exc).__name__})")
            continue
        found = h.integrity.verify_run_evidence(events=rec["events"], receipts=receipts, links=links, manifest=manifest, blobs=BundleBlobs(h, files, lid))
        for f in found.findings:
            v.add(f"RUN_RECORD_{f.code}", path, f"the harness integrity check found {f.code} at {safe_text(f.where, 40)}")
        contradiction = record_contradicts_itself(rec, manifest)
        if contradiction is not None:
            v.add("RUN_RECORD_CONTRADICTS_ITSELF", path, contradiction)
        if rec.get("sealed") is not True or rec.get("cancelled") is not False:
            if reported is not None and reported["native"]["status"] in ("NATIVE_PASS", "NATIVE_FAIL"):
                v.add("RUN_RECORD_NOT_SEALED_OR_CANCELLED", path, "a completed browser lane's run record is not sealed or says the run was cancelled")
        if rec.get("run_id") != f"{report['run_id']}.{lid}" or manifest.run_id != f"{report['run_id']}.{lid}":
            v.add("RUN_RECORD_WRONG_RUN", path, "the run record belongs to another run id than this lane's")
        if manifest.assertion_set_hash != lane.harness_pin:
            v.add("RUN_RECORD_WRONG_ASSERTIONS", path, "the run was verified in-run against another assertion set than the frozen one")
        origin = lane_origin(lane, files)
        if origin is None:
            v.add("EGRESS_PROFILE_MISSING", f"lanes/{lid}/egress-profile.json", "the egress profile is missing, malformed, or not exactly the one the plan's profile gives for the origin it names")
        else:
            try:
                executed = h.records.TestSpec.from_json(materialise_spec(lane.spec_template, origin))
                if manifest.spec_ref != executed.spec_ref():
                    v.add("EXECUTED_SPEC_DIFFERS", path, "the spec the run executed is not the frozen template with the allowed origin")
            except Exception as exc:
                v.add("EXECUTED_SPEC_DIFFERS", path, f"the executed spec cannot be rebuilt from the frozen template ({type(exc).__name__})")
        try:
            obs = loads_strict(files[observation_path(lid)])["observations"]
        except (KeyError, CanonError, TypeError):
            continue                                                    # a missing or unreadable observation file is already an inconclusive verdict
        by_id = {r.assertion_id: r for r in manifest.assertion_results}
        for row in obs:
            r = by_id.get(row.get("assertion_id")) if isinstance(row, dict) else None
            if r is not None and (r.actual != row.get("value") or r.actual_digest != row.get("value_digest")):
                v.add("OBSERVATION_NOT_IN_RUN_RECORD", observation_path(lid), f"the observation of {safe_text(row.get('assertion_id'), 64)} is not what the harness run record says was read")


ROOT_FILES = frozenset({"report.json", "bundle-manifest.json", "assertion-lock.json", "BUNDLE-FORMAT.txt", LOCK_PATH, "logs/orchestrator.log", "logs/target-requests.jsonl", "logs/reference-check.json"})
BLOB_RE = re.compile(r"^[0-9a-f]{64}$")


def _expected_files(frozen: FrozenPlan) -> Tuple[frozenset, Dict[str, str]]:
    """The paths a run of this plan writes (exactly: the builder and the lanes write nothing else) and the per-lane directories that may hold blobs."""
    names = set(ROOT_FILES)
    blobs: Dict[str, str] = {}
    for lane in frozen.lanes:
        base = f"lanes/{lane.lane_id}/"
        names |= {base + n for n in ("observations.json", "egress-profile.json", "target-requests.jsonl")}
        names |= {f"logs/{lane.lane_id}.stdout.txt", f"logs/{lane.lane_id}.stderr.txt"}
        if lane.engine == K.ENGINE_PLAYWRIGHT:
            names |= {base + n for n in ("gateway-log.jsonl", "browser-guard-log.jsonl", "native/lane-result.json", "native/run-record.json")}
            blobs[base + "native/blobs/"] = lane.lane_id
        else:
            names |= {base + n for n in ("native/output.xml", "native/robot-summary.json", "native/adapter-result.json")}
            names |= {base + "suite/" + n for n in lane.suite_files}
    return frozenset(names), blobs


def _check_file_set(frozen: FrozenPlan, files: Mapping[str, bytes], v: Verification) -> None:
    """A file the bundle lists that no run of this plan writes (a covert payload in a place nobody reads) is a finding, not an extra to ignore."""
    names, blob_dirs = _expected_files(frozen)
    for path in sorted(files):
        if path in names:
            continue
        if any(path.startswith(d) and BLOB_RE.fullmatch(path[len(d):]) for d in blob_dirs):
            continue
        v.add("UNEXPECTED_FILE", safe_text(path, 120), "the bundle lists a file that no run of its plan writes")


def verify_location(location: str, *, anchor: Optional[str] = None, plan_digest: Optional[str] = None, require_anchor: bool = False,
                    require_plan_digest: bool = False, up: Optional[Upstreams] = None) -> Verification:
    v = Verification()
    qe = verify_bundle(location, anchor=anchor, plan_digest=plan_digest)
    v.qe = qe
    for f in qe.findings:
        v.add(f.code, f.path, f.message)
    v.disagreements = list(qe.disagreements or [])
    if qe.run_outcome is not None:
        v.outcome = dict(qe.run_outcome)
    if require_anchor and not qe.anchor.matches:
        v.add("ANCHOR_REQUIRED", "anchor", "an external anchor was required and none matched: " + qe.anchor.notice)
    if require_plan_digest and not (qe.plan is not None and qe.plan.matches):
        v.add("PLAN_DIGEST_REQUIRED", "plan", "a plan digest from outside the bundle was required and none matched")
    if qe.complete:
        try:
            files = read_files(location)
            report = loads_strict(files["report.json"])
            up = up or verified_bootstrap()
            frozen = _check_lock(up, files, report, v)
            if frozen is not None:
                _check_verdicts(up, frozen, files, report, v)
                _check_native(frozen, files, report, v)
                _check_run_record(up, frozen, files, report, v)
                _check_file_set(frozen, files, v)
            v.run_exit_code = exit_code_for(report)
        except EnvironmentFault as exc:
            v.unavailable = True
            v.add("VERIFIER_UNAVAILABLE", "", f"the verifier cannot run here ({safe_text(exc.code, 60)}); nothing was verified, and that says nothing about the bundle")
        except (BuildError, SourceError, CanonError, KeyError, TypeError) as exc:
            v.add("VERIFY_INCOMPLETE", "", f"the bundle could not be read in full ({type(exc).__name__}); nothing is accepted")
        except Exception as exc:            # a bundle crafted to crash the verifier is rejected, never an 'internal error' that a caller could read as a fault of its own
            v.add("VERIFY_INCOMPLETE", "", f"the verification could not be completed ({type(exc).__name__}); nothing is accepted")
    return v


def render_text(location: str, v: Verification) -> str:
    t = lambda x, n=300: safe_text(x, n)         # noqa: E731
    head = "ACCEPTED (internally consistent)" if v.accepted else ("NOT VERIFIED: the verifier cannot run here" if v.unavailable else f"REJECTED, {len(v.findings)} finding(s)")
    lines = [f"verify {t(location)}: " + head]
    if v.qe is not None:
        lines.append(f"  recomputation: {v.recomputed} assertion(s) recomputed from the bundle alone, {v.agreeing} agree with the report")
        lines.append(f"  external anchor: {v.qe.anchor.notice}")
        if v.qe.plan is not None:
            lines.append(f"  frozen assertion set: {v.qe.plan.notice}")
    if v.outcome is not None:
        lines.append(f"  recorded run outcome: {t(v.outcome['outcome'])} ({t(v.outcome['reason_code'])})")
    for d in v.disagreements:
        lines.append(f"  ENGINE_VERIFIER_DISAGREE lane {t(d['lane_id'])}: native {t(d['native_status'])}, verdicts {t(', '.join(d['verdict_states']) or 'none')}")
    for n in v.notes:
        lines.append(f"  note: {t(n)}")
    for f in v.findings:
        lines.append(f"  {t(f.code)} {t(f.where, 120)}: {t(f.message)}")
    if v.accepted and not v.qe.anchor.matches:
        lines.append("  assurance: internal consistency only. Nothing here shows the bundle was not rewritten from start to finish; only a manifest digest published elsewhere (--anchor) does.")
    lines.append("  This does not show that the application under test is correct.")
    return "\n".join(lines) + "\n"
