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
from qa_evidence.verify import verify_bundle, verify_source

from . import constants as K, egresslog
from .bundle import extra_limitations, finalize_results
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
                "exit_code": self.exit_code, "run_outcome": self.outcome if self.accepted else None,          # a rejected bundle's own claim is not shown as a result
                "engine_verifier_disagreements": self.disagreements if self.accepted else [],
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


OVER_CAP = ("NATIVE_ERROR", "evidence-over-cap")
EGRESS_RAW = ("egress-denied", "egress-fence-lost")         # the raw status of a Robot lane that the kernel layers refused something of, or whose supervisor was lost: always an engine error


def _egress_log(files: Mapping[str, bytes], lane_id: str):
    data = files.get(f"lanes/{lane_id}/{egresslog.LOG_NAME}")
    return None if data is None else egresslog.parse(data)


def _egress_refused(files: Mapping[str, bytes], lane_id: str) -> bool:
    """Whether the lane's own egress log records at least one refusal (or a lost supervisor): what an ``egress-denied`` status rests on."""
    parsed = _egress_log(files, lane_id)
    return parsed is not None and not parsed[2] and egresslog.denied(parsed[1]) > 0
NOT_KEPT_NAME_RE = re.compile(r"^(lanes|logs)/[\x21-\x7e]{1,150}$")


@dataclass(frozen=True)
class Tolerance:
    """What a run that hit the evidence cap is allowed to lack (retest R2-1), and nothing more. ``over``: the lanes the report itself declares an engine error ``evidence-over-cap``, and only when the
    report also says ``evidence_incomplete``. ``names``: the bundle paths the run lists as not kept (``logs/evidence-not-kept.json``). Both can only LOWER a result: a lane reported as an over-cap engine
    error may differ from what its files say (they say it completed; the report refuses to rely on an incomplete record), a listed file may be absent, and as many missing blobs of the run record as were
    listed are accepted. A kept file is checked as always; a missing one that is not listed, a status that is higher than the files say, or a VERIFIED run with incomplete evidence is a finding."""

    over: frozenset = frozenset()
    names: frozenset = frozenset()
    incomplete: bool = False


def _tolerance(files: Mapping[str, bytes], report: Mapping[str, Any], v: "Verification") -> Tolerance:
    incomplete = "evidence_incomplete" in (report.get("extensions") or {})
    data = files.get(K.NOT_KEPT_PATH)
    if not incomplete:
        return Tolerance()                  # a not-kept list without the report saying so is an unexpected file (``_check_file_set``), and tolerates nothing
    v.notes.append("the evidence of this run is INCOMPLETE (it hit the evidence cap: " + safe_text(str(report["extensions"]["evidence_incomplete"]), 160) + "): every assertion that depends on a file that was not kept is "
                   "inconclusive, and the run is never verified")
    if report["verdict"]["outcome"] == "VERIFIED":
        v.add("EVIDENCE_INCOMPLETE_BUT_VERIFIED", "extensions", "the report says the evidence is incomplete and also that the run is VERIFIED: a run with incomplete evidence is never verified")
    names: frozenset = frozenset()
    count = 0
    if data is not None:
        try:
            doc = loads_strict(data)
            listed = doc["names"]
            if doc.get("schema") != K.NOT_KEPT_SCHEMA or doc.get("schema_version") != K.SCHEMA_VERSION or set(doc) != {"schema", "schema_version", "names"} or not (
                    isinstance(listed, list) and len(listed) <= 2000 and all(isinstance(x, str) and NOT_KEPT_NAME_RE.fullmatch(x) for x in listed)):
                raise ValueError("shape")
            if listed != sorted(set(listed)):
                raise ValueError("not in the canonical sorted, unique form the runner writes")
            names = frozenset(listed)
            count = len(listed)
        except (CanonError, KeyError, TypeError, ValueError) as exc:
            v.add("NOT_KEPT_MALFORMED", K.NOT_KEPT_PATH, "the list of files the run did not keep is not of the shape the runner writes" + (f" ({safe_text(str(exc), 80)})" if isinstance(exc, ValueError) and str(exc) != "shape" else ""))
    said = re.match(r"([0-9]{1,6}) file\(s\) not kept", str(report["extensions"]["evidence_incomplete"]))
    if said is None or int(said.group(1)) != count:
        v.add("EVIDENCE_OVER_CAP_NOT_SUPPORTED", "extensions.evidence_incomplete", f"the report says {safe_text(str(report['extensions']['evidence_incomplete']), 60)!r} but the list of files not kept names {count}")
    over = frozenset(l["lane_id"] for l in report["lanes"] if (l["native"]["status"], l["native"]["raw_status"]) == OVER_CAP)
    for lane in report["lanes"]:
        lid = lane["lane_id"]
        if lid not in over:
            continue
        control = f"lanes/{lid}/native/" + ("lane-result.json" if lane["engine"]["name"] == K.ENGINE_PLAYWRIGHT else "adapter-result.json")
        lost = [n for n in names if (n.startswith(f"lanes/{lid}/") or n.startswith(f"logs/{lid}.")) and n not in files]
        if not lost and control in files:
            v.add("EVIDENCE_OVER_CAP_NOT_SUPPORTED", f"lanes/{lid}", "the lane is declared an engine error (evidence-over-cap) but nothing of it is missing: no file of this lane is listed as not kept and absent, and its own result file is there")
    return Tolerance(over=over, names=names, incomplete=True)


def _json(files: Mapping[str, bytes], path: str) -> Any:
    return loads_strict(files[path])


def _lane_files(files: Mapping[str, bytes], lane_id: str) -> Dict[str, bytes]:
    prefix = f"lanes/{lane_id}/native/"
    return {p[len(prefix):]: d for p, d in files.items() if p.startswith(prefix)}


def _check_lock(up: Upstreams, files: Mapping[str, bytes], report: Mapping[str, Any], v: Verification, tol: Tolerance = Tolerance()) -> Optional[FrozenPlan]:
    if LOCK_PATH not in files:
        v.add("LOCK_MISSING", LOCK_PATH, "the bundle carries no plan lock: the frozen assertions cannot be re-derived")
        return None
    try:
        doc = _json(files, LOCK_PATH)
        frozen = thaw_lock(up, doc, for_verification=True)
    except PlanError as exc:
        if exc.code == "UNSUPPORTED_LOCK_VERSION":
            v.add("LOCK_UNSUPPORTED_VERSION", LOCK_PATH, safe_text(str(exc), 300))
            return None
        v.add("LOCK_REJECTED", LOCK_PATH, f"the plan lock does not re-freeze to itself with the pinned parsers ({getattr(exc, 'code', type(exc).__name__)})")
        return None
    except CanonError as exc:
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
                if data is None and not present and status.get(lane.lane_id) not in ("NATIVE_PASS", "NATIVE_FAIL") and lane.lane_id not in tol.over:
                    continue                                            # a lane that never started (cancelled, target down) has no copy of the suite to compare
                if data is None and lane.lane_id in tol.over and f"lanes/{lane.lane_id}/suite/{rel}" in tol.names:
                    continue                                            # the run lists it as not kept (the evidence cap), in a lane that says it hit the cap
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
    incomplete = "evidence_incomplete" in (report.get("extensions") or {})          # the one rule the builder applies: incomplete evidence is never VERIFIED
    if double:
        v.add("TEST_DOUBLE_BUNDLE", "extensions", "this bundle says a lane was produced by a test double: it carries no verdict and is not evidence of a run of the engines")
    for lane in frozen.lanes:
        for r in finalize_results(judge_lane(up, lane, run_id=report["run_id"], files=files), status.get(lane.lane_id, ""), double, _harness_verdicts(files, lane.lane_id), incomplete):
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


def _check_report_fields(frozen: FrozenPlan, files: Mapping[str, bytes], report: Mapping[str, Any], v: Verification) -> None:
    """Fields of the bundle that no verdict reads but that say something: they must be what the run writes (a reshaped reference check, a result that names another native status, a redaction note that
    claims more), so that nothing in the bundle is free text a forger can change without notice."""
    from .bundle import REDACTION
    from .corroborate import REFERENCE_CHECK_PATH, reference_check_shape_ok
    data = files.get(REFERENCE_CHECK_PATH)
    if data is not None:
        try:
            ok = reference_check_shape_ok(loads_strict(data))
        except CanonError:
            ok = False
        if not ok:
            v.add("REFERENCE_CHECK_MALFORMED", REFERENCE_CHECK_PATH, "the reference check's document is not of the shape the runner writes")
    status = {l["lane_id"]: l["native"]["status"] for l in report["lanes"]}
    for r in report["accounting"]["results"]:
        if r.get("native_status") != status.get(r.get("lane_id")):
            v.add("REPORT_FIELD_MISMATCH", safe_text(str(r.get("assertion_id")), 64), "the result names another native status than its lane's")
    if report.get("redaction") != REDACTION:
        v.add("REPORT_FIELD_MISMATCH", "redaction", "the redaction note is not the one the runner writes")
    ids = (K.ROBOT_EGRESS_LIMITATION_ID, K.ROBOT_EGRESS_LAYERS_ID)
    have = [(x.get("id"), x.get("text")) for x in report.get("limitations", []) if isinstance(x, dict) and x.get("id") in ids]
    want = [(x["id"], x["text"]) for x in extra_limitations(frozen)]
    if have != want:
        v.add("EGRESS_STATEMENT_MISSING" if len(have) < len(want) and all(w in want for w in have) else "EGRESS_STATEMENT_WRONG", "limitations",
              "the report must state what limits the egress of the plan's Robot lane(s) (that it is not enforced, or which kernel layers apply and what they do not stop), in the runner's words, and only for the lanes the plan has")


def _check_robot_egress(frozen: FrozenPlan, files: Mapping[str, bytes], report: Mapping[str, Any], v: Verification) -> None:
    """The audit file of every Robot lane that asked for the kernel layers: well formed; written by the layers the plan's profile needs (both, a self-test that passed, the allow-list of the egress profile);
    every allowed decision inside that allow-list; and the lane's native status agrees with it: a refusal (or a lost supervisor) in the log means the lane is an engine error (egress-denied or
    egress-fence-lost), never a completed lane, and such a status needs a refusal in the log. The report's count of refusals is the log's."""
    lanes = {l["lane_id"]: l["native"] for l in report["lanes"]}
    total = 0
    for fl in frozen.lanes:
        if fl.engine != K.ENGINE_ROBOT or fl.egress != "origin-only":
            continue
        lid = fl.lane_id
        path = f"lanes/{lid}/{egresslog.LOG_NAME}"
        native = lanes.get(lid)
        if native is None:
            continue
        parsed = _egress_log(files, lid)
        if parsed is None:
            if native["raw_status"] in EGRESS_RAW:
                v.add("EGRESS_DENIAL_NOT_IN_LOG", path, "the lane is reported as ended by the egress layers but its egress log is not in the bundle")
            continue                                             # a missing file of a lane that completed is EXPECTED_FILE_MISSING (_check_required)
        header, events, problems = parsed
        if problems:
            v.add("EGRESS_LOG_MALFORMED", path, safe_text("; ".join(problems[:3]), 200))
            continue
        origin = lane_origin(fl, files)
        if origin is None:
            v.add("EGRESS_PROFILE_MISSING", f"lanes/{lid}/egress-profile.json", "the egress profile is missing, malformed, or not exactly the one the plan's profile gives for the origin it names")
            continue
        allowed = [f"127.0.0.1/32:{origin.rsplit(':', 1)[1]}"]
        if header.get("event") == "unavailable":
            if native["raw_status"] != "egress-unavailable" or native["status"] != "NATIVE_UNAVAILABLE":
                v.add("EGRESS_LOG_MALFORMED", path, "the log says the layers were unavailable but the lane is not reported as unavailable for that reason")
            continue
        if native["raw_status"] == "egress-unavailable":
            v.add("EGRESS_LOG_MALFORMED", path, "the lane is reported unavailable (egress-unavailable) but its log says the layers were installed")
            continue
        if header.get("layers") != list(egresslog.ALL_LAYERS) or header.get("allowed") != allowed or header["selftest"].get("forbidden_tcp_refused") is not True \
                or header["selftest"].get("udp_refused") is not True:
            v.add("EGRESS_MECHANISM_WRONG", path, "the log does not show both layers installed around the allow-list of the egress profile with a self-test that passed")
        for e in events:
            if e["verdict"] == "allow" and not (e["syscall"] == "connect" and e.get("family") == "AF_INET" and e.get("address") == "127.0.0.1" and f"127.0.0.1/32:{e.get('port')}" in allowed):
                v.add("EGRESS_ALLOW_OUTSIDE_POLICY", path, f"record {e['seq']} allows something that is not the allow-list's address and port")
                break
        refused = egresslog.denied(events)
        total += refused
        if refused and native["status"] in ("NATIVE_PASS", "NATIVE_FAIL"):
            v.add("EGRESS_DENIAL_NOT_REFLECTED", path, f"the log records {refused} refused attempt(s) but the lane is reported as completed ({native['status']}): a refusal ends the lane as an engine error")
        if native["raw_status"] in EGRESS_RAW and (native["status"] != "NATIVE_ERROR" or not refused):
            v.add("EGRESS_DENIAL_NOT_IN_LOG", path, "the lane is reported as ended by the egress layers but its log records no refusal")
        if native["raw_status"] == "egress-fence-lost" and not any(e["verdict"] == "lost" for e in events):
            v.add("EGRESS_DENIAL_NOT_IN_LOG", path, "the lane is reported as having lost its egress supervisor but its log does not say so")
    reported = (report.get("extensions") or {}).get("egress_fence_denied")
    ran = any(fl.engine == K.ENGINE_ROBOT and fl.egress == "origin-only" and f"lanes/{fl.lane_id}/{egresslog.LOG_NAME}" in files for fl in frozen.lanes)
    if reported is not None and (not ran or reported != total):
        v.add("REPORT_FIELD_MISMATCH", "extensions.egress_fence_denied", "the number of refused attempts in the report is not the number in the lanes' egress logs")


def _check_native(frozen: FrozenPlan, files: Mapping[str, bytes], report: Mapping[str, Any], v: Verification, tol: Tolerance = Tolerance()) -> None:
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
        elif derived is not None and derived != got and got == OVER_CAP and lid in tol.over:
            v.notes.append(f"lane {safe_text(lid, 20)}: reported as an engine error (evidence-over-cap) although its own files say {derived[0]} ({safe_text(derived[1], 40)}): the run kept an incomplete record "
                           "and does not rely on it (a lower result than the files give, accepted; the reverse is never accepted)")
        elif derived is not None and derived != got and got[0] == "NATIVE_ERROR" and got[1] in EGRESS_RAW and _egress_refused(files, lid):
            v.notes.append(f"lane {safe_text(lid, 20)}: reported as an engine error ({got[1]}) although its own files say {derived[0]} ({safe_text(derived[1], 40)}): its egress log records a refused attempt "
                           "(a lower result than the files give, accepted; the reverse is never accepted)")
        elif derived is not None and derived != got:
            v.add("NATIVE_STATUS_RELABELLED", f"lanes/{lid}", f"the report says {got[0]} ({got[1]}); the engine's own files say {derived[0]} ({derived[1]})")


def _blob_name_at(rec: Mapping[str, Any], where: str, lane_id: str) -> Optional[str]:
    """The bundle path of the blob the harness integrity check found missing at ``where`` (``<event index>.<field>``, e.g. ``37.screenshot_ref``), or ``None`` when it cannot be told."""
    m = re.fullmatch(r"([0-9]{1,6})\.([a-z0-9_]{1,40})", str(where))
    if m is None:
        return None
    try:
        ref = rec["events"][int(m.group(1))]["payload"][m.group(2)]
        digest = str(ref["ref"] if isinstance(ref, dict) else ref).split(":", 1)[-1]
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    return f"lanes/{lane_id}/native/blobs/{digest}" if BLOB_RE.fullmatch(digest) else None


def _check_run_record(up: Upstreams, frozen: FrozenPlan, files: Mapping[str, bytes], report: Mapping[str, Any], v: Verification, tol: Tolerance = Tolerance()) -> None:
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
            if f.code == "MISSING_BLOB" and lid in tol.over and _blob_name_at(rec, f.where, lid) in tol.names:
                continue                                                # the blob the record points at is one the run lists as not kept, in a lane that hit the cap
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


def _expected_files(frozen: FrozenPlan, tol: Tolerance = Tolerance()) -> Tuple[frozenset, Dict[str, str]]:
    """The paths a run of this plan writes (exactly: the builder and the lanes write nothing else) and the per-lane directories that may hold blobs."""
    names = set(ROOT_FILES)
    if tol.incomplete:
        names.add(K.NOT_KEPT_PATH)
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
            if lane.egress == "origin-only":
                names.add(base + egresslog.LOG_NAME)
    return frozenset(names), blobs


def _required_files(frozen: FrozenPlan, report: Mapping[str, Any], tol: Tolerance) -> List[str]:
    """The files a run of this plan always writes, each of which must be in the bundle or listed as not kept. Run level: the orchestrator's log and the target's request log. For a lane that completed
    (NATIVE_PASS or NATIVE_FAIL): everything its engine and the orchestrator write for it. For a lane declared over the evidence cap: what the orchestrator itself writes for it, never what depends on
    what the engine produced. A lane that did not complete for another reason (it timed out, never started, was cancelled) writes whatever it got to: nothing is required of it."""
    need = ["logs/orchestrator.log", "logs/target-requests.jsonl"]
    status = {l["lane_id"]: l["native"]["status"] for l in report["lanes"]}
    for lane in frozen.lanes:
        lid, base = lane.lane_id, f"lanes/{lane.lane_id}/"
        done = status.get(lid) in ("NATIVE_PASS", "NATIVE_FAIL")
        refused = next((l["native"]["raw_status"] for l in report["lanes"] if l["lane_id"] == lid), "") in EGRESS_RAW
        if lane.engine == K.ENGINE_ROBOT and lane.egress == "origin-only" and (done or refused):
            need.append(base + egresslog.LOG_NAME)           # the audit of the kernel layers: required of a lane that completed and of one that was ended because they refused something
        if not done and lid not in tol.over:
            continue
        need += [base + "egress-profile.json", base + "target-requests.jsonl"]
        if lane.engine == K.ENGINE_PLAYWRIGHT:
            need += [base + "gateway-log.jsonl", base + "browser-guard-log.jsonl"]
            if done:
                need += [base + "native/lane-result.json", base + "native/run-record.json"]
        else:
            need += [base + "suite/" + n for n in lane.suite_files]
            if done:
                need += [base + "native/output.xml", base + "native/robot-summary.json", base + "native/adapter-result.json"]
    return need


def _check_not_kept_names(frozen: FrozenPlan, files: Mapping[str, bytes], v: Verification, tol: Tolerance) -> None:
    """A name in the list of files not kept must be one a run of this plan can write (the expected set, or a blob of a browser lane): a fabricated name is a finding, never an excuse."""
    expected, blob_dirs = _expected_files(frozen, tol)
    for name in sorted(tol.names):
        blob_dir = next((d for d in blob_dirs if name.startswith(d) and BLOB_RE.fullmatch(name[len(d):])), None)
        if blob_dir is not None:
            record = files.get(blob_dir[: -len("blobs/")] + "run-record.json")
            if record is not None and name[len(blob_dir):].encode() not in record:
                # the kept run record is the list of what the lane captured: a blob it never mentions is not one the run could have lost
                v.add("NOT_KEPT_MALFORMED", K.NOT_KEPT_PATH, f"the list names a blob the lane's run record does not refer to: {safe_text(name[len(blob_dir):][:16], 20)}...")
            continue
        if name in expected:
            continue
        v.add("NOT_KEPT_MALFORMED", K.NOT_KEPT_PATH, f"the list names a file no run of this plan writes: {safe_text(name, 100)}")


def _check_required(frozen: FrozenPlan, files: Mapping[str, bytes], report: Mapping[str, Any], v: Verification, tol: Tolerance) -> None:
    for path in _required_files(frozen, report, tol):
        if path not in files and path not in tol.names:
            v.add("EXPECTED_FILE_MISSING", safe_text(path, 120), "a file every run of this plan writes is neither in the bundle nor listed as not kept")


def _check_file_set(frozen: FrozenPlan, files: Mapping[str, bytes], v: Verification, tol: Tolerance = Tolerance()) -> None:
    """A file the bundle lists that no run of this plan writes (a covert payload in a place nobody reads) is a finding, not an extra to ignore."""
    names, blob_dirs = _expected_files(frozen, tol)
    for path in sorted(files):
        if path in names:
            continue
        if any(path.startswith(d) and BLOB_RE.fullmatch(path[len(d):]) for d in blob_dirs):
            continue
        v.add("UNEXPECTED_FILE", safe_text(path, 120), "the bundle lists a file that no run of its plan writes")


def verify_location(location: str, *, anchor: Optional[str] = None, plan_digest: Optional[str] = None, require_anchor: bool = False,
                    require_plan_digest: bool = False, up: Optional[Upstreams] = None, snapshot_seconds: Optional[float] = None) -> Verification:
    """Verify the bundle at ``location``: ONE snapshot is taken by a child process that is killed at the deadline (``isolated``), and everything below is computed from that snapshot, never from the
    files again (a writer that changes them while the verification runs cannot make two checks see two different bundles). Raises ``isolated.IsolatedReadError`` when no snapshot can be taken."""
    from . import isolated
    return verify_snapshot(isolated.snapshot_bundle(location, deadline_s=snapshot_seconds), anchor=anchor, plan_digest=plan_digest, require_anchor=require_anchor,
                           require_plan_digest=require_plan_digest, up=up)


def verify_snapshot(snapshot: Any, *, anchor: Optional[str] = None, plan_digest: Optional[str] = None, require_anchor: bool = False,
                    require_plan_digest: bool = False, up: Optional[Upstreams] = None) -> Verification:
    v = Verification()
    qe = verify_source(snapshot, anchor=anchor, plan_digest=plan_digest)[0]
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
            files = snapshot.files
            report = loads_strict(files["report.json"])
            up = up or verified_bootstrap()
            tol = _tolerance(files, report, v)
            frozen = _check_lock(up, files, report, v, tol)
            if frozen is not None:
                _check_verdicts(up, frozen, files, report, v)
                _check_native(frozen, files, report, v, tol)
                _check_run_record(up, frozen, files, report, v, tol)
                _check_file_set(frozen, files, v, tol)
                _check_required(frozen, files, report, v, tol)
                _check_not_kept_names(frozen, files, v, tol)
                _check_report_fields(frozen, files, report, v)
                _check_robot_egress(frozen, files, report, v)
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
    if v.accepted and v.outcome is not None:
        lines.append(f"  recorded run outcome: {t(v.outcome['outcome'])} ({t(v.outcome['reason_code'])})")
    for d in (v.disagreements if v.accepted else []):
        lines.append(f"  ENGINE_VERIFIER_DISAGREE lane {t(d['lane_id'])}: native {t(d['native_status'])}, verdicts {t(', '.join(d['verdict_states']) or 'none')}")
    for n in v.notes:
        lines.append(f"  note: {t(n)}")
    for f in v.findings:
        lines.append(f"  {t(f.code)} {t(f.where, 120)}: {t(f.message)}")
    if v.accepted and not v.qe.anchor.matches:
        lines.append("  assurance: internal consistency only. Nothing here shows the bundle was not rewritten from start to finish; only a manifest digest published elsewhere (--anchor) does.")
    lines.append("  This does not show that the application under test is correct.")
    return "\n".join(lines) + "\n"
