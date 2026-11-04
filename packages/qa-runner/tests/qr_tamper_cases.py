# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The product-level tamper and negative suite: each case changes a REAL bundle (written by ``redevops-qa demo``) in one way and names what ``verify`` must report.

``naive`` cases change a file and leave everything else alone; ``rechained`` cases also recompute the manifest the way a forger would; ``forged`` cases hand edited lane files and
a (possibly different) plan to this package's own builder, so the result is internally consistent in every digest. A forged bundle cannot be told from a genuine one by its own
contents: those cases name what an external anchor or a plan digest from outside does catch, and what nothing catches."""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field, replace
from typing import Callable, Dict, Optional, Tuple

from qa_evidence.canon import dumps_canonical, sha256_bytes
from qa_evidence.constants import MANIFEST_NAME
from qr_tamper import edit_json, forge_consistently, golden, load, put, rechain


@dataclass(frozen=True)
class Case:
    name: str
    base: str                                   # the golden bundle it starts from: "none" or "discount"
    mutate: Callable                            # (up, files) -> files
    expect: Tuple[str, ...]                     # finding codes that must all be present (verify exits 5)
    kind: str = "naive"


def _suite_replaced_and_the_plan_pins_edited(up, files):
    """Everything recomputed: the reviewed library replaced (here by a copy with one more line), the PLAN's own pins of the suite edited to match, the bundle's copy replaced, a new lock. The plan
    is different from the one that was frozen, so only a plan digest (or an anchor) from outside shows it."""
    import hashlib
    from qa_runner.golden import demo_plan
    from qa_runner.plan import freeze_plan
    lib = files["lanes/robot/suite/OrderApi.py"] + b"# replaced\n"
    plan = demo_plan()
    plan["lanes"][1]["suite_sha256"]["OrderApi.py"] = "sha256:" + hashlib.sha256(lib).hexdigest()
    frozen = freeze_plan(up, plan, for_verification=True)

    def lane(lid, o):
        if lid != "robot":
            return o
        f = dict(o.files)
        f["lanes/robot/suite/OrderApi.py"] = (lib, f["lanes/robot/suite/OrderApi.py"][1])
        return replace(o, files=f)
    return forge_consistently(up, files, edit_lane=lane, frozen=frozen)


def _list_a_file(path, data, role="log"):
    """A file that the manifest lists and the bundle carries, which no run of the plan writes (a covert payload)."""
    def mutate(up, files):
        out = dict(files)
        out[path] = data
        man = load(out, MANIFEST_NAME)
        man["files"].append({"path": path, "role": role, "digest": sha256_bytes(data), "size": len(data)})
        man["files"].sort(key=lambda e: e["path"])
        put(out, MANIFEST_NAME, man)
        return out
    return mutate


def _drop_blobs(garbage):
    def mutate(up, files):
        out = {k: v for k, v in files.items() if not (k.startswith("lanes/browser/native/blobs/") and not garbage)}
        if garbage:
            out.update({k: b"GARBAGE" for k in files if k.startswith("lanes/browser/native/blobs/")})
        man = load(out, MANIFEST_NAME)
        if not garbage:
            man["files"] = [e for e in man["files"] if e["path"] in out]
        put(out, MANIFEST_NAME, man)
        return rechain(out)
    return mutate


def _flip_robot_to_verified(files):
    def fn(r):
        for x in r["accounting"]["results"]:
            if x["assertion_id"] == "A-ORDER-RULE":
                x["verdict"].update(state="VERIFIED", reason_code="EQUALS_EXPECTED")
    return edit_json(files, "report.json", fn)


def _forge_report_states(up, files, states):
    """The report recomputed by the library itself (all counts, digests and the outcome agree) with chosen verdicts, over the evidence that is really in the bundle."""
    from qa_evidence.report import assemble_report
    rep = load(files, "report.json")
    results = []
    for x in rep["accounting"]["results"]:
        state, reason = states.get(x["assertion_id"], (x["verdict"]["state"], x["verdict"]["reason_code"]))
        results.append({"assertion_id": x["assertion_id"], "native_status": x["native_status"], "state": state, "reason_code": reason,
                        "evidence": (x["verdict"]["provenance"] or {}).get("evidence")})
    frozen = [dict(a) for a in rep["assertion_set"]["assertions"]]
    new = assemble_report(run_id=rep["run_id"], started_at=rep["started_at"], finished_at=rep["finished_at"], plan_digest=rep["plan_digest"], environment=rep["environment"],
                          lanes=rep["lanes"], frozen=frozen, results=results, verifier=rep["verdict"]["provenance"]["verifier"], redaction=rep["redaction"],
                          extensions=rep.get("extensions"))
    out = dict(files)
    put(out, "report.json", new)
    return rechain(out)


def _edit_lock(files, fn):
    return rechain(edit_json(files, "plan.lock.json", fn))


def _other(defect):
    return golden(defect)


def _swap_report(up, files):
    out = dict(files)
    out["report.json"] = _other("none")["report.json"]
    return rechain(out)


def _drop_robot_lane(up, files):
    """Everything recomputed: the plan without the Robot lane, the lanes, the verdicts, the report, the manifest. The failing lane is simply not there."""
    from qa_runner.golden import demo_plan
    from qa_runner.plan import freeze_plan
    plan = demo_plan()
    plan["lanes"] = plan["lanes"][:1]
    frozen = freeze_plan(up, plan)
    return forge_consistently(up, files, edit_lane=lambda lid, o: o, frozen=frozen)


def _weaken_the_assertion(up, files):
    """Everything recomputed: the Robot assertion's frozen expected values replaced by the defective ones the run saw, a new plan lock, a consistent bundle that is VERIFIED."""
    from qa_runner.golden import demo_plan
    from qa_runner.plan import freeze_plan
    plan = demo_plan()
    plan["lanes"][1]["spec"]["assertions"][0]["predicate"]["expected"]["observations"].update(order_101_total_cents=10500, order_103_total_cents=10000, order_104_total_cents=10005)
    return forge_consistently(up, files, edit_lane=lambda lid, o: o, frozen=freeze_plan(up, plan))


def _robot_reports_a_clean_run(up, files):
    """Everything recomputed AND every file that says otherwise rewritten: ``output.xml``, the engine's summary, the adapter result (status, tests and the hashes of the two files it names), the
    observation record, and the reference check of the target (so that no independent fact contradicts the verdict). Nothing in the bundle contradicts itself any more: the unkeyed limit."""
    import hashlib
    def lane(lid, o):
        if lid != "robot":
            return o
        xml = o.native_files["output.xml"].decode()
        for bad, good in (("order_101_total_cents=10500", "order_101_total_cents=9450"), ("order_103_total_cents=10000", "order_103_total_cents=9000"), ("order_104_total_cents=10005", "order_104_total_cents=9005")):
            xml = xml.replace(bad, good)
        xml = xml.replace('<status status="FAIL"', '<status status="PASS"').replace('pass="0" fail="1"', 'pass="1" fail="0"')
        native = dict(o.native_files)
        native["output.xml"] = xml.encode()
        summary = json.loads(native["robot-summary.json"])
        summary["raw_output_sha256"] = hashlib.sha256(native["output.xml"]).hexdigest()
        for t in summary["tests"]:
            t["status"] = "PASS"
        native["robot-summary.json"] = json.dumps(summary, sort_keys=True, indent=1).encode()
        ar = json.loads(native["adapter-result.json"])
        ar.update(status="PASS", exit_code=0, error_code=None)
        for a in ar.get("native_assertions", []):
            a["status"] = "PASS"
        for a in ar["artifacts"]:
            a["sha256"] = hashlib.sha256(native[a["path"]]).hexdigest()
        native["adapter-result.json"] = (json.dumps(ar, sort_keys=True, indent=2) + "\n").encode()
        files_ = dict(o.files)
        from qa_robot import observation_document, parse_observations
        rid = f"{load(files, 'report.json')['run_id']}.robot"
        files_["lanes/robot/observations.json"] = (dumps_canonical(observation_document(parse_observations(native["output.xml"]), run_id=rid, lane_id="robot")), "observation")
        return replace(o, native_status="NATIVE_PASS", raw_status="PASS", exit_code=0, native_files=native, files=files_, counts={"passed": 1, "failed": 0, "errored": 0, "skipped": 0})
    forged = dict(files)
    forged["logs/reference-check.json"] = dumps_canonical({**load(files, "logs/reference-check.json"), "deviations": []})
    return forge_consistently(up, forged, edit_lane=lane)


def _relabel_native_pass(up, files):
    """Only the engine's reported status is changed (with a consistent report): the engine's own files still say FAIL."""
    def lane(lid, o):
        return replace(o, native_status="NATIVE_PASS", raw_status="PASS", exit_code=0, counts={"passed": 1, "failed": 0, "errored": 0, "skipped": 0}) if lid == "robot" else o
    return forge_consistently(up, files, edit_lane=lane)


def _edit_native(lid, name, fn):
    def mutate(up, files):
        def lane(l, o):
            if l != lid:
                return o
            native = dict(o.native_files)
            native[name] = fn(native[name])
            return replace(o, native_files=native)
        return forge_consistently(up, files, edit_lane=lane)
    return mutate


def _edit_lane_file(lid, path, fn):
    def mutate(up, files):
        def lane(l, o):
            if l != lid:
                return o
            f = dict(o.files)
            data, role = f[path]
            f[path] = (fn(data), role)
            return replace(o, files=f)
        return forge_consistently(up, files, edit_lane=lane)
    return mutate


def _json_edit(fn):
    def apply(data):
        doc = json.loads(data)
        fn(doc)
        return dumps_canonical(doc) if data.endswith(b"\n") and data.startswith(b"{\n  ") else json.dumps(doc, sort_keys=True).encode()
    return apply


def _record_edit(fn):
    def apply(data):
        doc = json.loads(data)
        fn(doc)
        return dumps_canonical(doc)
    return apply


def _claim_verified(doc):
    doc["observations"][0]["verified"] = True


def _claim_verified_in_robot_record(doc):
    doc["spec"]["observations"]["verified"] = 1


CASES = [
    # ---- a verdict that does not match the evidence --------------------------------------------------------------------------------------
    Case("forged PASS: the failing verdict flipped in the report, nothing else changed", "discount", lambda up, f: _flip_robot_to_verified(f), ("SIZE_MISMATCH", "VERDICT_RECOMPUTE_MISMATCH")),
    Case("forged PASS: flipped and the manifest re-chained", "discount", lambda up, f: rechain(_flip_robot_to_verified(f)), ("ACCOUNTING_COUNT_MISMATCH", "VERDICT_RECOMPUTE_MISMATCH"), "rechained"),
    Case("forged PASS: the report recomputed by the library over the real evidence", "discount",
         lambda up, f: _forge_report_states(up, f, {"A-ORDER-RULE": ("VERIFIED", "EQUALS_EXPECTED")}), ("VERDICT_RECOMPUTE_MISMATCH",), "forged"),
    Case("flipped verdict: a verified assertion reported as failed over passing evidence", "none",
         lambda up, f: _forge_report_states(up, f, {"A-SAVED": ("FAILED", "EXPECTED_VALUE_DIFFERS")}), ("VERDICT_RECOMPUTE_MISMATCH",), "forged"),
    Case("flipped verdict: the run outcome alone", "discount", lambda up, f: rechain(edit_json(f, "report.json", lambda r: r["verdict"].update(outcome="VERIFIED", reason_code="ALL_ASSERTIONS_VERIFIED"))),
         ("VERDICT_OUTCOME_MISMATCH",), "rechained"),
    Case("an assertion made inconclusive by the report over evidence that satisfies it", "none",
         lambda up, f: _forge_report_states(up, f, {"A-URL": ("INCONCLUSIVE", "EVIDENCE_UNUSABLE")}), ("VERDICT_RECOMPUTE_MISMATCH",), "forged"),
    # ---- what the report says about egress ----------------------------------------------------------------------------------------------------
    Case("the statement of the egress layers of the Robot lane removed from the report", "none",
         lambda up, f: rechain(edit_json(f, "report.json", lambda r: r.update(limitations=[x for x in r["limitations"] if x["id"] != "egress-layers-robot"]))), ("EGRESS_STATEMENT_MISSING",), "rechained"),
    Case("the statement of the egress layers of the Robot lane reworded", "discount",
         lambda up, f: rechain(edit_json(f, "report.json", lambda r: [x.update(text="Egress is enforced.") for x in r["limitations"] if x["id"] == "egress-layers-robot"])), ("EGRESS_STATEMENT_WRONG",), "rechained"),
    # ---- the frozen assertions -------------------------------------------------------------------------------------------------------------
    Case("edited expected value in the plan lock", "none", lambda up, f: _edit_lock(f, lambda l: l["lanes"][1]["assertions"][0]["predicate"]["expected"]["observations"].update(order_101_total_cents=10500)),
         ("LOCK_REJECTED",), "rechained"),
    Case("edited expected value in the plan lock, naive", "none", lambda up, f: edit_json(f, "plan.lock.json", lambda l: l["lanes"][1]["assertions"][0]["predicate"]["expected"]["observations"].update(order_101_total_cents=10500)),
         ("SIZE_MISMATCH", "LOCK_REJECTED")),
    Case("edited assertion digest in the assertion lock", "none", lambda up, f: rechain({**f, "assertion-lock.json": f["assertion-lock.json"].replace(b"sha256:", b"sha256:0", 1)}), ("ASSERTION_LOCK_MISMATCH", "LOCK_ASSERTION_LOCK_MISMATCH"), "rechained"),
    Case("a check program pinned by another hash than the registered one", "none", lambda up, f: _edit_lock(f, lambda l: l["lanes"][1]["assertions"][0]["check_program_ref"].update(program_hash="sha256:" + "0" * 64)),
         ("LOCK_REJECTED",), "rechained"),
    Case("an unknown field in the plan lock", "none", lambda up, f: _edit_lock(f, lambda l: l["lanes"][0].update(verdict="PASS")), ("LOCK_REJECTED",), "rechained"),
    Case("an unknown field in a frozen assertion inside the lock", "none", lambda up, f: _edit_lock(f, lambda l: l["lanes"][0]["assertions"][0].update(verified=True)), ("LOCK_REJECTED",), "rechained"),
    Case("the plan lock removed", "none", lambda up, f: {k: v for k, v in f.items() if k != "plan.lock.json"}, ("MISSING_FILE", "LOCK_MISSING")),
    Case("a changed suite file", "none", lambda up, f: rechain({**f, "lanes/robot/suite/OrderApi.py": f["lanes/robot/suite/OrderApi.py"] + b"# changed\n"}), ("SUITE_FILE_MISMATCH",), "rechained"),
    # ---- dropped lane or assertion ---------------------------------------------------------------------------------------------------------
    Case("the failing lane dropped, everything recomputed (internally consistent; only a plan digest or an anchor from outside shows it)", "discount", _drop_robot_lane, (), "forged"),
    Case("the assertion weakened after planning, everything recomputed (internally consistent; only a plan digest or an anchor from outside shows it)", "discount", _weaken_the_assertion, (), "forged"),
    Case("a lane dropped from the report only", "none", lambda up, f: rechain(edit_json(f, "report.json", lambda r: r.update(lanes=r["lanes"][:1]))), ("UNKNOWN_LANE", "LANES_MISMATCH", "MANIFEST_REPORT_MISMATCH"), "rechained"),
    Case("an assertion dropped from the report only", "none", lambda up, f: rechain(edit_json(f, "report.json", lambda r: r["accounting"].update(results=r["accounting"]["results"][:-1]))), ("ACCOUNTING_MISSING", "VERDICT_NOT_RECORDED"), "rechained"),
    # ---- another run's files ------------------------------------------------------------------------------------------------------------------
    Case("a report swapped in from another run", "discount", _swap_report, ("MANIFEST_REPORT_MISMATCH", "RUN_RECORD_WRONG_RUN", "NATIVE_STATUS_RELABELLED"), "rechained"),
    Case("a lane run id spliced from another run", "none", lambda up, f: rechain(edit_json(f, "report.json", lambda r: r["lanes"][0].update(run_id="r0-other.browser"))), ("LANE_RUN_ID_MISMATCH",), "rechained"),
    Case("replay: the observation file of another run", "discount", lambda up, f: rechain({**f, "lanes/robot/observations.json": golden("none")["lanes/robot/observations.json"]}),
         ("EVIDENCE_NOT_IN_MANIFEST", "VERDICT_RECOMPUTE_MISMATCH"), "rechained"),
    Case("replay: the other run's native report and record, all recomputed", "discount",
         lambda up, f: _edit_native("robot", "output.xml", lambda b: golden("none")["lanes/robot/native/output.xml"])(up, f), ("NATIVE_FILES_DISAGREE",), "forged"),
    # ---- missing or edited artifacts ------------------------------------------------------------------------------------------------------
    Case("a missing native artifact", "none", lambda up, f: {k: v for k, v in f.items() if k != "lanes/robot/native/output.xml"}, ("MISSING_FILE", "VERDICT_RECOMPUTE_MISMATCH")),
    Case("a native artifact removed from the bundle and the manifest", "none", lambda up, f: rechain(edit_json({k: v for k, v in f.items() if k != "lanes/robot/native/output.xml"}, MANIFEST_NAME,
                                                                                                          lambda m: m.update(files=[e for e in m["files"] if e["path"] != "lanes/robot/native/output.xml"]))),
         ("NATIVE_ARTIFACT_MISMATCH", "VERDICT_RECOMPUTE_MISMATCH"), "rechained"),
    Case("an edited native artifact", "none", lambda up, f: {**f, "lanes/robot/native/output.xml": f["lanes/robot/native/output.xml"].replace(b'status="PASS"', b'status="FAIL"', 1)}, ("DIGEST_MISMATCH",)),
    Case("an edited native artifact and the manifest re-chained", "none", lambda up, f: rechain({**f, "lanes/robot/native/output.xml": f["lanes/robot/native/output.xml"] + b" "}), ("NATIVE_ARTIFACT_MISMATCH",), "rechained"),
    Case("a missing observation file", "none", lambda up, f: {k: v for k, v in f.items() if k != "lanes/browser/observations.json"}, ("MISSING_FILE", "VERDICT_RECOMPUTE_MISMATCH")),
    Case("an extra file the manifest does not list", "none", lambda up, f: {**f, "lanes/robot/native/extra.txt": b"x"}, ("EXTRA_FILE",)),
    # ---- duplicates ---------------------------------------------------------------------------------------------------------------------------
    Case("an assertion accounted twice", "none", lambda up, f: rechain(edit_json(f, "report.json", lambda r: r["accounting"]["results"].append(copy.deepcopy(r["accounting"]["results"][0])))), ("ACCOUNTING_DUPLICATE", "ACCOUNTING_COUNT_MISMATCH"), "rechained"),
    Case("an assertion id frozen twice", "none", lambda up, f: rechain(edit_json(f, "report.json", lambda r: r["assertion_set"]["assertions"].append(copy.deepcopy(r["assertion_set"]["assertions"][0])))), ("DUPLICATE_ASSERTION_ID", "FROZEN_SET_MISMATCH"), "rechained"),
    Case("two lanes with the same id", "none", lambda up, f: rechain(edit_json(f, "report.json", lambda r: r["lanes"].append(copy.deepcopy(r["lanes"][0])))), ("DUPLICATE_LANE_ID", "DUPLICATE_RUN_ID", "LANES_MISMATCH"), "rechained"),
    # ---- adapter-supplied claims and relabelled native results -----------------------------------------------------------------------------
    Case("an adapter-supplied 'verified' field in a browser observation, report left as it was", "none",
         lambda up, f: rechain(edit_json(f, "lanes/browser/observations.json", lambda d: d["observations"][0].update(verified=True))), ("EVIDENCE_NOT_IN_MANIFEST", "VERDICT_RECOMPUTE_MISMATCH"), "rechained"),
    Case("an adapter-supplied 'verified' field in a browser observation, everything recomputed", "none",
         _edit_lane_file("browser", "lanes/browser/observations.json", _record_edit(_claim_verified)), (), "claim"),
    Case("an adapter-supplied 'verified' observation in the Robot record, everything recomputed", "none",
         _edit_lane_file("robot", "lanes/robot/observations.json", _record_edit(_claim_verified_in_robot_record)), (), "claim"),
    Case("a VERIFIED status in the engine's own result, everything recomputed", "none",
         _edit_native("robot", "adapter-result.json", lambda b: json.dumps({**json.loads(b), "status": "VERIFIED"}, sort_keys=True).encode()), ("NATIVE_STATUS_UNKNOWN", "NATIVE_RESULT_MISSING"), "forged"),
    Case("native FAIL relabelled as PASS in the report, the engine's files unchanged", "discount", _relabel_native_pass, ("NATIVE_STATUS_RELABELLED",), "forged"),
    Case("a native PASS written as a FAIL in the report", "none", lambda up, f: forge_consistently(up, f, edit_lane=lambda lid, o: replace(o, native_status="NATIVE_FAIL", raw_status="FAIL", exit_code=1,
                                                                                                                                        counts={"passed": 0, "failed": 1, "errored": 0, "skipped": 0}) if lid == "robot" else o),
         ("NATIVE_STATUS_RELABELLED",), "forged"),
    # ---- the harness run record ----------------------------------------------------------------------------------------------------------
    Case("an event payload of the run record edited, everything recomputed", "none",
         _edit_native("browser", "run-record.json", lambda b: dumps_canonical(_edited(json.loads(b), lambda d: d["events"][5]["payload"].update(run_id="other-run")))), ("RUN_RECORD_EVENT_CHAIN",), "forged"),
    Case("an event of the run record dropped, everything recomputed", "none",
         _edit_native("browser", "run-record.json", lambda b: dumps_canonical(_edited(json.loads(b), lambda d: d["events"].pop(7)))), ("RUN_RECORD_EVENT_CHAIN",), "forged"),
    Case("a receipt of the run record dropped, everything recomputed", "none",
         _edit_native("browser", "run-record.json", lambda b: dumps_canonical(_edited(json.loads(b), lambda d: (d["receipts"].pop(), d["receipt_links"].pop())))), ("RUN_RECORD_MANIFEST_RECEIPTS", "RUN_RECORD_SEAL_RECEIPT_HEAD"), "forged"),
    Case("the run record of another run", "none", _edit_native("browser", "run-record.json", lambda b: golden("discount")["lanes/browser/native/run-record.json"]), ("RUN_RECORD_WRONG_RUN", "EXECUTED_SPEC_DIFFERS", "OBSERVATION_NOT_IN_RUN_RECORD"), "forged"),
    Case("an observation that is not what the run record says was read", "none",
         _edit_lane_file("browser", "lanes/browser/observations.json", _record_edit(lambda d: d["observations"][1].update(value="Settings saved!"))), ("OBSERVATION_NOT_IN_RUN_RECORD",), "forged"),
    Case("the allowed origin changed so the executed spec is not the frozen one", "none",
         _edit_lane_file("browser", "lanes/browser/egress-profile.json", _record_edit(lambda d: d["private"][0].update(ports=[1]))), ("EXECUTED_SPEC_DIFFERS",), "forged"),
    # ---- review of #32 and #33 ----------------------------------------------------------------------------------------------------------
    Case("the suite pins deleted from the lock", "none", lambda up, f: _edit_lock(f, lambda l: l["lanes"][1].update(suite_files={})), ("LOCK_REJECTED",), "rechained"),
    Case("the suite pins deleted from the plan inside the lock", "none", lambda up, f: _edit_lock(f, lambda l: l["plan"]["lanes"][1].update(suite_sha256={})), ("LOCK_REJECTED",), "rechained"),
    Case("a suite file replaced and the lock's own copy of the hash updated, the plan's pins untouched", "none",
         lambda up, f: _edit_lock(rechain({**f, "lanes/robot/suite/OrderApi.py": f["lanes/robot/suite/OrderApi.py"] + b"# replaced\n"}),
                                  lambda l: l["lanes"][1]["suite_files"].update({"OrderApi.py": "sha256:" + hashlib.sha256(f["lanes/robot/suite/OrderApi.py"] + b"# replaced\n").hexdigest()})),
         ("LOCK_REJECTED",), "rechained"),
    Case("the suite replaced and the plan's own pins edited to match, everything recomputed (internally consistent; only a plan digest or an anchor from outside shows it)", "discount",
         _suite_replaced_and_the_plan_pins_edited, (), "forged"),
    Case("the blobs the run record refers to deleted", "none", _drop_blobs(False), ("RUN_RECORD_MISSING_BLOB",), "rechained"),
    Case("the blobs the run record refers to replaced by garbage", "none", _drop_blobs(True), ("RUN_RECORD_BLOB_CONTENT",), "rechained"),
    Case("a file no run of the plan writes, listed in the manifest (a lane directory that is not in the plan)", "none", _list_a_file("lanes/ghost/x.bin", b"payload"), ("UNEXPECTED_FILE",), "rechained"),
    Case("a hidden log of 5 MiB", "none", _list_a_file("logs/hidden.bin", b"\0" * (5 * 1024 * 1024)), ("UNEXPECTED_FILE",), "rechained"),
    Case("a note among the records of the Robot lane", "none", _list_a_file("lanes/robot/notes.txt", b"hello", "record"), ("UNEXPECTED_FILE",), "rechained"),
    Case("an adapter result with a duplicate key (the last one wins in plain JSON)", "none",
         _edit_native("robot", "adapter-result.json", lambda b: b.replace(b'"status": "PASS"', b'"status": "FAIL", "status": "PASS"', 1)), ("NATIVE_FILE_UNREADABLE",), "forged"),
    Case("an adapter result with NaN in it", "none", _edit_native("robot", "adapter-result.json", lambda b: b.replace(b'"attempts": 1', b'"attempts": NaN', 1)), ("NATIVE_FILE_UNREADABLE",), "forged"),
    Case("the tool versions removed from the lock", "none", lambda up, f: _edit_lock(f, lambda l: l.pop("pins")), ("LOCK_METADATA_MALFORMED",), "rechained"),
    Case("the runner version of the lock replaced by a list", "none", lambda up, f: _edit_lock(f, lambda l: l.update(runner_version=["x"])), ("LOCK_METADATA_MALFORMED",), "rechained"),
    Case("the label of the egress profile removed", "none", _edit_lane_file("browser", "lanes/browser/egress-profile.json", _record_edit(lambda d: d["private"][0].pop("label"))), ("EGRESS_PROFILE_MISSING",), "forged"),
    Case("a second network allowed by the egress profile", "none", _edit_lane_file("browser", "lanes/browser/egress-profile.json", _record_edit(lambda d: d["private"][0]["networks"].append("10.0.0.0/8"))), ("EGRESS_PROFILE_MISSING",), "forged"),
    Case("a bundle that says a test double produced it", "none", lambda up, f: rechain(edit_json(f, "report.json", lambda r: r.update(extensions={**(r.get("extensions") or {}), "test_double": "lane-command"}))),
         ("TEST_DOUBLE_BUNDLE",), "rechained"),
    # ---- retest of #32 and #33 ------------------------------------------------------------------------------------------------------------
    Case("a lock of the older plan format", "none", lambda up, f: _edit_lock(f, lambda l: l.update(schema_version="1.0")), ("LOCK_UNSUPPORTED_VERSION",), "rechained"),
    Case("the reference check's document reshaped (a key added)", "discount", lambda up, f: rechain(edit_json(f, "logs/reference-check.json", lambda d: d.update(note="x"))), ("REFERENCE_CHECK_MALFORMED",), "rechained"),
    Case("the reference check's deviations dropped from its document", "discount", lambda up, f: rechain(edit_json(f, "logs/reference-check.json", lambda d: d.pop("deviations"))), ("REFERENCE_CHECK_MALFORMED",), "rechained"),
    Case("a result that names another native status than its lane's", "none", lambda up, f: rechain(edit_json(f, "report.json", lambda r: r["accounting"]["results"][0].update(native_status="NATIVE_FAIL"))),
         ("REPORT_FIELD_MISMATCH",), "rechained"),
    Case("a redaction note that claims more than the runner does", "none", lambda up, f: rechain(edit_json(f, "report.json", lambda r: r["redaction"].update(applied=True))), ("REPORT_FIELD_MISMATCH",), "rechained"),
]


def _edited(doc, fn):
    fn(doc)
    return doc


# ---- the checks, shared by the offline suite (golden bundles) and the end-to-end suite (bundles written by the run under test) ------------------------------------------
PLAN_DIGEST = "sha256:67f553bab6744a83ea8f39b8759d15b8b1a3e7dabdd888c3e4bbc86ae4eb444c"
CONSISTENT = [c for c in CASES if c.kind == "forged" and not c.expect]
CLAIMS = [c for c in CASES if c.kind == "claim"]
REJECTED = [c for c in CASES if c.expect]


def check_rejected(up, tmp_path, case, base):
    from qr_tamper import codes, verify_files_in
    v = verify_files_in(tmp_path, case.mutate(up, base(case.base)))
    assert not v.accepted and v.exit_code == 5, (case.name, codes(v))
    assert set(case.expect) <= set(codes(v)), (case.name, codes(v))


def check_consistent_forgery(up, tmp_path, case, base):
    """Internally consistent in every digest: accepted alone, rejected by the anchor of the genuine bundle, and by the plan digest when the plan was changed."""
    from qr_tamper import codes, manifest_digest, verify_files_in
    genuine = base(case.base)
    files = case.mutate(up, genuine)
    alone = verify_files_in(tmp_path, files)
    assert alone.accepted and alone.exit_code in (0, 1, 3, 4), (case.name, codes(alone))
    assert alone.assurance == "internal-consistency-only" and alone.qe.anchor.state == "absent" and alone.qe.plan.state == "absent"
    anchored = verify_files_in(tmp_path, files, anchor=manifest_digest(genuine))
    assert not anchored.accepted and "ANCHOR_MISMATCH" in codes(anchored) and anchored.exit_code == 5
    if "assertion weakened" in case.name or "lane dropped" in case.name or "suite replaced" in case.name:
        planned = verify_files_in(tmp_path, files, plan_digest=PLAN_DIGEST)
        assert not planned.accepted and "PLAN_DIGEST_MISMATCH" in codes(planned)


def check_claim(up, tmp_path, case, base):
    from qr_tamper import verify_files_in
    files = case.mutate(up, base(case.base))
    v = verify_files_in(tmp_path, files)
    report = json.loads(files["report.json"])
    lane = "browser" if "browser" in case.name else "robot"
    states = {r["assertion_id"]: (r["verdict"]["state"], r["verdict"]["reason_code"]) for r in report["accounting"]["results"] if r["lane_id"] == lane}
    assert states and set(states.values()) == {("INCONCLUSIVE", "EVIDENCE_UNUSABLE")}
    assert report["verdict"]["outcome"] == "INCONCLUSIVE" and v.accepted and v.exit_code == 4


def check_dropped_and_weakened(up, tmp_path, base):
    from qr_tamper import verify_files_in
    by_name = {c.name.split(",")[0]: c for c in CONSISTENT}
    dropped = verify_files_in(tmp_path, by_name["the failing lane dropped"].mutate(up, base("discount")))
    assert dropped.outcome["outcome"] == "VERIFIED" and dropped.exit_code == 0           # the forgery works against a verifier that is given nothing from outside
    weakened = verify_files_in(tmp_path, by_name["the assertion weakened after planning"].mutate(up, base("discount")))
    # the evidence that is still in the bundle contradicts the weakened plan twice: the Robot engine's own FAIL and the target's independent reference check, which finds the discount rule deviating.
    # The reference check vetoes the verdict (the assertion is INCONCLUSIVE, EVIDENCE_UNUSABLE), so the run is INCONCLUSIVE and never a plain VERIFIED, even for a forger who rewrote the plan
    assert weakened.accepted and weakened.outcome == {"outcome": "INCONCLUSIVE", "reason_code": "NOT_ALL_ASSERTIONS_VERIFIED"} and weakened.exit_code == 4


def check_the_strongest_forger(up, tmp_path, base):
    """The Robot engine's report, result and summary rewritten to say the rule held, the record re-derived, everything recomputed. The plan was not touched, so the plan digest cannot tell
    either: only the anchor rejects it. This is the documented limit of an unkeyed hash chain."""
    from qr_tamper import codes, manifest_digest, verify_files_in
    genuine = base("discount")
    forged = _robot_reports_a_clean_run(up, genuine)
    alone = verify_files_in(tmp_path, forged)
    assert alone.accepted and alone.exit_code == 0 and alone.outcome["outcome"] == "VERIFIED" and alone.assurance == "internal-consistency-only"
    assert verify_files_in(tmp_path, forged, plan_digest=PLAN_DIGEST).accepted
    anchored = verify_files_in(tmp_path, forged, anchor=manifest_digest(genuine))
    assert not anchored.accepted and "ANCHOR_MISMATCH" in codes(anchored)
    assert verify_files_in(tmp_path, genuine, anchor=manifest_digest(genuine), plan_digest=PLAN_DIGEST).accepted
