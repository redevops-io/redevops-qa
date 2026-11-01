# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The bundle builder: a pure function from collected lane outcomes to an evidence bundle. Native status and verdict stay apart; nothing is VERIFIED unless the engine ran to
completion and passed AND the independent recomputation (after the lane's own claims were corroborated) verified every frozen assertion. The lane files are those of REAL runs."""
import json

import pytest

from qa_evidence.build import BuildError
from qa_evidence.verify import verify_files
from qa_runner.bundle import LaneOutcome, RunInputs, build_run_bundle, finalize_results
from qr_data import BROWSER_RUN, browser_files

ENV = {"os": "linux", "arch": "x86_64", "python": "3.12.3"}


def lane(defect="none", status="NATIVE_PASS", raw="PASS", exit_code=0, harness=None, native=None, obs=True, double=False):
    """The lane outcome of a real run (its files), with the engine status chosen by the test."""
    files = browser_files(defect)
    nat = {p[len("lanes/browser/native/"):]: d for p, d in files.items() if p.startswith("lanes/browser/native/")} if native is None else native
    other = {p: (files[p], role) for p, role in (("lanes/browser/observations.json", "observation"), ("lanes/browser/egress-profile.json", "record"),
                                                 ("lanes/browser/target-requests.jsonl", "log")) if (obs or role != "observation")}
    if harness is None:
        harness = {i["assertion_id"]: i["verdict"] for i in json.loads(files["lanes/browser/native/lane-result.json"])["harness_verdicts"]}
    return LaneOutcome(lane_id="browser", engine_name="playwright-chromium", engine_version="1.64.1", native_status=status, raw_status=raw, exit_code=exit_code,
                       native_files=nat, files=other, harness_verdicts=harness, double=double)


def build(up, frozen, outcome, defect="none", extra_logs=True, extensions=None):
    files = browser_files(defect)
    logs = {"logs/orchestrator.log": b"line\n"}
    if extra_logs:
        logs["logs/reference-check.json"] = files["logs/reference-check.json"]
    inputs = RunInputs(frozen=frozen, run_id=BROWSER_RUN[defect], started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:05Z", environment=ENV, lanes=(outcome,),
                       logs=logs, extensions=extensions or {"target_defect": defect})
    return build_run_bundle(up, inputs)


def report_of(bundle):
    return json.loads(bundle.files["report.json"])


def test_a_passing_lane_whose_observations_satisfy_the_frozen_assertions_is_verified_and_the_bundle_verifies(up, golden_frozen):
    b = build(up, golden_frozen, lane())
    r = report_of(b)
    assert r["verdict"] == {**r["verdict"], "outcome": "VERIFIED", "reason_code": "ALL_ASSERTIONS_VERIFIED"}
    assert r["accounting"]["frozen"] == r["accounting"]["verified"] == 3 and r["accounting"]["unaccounted"] == 0
    result = verify_files(b.files, plan_digest=golden_frozen.plan_digest)
    assert result.ok and result.plan.state == "verified" and result.anchor.state == "absent"


def test_the_engine_status_and_the_verdict_are_separate_fields_with_disjoint_vocabularies(up, golden_frozen):
    r = report_of(build(up, golden_frozen, lane()))
    assert r["lanes"][0]["native"]["status"] == "NATIVE_PASS"
    assert {x["verdict"]["state"] for x in r["accounting"]["results"]} == {"VERIFIED"}
    assert {x["native_status"] for x in r["accounting"]["results"]} == {"NATIVE_PASS"}


def test_a_native_pass_never_makes_a_verified_verdict_without_the_recomputation(up, golden_frozen):
    files = browser_files("settings")
    # the engine says PASS and the observation file says the box was ticked; the run record (the real one) says it was not
    forged = json.loads(files["lanes/browser/observations.json"])
    for o in forged["observations"]:
        if o["assertion_id"] == "A-NOTIF-ON":
            o["value"] = True
    from qa_evidence.canon import dumps_canonical
    out = lane("settings", harness={"A-NOTIF-ON": "PASS", "A-SAVED": "PASS", "A-URL": "PASS"})
    out = LaneOutcome(**{**out.__dict__, "files": {**out.files, "lanes/browser/observations.json": (dumps_canonical(forged), "observation")}})
    r = report_of(build(up, golden_frozen, out, "settings"))
    assert r["verdict"]["outcome"] != "VERIFIED" and r["lanes"][0]["native"]["status"] == "NATIVE_PASS"
    assert {x["verdict"]["state"] for x in r["accounting"]["results"]} == {"INCONCLUSIVE"}
    r = report_of(build(up, golden_frozen, lane(obs=False)))
    assert r["verdict"]["outcome"] != "VERIFIED"


def test_a_failed_assertion_fails_the_run_even_when_the_engine_reported_a_pass(up, golden_frozen):
    r = report_of(build(up, golden_frozen, lane("settings", status="NATIVE_PASS", raw="PASS", exit_code=0), "settings"))
    assert r["verdict"]["outcome"] == "FAILED" and r["accounting"]["failed"] == 1 and r["accounting"]["verified"] == 2


@pytest.mark.parametrize("status,raw,code", [("NATIVE_ERROR", "error", 3), ("NATIVE_TIMEOUT", "timeout", None), ("NATIVE_UNAVAILABLE", "target-not-started", None),
                                             ("NATIVE_SKIPPED", "cancelled-before-start", None)])
def test_a_lane_that_did_not_run_to_completion_is_never_verified_and_carries_no_verified_or_failed_assertion(up, golden_frozen, status, raw, code):
    """Review finding M7: not even with files that look perfect, and not a FAILED either (a defective target's files would give FAILED and exit 1 for an engine that did not finish)."""
    for defect in ("none", "settings"):
        r = report_of(build(up, golden_frozen, lane(defect, status=status, raw=raw, exit_code=code), defect))
        assert r["verdict"]["outcome"] == "INCONCLUSIVE" and r["verdict"]["reason_code"] == "NOT_ALL_ASSERTIONS_VERIFIED"
        assert {x["verdict"]["state"] for x in r["accounting"]["results"]} == {"INCONCLUSIVE"} and r["lanes"][0]["native"]["status"] == status


def test_finalize_results_downgrades_verified_and_failed_for_an_engine_that_did_not_complete():
    judged = [{"assertion_id": "A", "state": "VERIFIED", "reason_code": "EQUALS_EXPECTED", "evidence": None}, {"assertion_id": "B", "state": "FAILED", "reason_code": "EXPECTED_VALUE_DIFFERS",
                                                                                                        "evidence": None}]
    for status in ("NATIVE_ERROR", "NATIVE_TIMEOUT", "NATIVE_UNAVAILABLE", "NATIVE_SKIPPED"):
        assert {(r["state"], r["reason_code"]) for r in finalize_results(judged, status, False, {})} == {("INCONCLUSIVE", "EVIDENCE_UNUSABLE")}
    assert [r["state"] for r in finalize_results(judged, "NATIVE_PASS", False, {})] == ["VERIFIED", "FAILED"]


def test_a_lane_produced_by_a_test_double_never_carries_a_verdict(up, golden_frozen):
    """Review finding H1: the double of the tests used to produce VERIFIED with an empty target log. It is now labelled and can only be INCONCLUSIVE (TEST_DOUBLE), whatever its files say."""
    b = build(up, golden_frozen, lane(double=True), extensions={"target_defect": "none", "test_double": "lane-command"})
    r = report_of(b)
    assert r["verdict"]["outcome"] == "INCONCLUSIVE" and {(x["verdict"]["state"], x["verdict"]["reason_code"]) for x in r["accounting"]["results"]} == {("INCONCLUSIVE", "TEST_DOUBLE")}
    assert r["extensions"]["test_double"] == "lane-command"


def test_a_lane_with_no_evidence_at_all_accounts_for_every_assertion_as_inconclusive(up, golden_frozen):
    r = report_of(build(up, golden_frozen, lane(status="NATIVE_TIMEOUT", raw="timeout", exit_code=None, obs=False, native={}, harness={}), extra_logs=False))
    assert r["accounting"] == {**r["accounting"], "frozen": 3, "inconclusive": 3, "verified": 0, "failed": 0, "unaccounted": 0}
    assert {x["verdict"]["reason_code"] for x in r["accounting"]["results"]} <= {"EVIDENCE_MISSING", "EVIDENCE_UNUSABLE"}


def test_each_result_carries_the_native_status_of_its_own_lane(up, golden_frozen):
    r = report_of(build(up, golden_frozen, lane(status="NATIVE_TIMEOUT", raw="timeout", exit_code=None)))
    assert {x["native_status"] for x in r["accounting"]["results"]} == {"NATIVE_TIMEOUT"}


def test_a_native_fail_lane_whose_assertions_are_all_verified_is_inconclusive_with_the_named_reason(up, golden_frozen):
    """R1 at the product layer: never a plain VERIFIED, and verify says so."""
    b = build(up, golden_frozen, lane(status="NATIVE_FAIL", raw="PRODUCT_FAIL", exit_code=1))
    r = report_of(b)
    assert r["verdict"]["outcome"] == "INCONCLUSIVE" and r["verdict"]["reason_code"] == "NATIVE_FAIL_VERIFIED_ASSERTIONS"
    res = verify_files(b.files)
    assert res.ok and res.run_outcome["reason_code"] == "NATIVE_FAIL_VERIFIED_ASSERTIONS"
    assert [d["code"] for d in res.disagreements] == ["ENGINE_VERIFIER_DISAGREE"]


def test_when_the_in_run_verifier_and_the_recomputation_disagree_nothing_is_certified(up, golden_frozen):
    r = report_of(build(up, golden_frozen, lane(harness={"A-NOTIF-ON": "FAIL", "A-SAVED": "PASS", "A-URL": "PASS"})))
    by_id = {x["assertion_id"]: x["verdict"] for x in r["accounting"]["results"]}
    assert by_id["A-NOTIF-ON"]["state"] == "INCONCLUSIVE" and by_id["A-NOTIF-ON"]["reason_code"] == "VERIFIER_ERROR"
    assert r["verdict"]["outcome"] == "INCONCLUSIVE"


def test_the_bundle_is_deterministic_for_the_same_inputs(up, golden_frozen):
    a, b = build(up, golden_frozen, lane()), build(up, golden_frozen, lane())
    assert a.manifest_digest == b.manifest_digest and a.archive_bytes() == b.archive_bytes()


def test_the_bundle_lists_the_lock_the_native_files_the_observations_and_the_logs(up, golden_frozen):
    b = build(up, golden_frozen, lane())
    roles = {f["path"]: f["role"] for f in b.manifest["files"]}
    assert roles["plan.lock.json"] == "record" and roles["lanes/browser/native/run-record.json"] == "native-artifact"
    assert roles["lanes/browser/observations.json"] == "observation" and roles["logs/orchestrator.log"] == "log"
    assert b.files["plan.lock.json"] == golden_frozen.lock_bytes()
    assert json.loads(b.files["assertion-lock.json"]) == golden_frozen.rows and b.manifest["plan_digest"] == golden_frozen.plan_digest


def test_the_report_names_the_runner_as_producer_of_the_verdicts_never_the_engine(up, golden_frozen):
    r = report_of(build(up, golden_frozen, lane()))
    assert r["verdict"]["provenance"]["verifier"]["id"] == "redevops-qa-verify" and r["verdict"]["provenance"]["verifier"]["id"] != "playwright-chromium"
    assert r["extensions"] == {"target_defect": "none"}


def test_evidence_that_equals_a_native_artifact_byte_for_byte_is_refused(up, golden_frozen):
    out = lane()
    obs = out.files["lanes/browser/observations.json"][0]
    with pytest.raises(BuildError) as exc:
        build(up, golden_frozen, LaneOutcome(**{**out.__dict__, "native_files": {**out.native_files, "same.json": obs}}))
    assert "EVIDENCE_IS_NATIVE_BYTES" in {c for c, _, _ in exc.value.problems}


def test_every_lane_of_the_plan_needs_exactly_one_outcome(up, golden_frozen):
    inputs = RunInputs(frozen=golden_frozen, run_id="r0-x", started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:05Z", environment=ENV, lanes=())
    with pytest.raises(ValueError):
        build_run_bundle(up, inputs)
    two = RunInputs(frozen=golden_frozen, run_id="r0-x", started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:05Z", environment=ENV, lanes=(lane(), lane()))
    with pytest.raises(ValueError):
        build_run_bundle(up, two)


def test_the_run_id_must_leave_room_for_the_lane_id(up, golden_frozen):
    inputs = RunInputs(frozen=golden_frozen, run_id="r" * 60, started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:05Z", environment=ENV, lanes=(lane(),))
    with pytest.raises(BuildError):
        build_run_bundle(up, inputs)
