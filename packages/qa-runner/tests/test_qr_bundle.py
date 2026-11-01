# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The bundle builder: a pure function from collected lane outcomes to an evidence bundle. Native status and verdict stay apart; nothing is VERIFIED unless the
engine ran to completion and passed AND the independent recomputation verified every frozen assertion."""
import json

import pytest

from qa_evidence.build import BuildError
from qa_evidence.canon import dumps_canonical
from qa_evidence.verify import verify_files
from qa_runner.bundle import LaneOutcome, RunInputs, build_run_bundle
from qa_runner.judge import observation_path
from qr_data import RUN, good_rows, observation_bytes

ENV = {"os": "linux", "arch": "x86_64", "python": "3.12.3"}


def lane(frozen, status="NATIVE_PASS", raw="PASS", exit_code=0, rows=None, harness=None, native=None, obs=True):
    files = {}
    if obs:
        files[observation_path("browser")] = (observation_bytes(rows), "observation")
    return LaneOutcome(lane_id="browser", engine_name="playwright-chromium", engine_version="1.64.1", native_status=status, raw_status=raw, exit_code=exit_code,
                       native_files={"run-record.json": b'{"native": true}\n'} if native is None else native, files=files,
                       harness_verdicts={"A-NOTIF-ON": "PASS", "A-SAVED": "PASS", "A-URL": "PASS"} if harness is None else harness)


def build(up, frozen, outcome, logs=None):
    inputs = RunInputs(frozen=frozen, run_id=RUN, started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:05Z", environment=ENV, lanes=(outcome,),
                       logs=logs or {"logs/orchestrator.log": b"line\n"}, extensions={"target_defect": "none"})
    return build_run_bundle(up, inputs)


def report_of(bundle):
    return json.loads(bundle.files["report.json"])


def test_a_passing_lane_whose_observations_satisfy_the_frozen_assertions_is_verified_and_the_bundle_verifies(up, golden_frozen):
    b = build(up, golden_frozen, lane(golden_frozen))
    r = report_of(b)
    assert r["verdict"] == {**r["verdict"], "outcome": "VERIFIED", "reason_code": "ALL_ASSERTIONS_VERIFIED"}
    assert r["accounting"]["frozen"] == r["accounting"]["verified"] == 3 and r["accounting"]["unaccounted"] == 0
    result = verify_files(b.files, plan_digest=golden_frozen.plan_digest)
    assert result.ok and result.plan.state == "verified" and result.anchor.state == "absent"


def test_the_engine_status_and_the_verdict_are_separate_fields_with_disjoint_vocabularies(up, golden_frozen):
    r = report_of(build(up, golden_frozen, lane(golden_frozen)))
    assert r["lanes"][0]["native"]["status"] == "NATIVE_PASS"
    assert {x["verdict"]["state"] for x in r["accounting"]["results"]} == {"VERIFIED"}
    assert {x["native_status"] for x in r["accounting"]["results"]} == {"NATIVE_PASS"}


def test_a_native_pass_never_makes_a_verified_verdict_without_the_recomputation(up, golden_frozen):
    for rows in (good_rows(notif=False), []):
        r = report_of(build(up, golden_frozen, lane(golden_frozen, rows=rows)))          # the engine says PASS; the observations do not satisfy the assertions
        assert r["verdict"]["outcome"] != "VERIFIED"
        assert r["lanes"][0]["native"]["status"] == "NATIVE_PASS"


def test_a_failed_assertion_fails_the_run_even_when_the_engine_passed(up, golden_frozen):
    r = report_of(build(up, golden_frozen, lane(golden_frozen, rows=good_rows(notif=False), harness={"A-NOTIF-ON": "FAIL", "A-SAVED": "PASS", "A-URL": "PASS"})))
    assert r["verdict"]["outcome"] == "FAILED" and r["accounting"]["failed"] == 1 and r["accounting"]["verified"] == 2


@pytest.mark.parametrize("status,raw,code", [("NATIVE_ERROR", "error", 3), ("NATIVE_TIMEOUT", "timeout", None), ("NATIVE_UNAVAILABLE", "target-not-started", None),
                                             ("NATIVE_SKIPPED", "cancelled-before-start", None)])
def test_a_lane_that_did_not_run_to_completion_is_never_verified_even_with_perfect_observations(up, golden_frozen, status, raw, code):
    r = report_of(build(up, golden_frozen, lane(golden_frozen, status=status, raw=raw, exit_code=code)))
    assert r["verdict"]["outcome"] == "INCONCLUSIVE" and r["verdict"]["reason_code"] == "ENGINE_DID_NOT_COMPLETE"
    assert r["lanes"][0]["native"]["status"] == status


def test_each_result_carries_the_native_status_of_its_own_lane(up, golden_frozen):
    r = report_of(build(up, golden_frozen, lane(golden_frozen, status="NATIVE_TIMEOUT", raw="timeout", exit_code=None)))
    assert {x["native_status"] for x in r["accounting"]["results"]} == {"NATIVE_TIMEOUT"}


def test_a_lane_with_no_evidence_at_all_accounts_for_every_assertion_as_inconclusive(up, golden_frozen):
    r = report_of(build(up, golden_frozen, lane(golden_frozen, status="NATIVE_TIMEOUT", raw="timeout", exit_code=None, obs=False, native={})))
    assert r["accounting"] == {**r["accounting"], "frozen": 3, "inconclusive": 3, "verified": 0, "failed": 0, "unaccounted": 0}
    assert {x["verdict"]["reason_code"] for x in r["accounting"]["results"]} == {"EVIDENCE_MISSING"}


def test_a_native_fail_lane_whose_assertions_are_all_verified_is_inconclusive_with_the_named_reason(up, golden_frozen):
    """R1 at the product layer: never a plain VERIFIED, and verify says so."""
    b = build(up, golden_frozen, lane(golden_frozen, status="NATIVE_FAIL", raw="PRODUCT_FAIL", exit_code=1))
    r = report_of(b)
    assert r["verdict"]["outcome"] == "INCONCLUSIVE" and r["verdict"]["reason_code"] == "NATIVE_FAIL_VERIFIED_ASSERTIONS"
    res = verify_files(b.files)
    assert res.ok and res.run_outcome["reason_code"] == "NATIVE_FAIL_VERIFIED_ASSERTIONS"
    assert [d["code"] for d in res.disagreements] == ["ENGINE_VERIFIER_DISAGREE"]


def test_when_the_in_run_verifier_and_the_recomputation_disagree_nothing_is_certified(up, golden_frozen):
    r = report_of(build(up, golden_frozen, lane(golden_frozen, harness={"A-NOTIF-ON": "FAIL", "A-SAVED": "PASS", "A-URL": "PASS"})))
    by_id = {x["assertion_id"]: x["verdict"] for x in r["accounting"]["results"]}
    assert by_id["A-NOTIF-ON"]["state"] == "INCONCLUSIVE" and by_id["A-NOTIF-ON"]["reason_code"] == "VERIFIER_ERROR"
    assert r["verdict"]["outcome"] == "INCONCLUSIVE"


def test_the_bundle_is_deterministic_for_the_same_inputs(up, golden_frozen):
    a, b = build(up, golden_frozen, lane(golden_frozen)), build(up, golden_frozen, lane(golden_frozen))
    assert a.manifest_digest == b.manifest_digest and a.archive_bytes() == b.archive_bytes()


def test_the_bundle_lists_the_lock_the_native_files_the_observations_and_the_logs(up, golden_frozen):
    b = build(up, golden_frozen, lane(golden_frozen))
    roles = {f["path"]: f["role"] for f in b.manifest["files"]}
    assert roles["plan.lock.json"] == "record" and roles["lanes/browser/native/run-record.json"] == "native-artifact"
    assert roles["lanes/browser/observations.json"] == "observation" and roles["logs/orchestrator.log"] == "log"
    assert b.files["plan.lock.json"] == golden_frozen.lock_bytes()
    assert json.loads(b.files["assertion-lock.json"]) == golden_frozen.rows and b.manifest["plan_digest"] == golden_frozen.plan_digest


def test_the_report_names_the_runner_as_producer_of_the_verdicts_never_the_engine(up, golden_frozen):
    r = report_of(build(up, golden_frozen, lane(golden_frozen)))
    assert r["verdict"]["provenance"]["verifier"]["id"] == "redevops-qa-verify" and r["verdict"]["provenance"]["verifier"]["id"] != "playwright-chromium"
    assert r["extensions"] == {"target_defect": "none"}


def test_evidence_that_equals_a_native_artifact_byte_for_byte_is_refused(up, golden_frozen):
    data = observation_bytes()
    with pytest.raises(BuildError) as exc:
        build(up, golden_frozen, lane(golden_frozen, native={"run-record.json": data}))
    assert "EVIDENCE_IS_NATIVE_BYTES" in {c for c, _, _ in exc.value.problems}


def test_every_lane_of_the_plan_needs_exactly_one_outcome(up, golden_frozen):
    inputs = RunInputs(frozen=golden_frozen, run_id=RUN, started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:05Z", environment=ENV, lanes=())
    with pytest.raises(ValueError):
        build_run_bundle(up, inputs)
    two = RunInputs(frozen=golden_frozen, run_id=RUN, started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:05Z", environment=ENV,
                    lanes=(lane(golden_frozen), lane(golden_frozen)))
    with pytest.raises(ValueError):
        build_run_bundle(up, two)


def test_the_run_id_must_leave_room_for_the_lane_id(up, golden_frozen):
    inputs = RunInputs(frozen=golden_frozen, run_id="r" * 60, started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:05Z", environment=ENV,
                       lanes=(lane(golden_frozen),))
    with pytest.raises(BuildError):
        build_run_bundle(up, inputs)
