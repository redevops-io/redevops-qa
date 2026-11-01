# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""R1 of the review of the first version: a lane whose engine reported a failure (NATIVE_FAIL) while every assertion is VERIFIED.

The rule: the run outcome is INCONCLUSIVE with the reason NATIVE_FAIL_VERIFIED_ASSERTIONS, never VERIFIED. The disagreement is shown by
``verify`` (text and JSON), not only by ``inspect``. No schema change: the run reason code is an open code pattern and the outcome set is
unchanged, so a reader written before this rule recomputes VERIFIED, finds the stored INCONCLUSIVE and refuses the bundle (fail closed)."""
import copy
import io
import json

import pytest

import qe_helpers as H
from qa_evidence.build import BuildError
from qa_evidence.cli import main
from qa_evidence.report import compute_outcome, engine_verifier_disagreements, run_reason
from qa_evidence.verify import verify_files
from qe_helpers import build_base, inputs

NF = dict(robot_obs=H.ROBOT_OBS_GOOD, robot_state="VERIFIED", robot_reason="EQUALS_EXPECTED", robot_status="NATIVE_FAIL", robot_exit=1)


def test_the_rule_in_the_outcome_functions():
    assert compute_outcome(["VERIFIED"], 1, ["NATIVE_PASS"]) == "VERIFIED"
    assert compute_outcome(["VERIFIED", "VERIFIED"], 2, ["NATIVE_PASS", "NATIVE_FAIL"]) == "INCONCLUSIVE"
    assert run_reason("INCONCLUSIVE", ["VERIFIED", "VERIFIED"], 2, ["NATIVE_PASS", "NATIVE_FAIL"]) == "NATIVE_FAIL_VERIFIED_ASSERTIONS"
    # a lane that did not complete is the more basic problem and keeps its own reason
    assert run_reason("INCONCLUSIVE", ["VERIFIED"], 1, ["NATIVE_FAIL", "NATIVE_TIMEOUT"]) == "ENGINE_DID_NOT_COMPLETE"
    # any FAILED assertion still fails the run, whatever the native statuses are
    assert compute_outcome(["FAILED", "VERIFIED"], 2, ["NATIVE_FAIL", "NATIVE_PASS"]) == "FAILED"
    # unverified assertions keep the generic reason
    assert run_reason("INCONCLUSIVE", ["INCONCLUSIVE", "VERIFIED"], 2, ["NATIVE_FAIL", "NATIVE_PASS"]) == "NOT_ALL_ASSERTIONS_VERIFIED"


def test_a_native_fail_lane_with_verified_assertions_builds_as_inconclusive_with_the_named_reason():
    report, files, tools = inputs(**NF)
    assert report["accounting"]["verified"] == 3 and report["accounting"]["failed"] == 0
    assert report["verdict"]["outcome"] == "INCONCLUSIVE" and report["verdict"]["reason_code"] == "NATIVE_FAIL_VERIFIED_ASSERTIONS"
    bundle = build_base(**NF)
    assert verify_files(bundle.files).ok


def test_a_report_that_still_claims_verified_for_that_lane_is_refused():
    report, files, tools = inputs(**NF)
    forged = copy.deepcopy(report)
    forged["verdict"].update({"outcome": "VERIFIED", "reason_code": "ALL_ASSERTIONS_VERIFIED"})
    from qa_evidence.build import build_bundle
    with pytest.raises(BuildError) as exc:
        build_bundle(report=forged, files=files, tools=tools)
    assert "VERDICT_OUTCOME_MISMATCH" in {c for c, _, _ in exc.value.problems}


def test_verify_text_and_json_surface_the_disagreement(tmp_path):
    bundle = build_base(**NF)
    target = tmp_path / "b"
    bundle.write_directory(str(target))
    out, err = io.StringIO(), io.StringIO()
    assert main(["verify", str(target)], out, err) == 0                      # the bundle is internally consistent: integrity is not the outcome
    text = out.getvalue()
    assert "run outcome: INCONCLUSIVE (NATIVE_FAIL_VERIFIED_ASSERTIONS)" in text
    assert "ENGINE_VERIFIER_DISAGREE lane robot: native NATIVE_FAIL, verdicts VERIFIED" in text
    out = io.StringIO()
    main(["verify", str(target), "--json"], out, io.StringIO())
    doc = json.loads(out.getvalue())
    assert doc["run_outcome"] == {"outcome": "INCONCLUSIVE", "reason_code": "NATIVE_FAIL_VERIFIED_ASSERTIONS"}
    assert doc["engine_verifier_disagreements"] == [{"code": "ENGINE_VERIFIER_DISAGREE", "lane_id": "robot", "native_status": "NATIVE_FAIL",
                                                     "verdict_states": ["VERIFIED"]}]


def test_a_consistent_run_reports_no_disagreement_and_a_verified_outcome(tmp_path):
    report, files, tools = inputs(robot_obs=H.ROBOT_OBS_GOOD, robot_state="VERIFIED", robot_reason="EQUALS_EXPECTED")
    assert report["verdict"]["outcome"] == "VERIFIED" and engine_verifier_disagreements(report) == []
    result = verify_files(build_base(robot_obs=H.ROBOT_OBS_GOOD, robot_state="VERIFIED", robot_reason="EQUALS_EXPECTED").files)
    assert result.run_outcome == {"outcome": "VERIFIED", "reason_code": "ALL_ASSERTIONS_VERIFIED"} and result.disagreements == []
    assert result.to_json()["engine_verifier_disagreements"] == []


def test_a_report_that_cannot_be_read_has_no_outcome_to_show():
    result = verify_files({})
    assert not result.ok and result.run_outcome is None and result.to_json()["run_outcome"] is None
