# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The verification ceiling: a run against a target with no independent restatement of what its assertions expect (an external target) prints CORROBORATED and never VERIFIED.
The cap is computed in ``compute_outcome``; a report that carries the ceiling is checked against it by every verifier, and a report that says VERIFIED while carrying the ceiling is refused."""
import copy

import pytest

import qe_helpers as H
from qa_evidence.build import BuildError, build_bundle
from qa_evidence.report import compute_outcome, run_reason
from qa_evidence.verify import verify_files
from qe_helpers import build_base, inputs

GOOD = dict(robot_obs=H.ROBOT_OBS_GOOD, robot_state="VERIFIED", robot_reason="EQUALS_EXPECTED")


def test_the_cap_is_in_the_outcome_function():
    assert compute_outcome(["VERIFIED"], 1, ["NATIVE_PASS"]) == "VERIFIED"
    assert compute_outcome(["VERIFIED"], 1, ["NATIVE_PASS"], "CORROBORATED") == "CORROBORATED"
    assert run_reason("CORROBORATED", ["VERIFIED"], 1, ["NATIVE_PASS"], "CORROBORATED") == "ALL_ASSERTIONS_CORROBORATED"
    # the cap lowers nothing else: a failed assertion still fails, an incomplete run is still inconclusive
    assert compute_outcome(["FAILED", "VERIFIED"], 2, ["NATIVE_FAIL", "NATIVE_PASS"], "CORROBORATED") == "FAILED"
    assert compute_outcome(["VERIFIED"], 1, ["NATIVE_TIMEOUT"], "CORROBORATED") == "INCONCLUSIVE"
    assert compute_outcome(["VERIFIED", "INCONCLUSIVE"], 2, ["NATIVE_PASS"], "CORROBORATED") == "INCONCLUSIVE"


def test_a_capped_report_carries_the_ceiling_and_an_uncapped_one_does_not_change():
    plain, _, _ = inputs(**GOOD)
    capped, _, _ = inputs(**GOOD, ceiling="CORROBORATED")
    assert "verification_ceiling" not in plain and plain["verdict"]["outcome"] == "VERIFIED"
    assert capped["verification_ceiling"] == "CORROBORATED" and capped["verdict"] == {**plain["verdict"], "outcome": "CORROBORATED", "reason_code": "ALL_ASSERTIONS_CORROBORATED"}
    assert verify_files(build_base(**GOOD, ceiling="CORROBORATED").files).ok and verify_files(build_base(**GOOD).files).ok


def test_a_report_that_drops_or_ignores_the_ceiling_is_refused():
    report, files, tools = inputs(**GOOD, ceiling="CORROBORATED")
    for mutate in (lambda r: r["verdict"].update(outcome="VERIFIED", reason_code="ALL_ASSERTIONS_VERIFIED"),                      # says VERIFIED while capped
                   lambda r: r["verdict"].update(reason_code="ALL_ASSERTIONS_VERIFIED")):                                          # CORROBORATED with the uncapped reason
        forged = copy.deepcopy(report)
        mutate(forged)
        with pytest.raises(BuildError) as exc:
            build_bundle(report=forged, files=files, tools=tools)
        assert {c for c, _, _ in exc.value.problems} & {"VERDICT_OUTCOME_MISMATCH", "REASON_CODE_STATE_MISMATCH"}
    # the ceiling can only say CORROBORATED: VERIFIED is the absence of a cap, never a value
    forged = copy.deepcopy(report)
    forged["verification_ceiling"] = "VERIFIED"
    with pytest.raises(BuildError):
        build_bundle(report=forged, files=files, tools=tools)


def test_removing_the_ceiling_from_a_capped_report_leaves_an_outcome_the_recomputation_does_not_give():
    report, files, tools = inputs(**GOOD, ceiling="CORROBORATED")
    stripped = copy.deepcopy(report)
    del stripped["verification_ceiling"]
    with pytest.raises(BuildError) as exc:
        build_bundle(report=stripped, files=files, tools=tools)
    assert "VERDICT_OUTCOME_MISMATCH" in {c for c, _, _ in exc.value.problems}
