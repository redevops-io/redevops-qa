# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Negative fixtures: a native PASS is never promoted to an oracle PASS."""
import dataclasses

import pytest

from ak_support import run
from qa_adapter_kit import (AdapterClass, AdapterResult, CanonicalEvidence, ErrorCode, ModelError, NativeAssertion, OracleVerdict, Status, canonical_status,
                            map_to_canonical)


def native(nid, status, *ids):
    return NativeAssertion(native_id=nid, name=nid, status=Status(status), declared_assertion_ids=tuple(ids))


def res(*natives, status=None):
    from qa_adapter_kit import aggregate_status
    return AdapterResult(run_id="r1", adapter_id="fake-suite", adapter_class=AdapterClass.SUITE, status=status or aggregate_status(tuple(natives)),
                         native_assertions=tuple(natives),
                         error_code=ErrorCode.NATIVE_ERROR if (status or aggregate_status(tuple(natives))) is Status.ERROR else None)


def test_a_native_pass_with_an_explicit_matching_mapping_is_native_evidence_and_still_unverified():
    report = map_to_canonical(res(native("T1", "PASS", "A-1")), ["A-1"], {"T1": "A-1"})
    [ev] = report.evidence
    assert ev.native_status is Status.PASS and ev.native_ids == ("T1",)
    assert ev.oracle_status is Status.UNVERIFIED and canonical_status(ev) is Status.UNVERIFIED


def test_a_required_assertion_with_no_mapping_is_unverified_even_when_every_native_test_passed():
    report = map_to_canonical(res(native("T1", "PASS", "A-1"), native("T2", "PASS", "A-2")), ["A-1", "A-2"], {})
    assert [e.native_status for e in report.evidence] == [Status.UNVERIFIED, Status.UNVERIFIED]
    assert all(canonical_status(e) is Status.UNVERIFIED for e in report.evidence) and report.unmapped_native == ("T1", "T2")


def test_a_mapping_to_an_assertion_the_test_does_not_declare_is_refused():
    report = map_to_canonical(res(native("T1", "PASS", "A-9")), ["A-1"], {"T1": "A-1"})
    assert report.evidence[0].native_status is Status.UNVERIFIED and report.refused[0][0] == "T1" and "does not declare" in report.refused[0][1]


def test_a_test_that_declares_an_assertion_but_is_not_mapped_gives_no_evidence():
    report = map_to_canonical(res(native("T1", "PASS", "A-1")), ["A-1"], {})
    assert report.evidence[0].native_status is Status.UNVERIFIED and report.evidence[0].native_ids == ()


def test_a_mapping_to_an_assertion_that_is_not_required_is_refused():
    report = map_to_canonical(res(native("T1", "PASS", "A-7")), ["A-1"], {"T1": "A-7"})
    assert [e.assertion_id for e in report.evidence] == ["A-1"] and "not a required assertion" in report.refused[0][1]


def test_a_mapping_that_names_an_unreported_native_test_is_refused():
    report = map_to_canonical(res(native("T1", "PASS", "A-1")), ["A-1"], {"GHOST": "A-1"})
    assert report.refused[0][0] == "GHOST" and report.evidence[0].native_status is Status.UNVERIFIED


@pytest.mark.parametrize("statuses,expected", [(["PASS", "PASS"], "PASS"), (["PASS", "FAIL"], "FAIL"), (["PASS", "SKIP"], "SKIP"),
                                               (["PASS", "UNKNOWN"], "UNKNOWN"), (["PASS", "ERROR"], "ERROR")])
def test_several_native_tests_for_one_assertion_take_the_worst_native_status(statuses, expected):
    natives = [native(f"T{i}", s, "A-1") for i, s in enumerate(statuses)]
    report = map_to_canonical(res(*natives), ["A-1"], {n.native_id: "A-1" for n in natives})
    assert report.evidence[0].native_status is Status(expected)


@pytest.mark.parametrize("status", ["FAIL", "ERROR", "SKIP", "UNKNOWN"])
def test_a_non_pass_native_status_is_carried_but_also_never_a_canonical_verdict(status):
    [ev] = map_to_canonical(res(native("T1", status, "A-1")), ["A-1"], {"T1": "A-1"}).evidence
    assert ev.native_status is Status(status) and canonical_status(ev) is Status.UNVERIFIED


def test_evidence_cannot_be_constructed_with_an_oracle_status_or_basis():
    with pytest.raises(ModelError):
        CanonicalEvidence("A-1", "r1", "fake-suite", ("T1",), Status.PASS, oracle_status=Status.PASS)
    with pytest.raises(ModelError):
        CanonicalEvidence("A-1", "r1", "fake-suite", ("T1",), Status.PASS, basis="oracle")


def test_an_independent_verdict_for_the_exact_evidence_is_the_only_way_to_a_canonical_status():
    [ev] = map_to_canonical(res(native("T1", "PASS", "A-1")), ["A-1"], {"T1": "A-1"}).evidence
    verdict = OracleVerdict("A-1", "independent-verifier", Status.PASS, ev.digest())
    assert canonical_status(ev, verdict) is Status.PASS
    assert canonical_status(ev, OracleVerdict("A-1", "independent-verifier", Status.FAIL, ev.digest())) is Status.FAIL


def test_an_adapter_cannot_verify_its_own_result():
    [ev] = map_to_canonical(res(native("T1", "PASS", "A-1")), ["A-1"], {"T1": "A-1"}).evidence
    for verifier in ("fake-suite", "fake-suite-oracle"):
        with pytest.raises(ModelError, match="own result"):
            canonical_status(ev, OracleVerdict("A-1", verifier, Status.PASS, ev.digest()))


def test_a_verdict_for_other_evidence_or_another_assertion_is_refused():
    [ev] = map_to_canonical(res(native("T1", "PASS", "A-1")), ["A-1"], {"T1": "A-1"}).evidence
    with pytest.raises(ModelError, match="different evidence"):
        canonical_status(ev, OracleVerdict("A-1", "v", Status.PASS, "0" * 64))
    with pytest.raises(ModelError, match="different assertion"):
        canonical_status(ev, OracleVerdict("A-2", "v", Status.PASS, ev.digest()))
    changed = map_to_canonical(res(native("T1", "FAIL", "A-1")), ["A-1"], {"T1": "A-1"}).evidence[0]
    with pytest.raises(ModelError, match="different evidence"):
        canonical_status(changed, OracleVerdict("A-1", "v", Status.PASS, ev.digest()))      # a PASS verdict for the earlier, passing evidence


def test_a_verdict_cannot_judge_assertions_that_have_no_native_evidence():
    [ev] = map_to_canonical(res(native("T1", "PASS", "A-1")), ["A-2"], {}).evidence
    with pytest.raises(ModelError, match="no native evidence"):
        canonical_status(ev, OracleVerdict("A-2", "v", Status.PASS, ev.digest()))


def test_a_verdict_cannot_be_unverified():
    with pytest.raises(ModelError):
        OracleVerdict("A-1", "v", Status.UNVERIFIED, "0" * 64)
    with pytest.raises(ModelError):
        OracleVerdict("A-1", "", Status.PASS, "0" * 64)


def test_the_evidence_digest_depends_on_the_native_status_and_the_run():
    base = CanonicalEvidence("A-1", "r1", "fake-suite", ("T1",), Status.PASS)
    assert base.digest() != dataclasses.replace(base, native_status=Status.FAIL).digest()
    assert base.digest() != dataclasses.replace(base, run_id="r2").digest()
    assert base.digest() == dataclasses.replace(base, reasons=("x",)).digest()           # reasons are commentary, not evidence


# ---------------------------------------------------------------------------------------------- end to end through the runner
def test_end_to_end_a_passing_suite_gives_native_pass_and_canonical_unverified(tmp_path):
    result, _ = run(tmp_path, "pass", required_assertions=("A-1",), assertion_mapping={"T1": "A-1"})
    assert result.status is Status.PASS
    [ev] = map_to_canonical(result, ("A-1",), {"T1": "A-1"}).evidence
    assert ev.native_status is Status.PASS and canonical_status(ev) is Status.UNVERIFIED


def test_end_to_end_an_untagged_passing_test_cannot_support_a_required_assertion(tmp_path):
    result, _ = run(tmp_path, "pass_untagged")
    report = map_to_canonical(result, ("A-1",), {"T1": "A-1"})
    assert result.status is Status.PASS and report.evidence[0].native_status is Status.UNVERIFIED and report.refused


def test_end_to_end_a_test_tagged_for_another_assertion_cannot_support_this_one(tmp_path):
    result, _ = run(tmp_path, "pass_wrong_tag")
    assert map_to_canonical(result, ("A-1",), {"T1": "A-1"}).evidence[0].native_status is Status.UNVERIFIED


def test_end_to_end_partial_coverage_leaves_the_other_assertion_unverified(tmp_path):
    result, _ = run(tmp_path, "pass_two")
    report = map_to_canonical(result, ("A-1", "A-2"), {"T1": "A-1"})
    assert [(e.assertion_id, e.native_status) for e in report.evidence] == [("A-1", Status.PASS), ("A-2", Status.UNVERIFIED)]
    assert report.unmapped_native == ("T2",)


def test_end_to_end_a_run_error_gives_no_evidence_at_all(tmp_path):
    result, _ = run(tmp_path, "malformed")
    assert result.status is Status.ERROR
    assert map_to_canonical(result, ("A-1",), {"T1": "A-1"}).evidence[0].native_status is Status.UNVERIFIED
