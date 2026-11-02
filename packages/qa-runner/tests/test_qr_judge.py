# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Verdicts from recorded observations and frozen assertions: the one function the run and ``verify`` share."""
import copy
import dataclasses

import pytest

from qa_evidence.canon import dumps_canonical, sha256_bytes
from qa_runner.judge import EvidenceUnusable, judge_observed as judge_lane, observation_document, observation_path, parse_observations
from qr_data import ORIGIN, RUN, files_with, good_rows, observation_bytes, row


def judged(up, frozen, data, run=RUN):
    lane = frozen.lane("browser")
    return {r["assertion_id"]: r for r in judge_lane(up, lane, run_id=run, files={} if data is None else files_with(data))}


def states(results):
    return {k: (v["state"], v["reason_code"]) for k, v in results.items()}


def test_matching_observations_are_verified_with_the_evidence_named(up, golden_frozen):
    data = observation_bytes()
    res = judged(up, golden_frozen, data)
    assert states(res) == {"A-NOTIF-ON": ("VERIFIED", "EQUALS_EXPECTED"), "A-SAVED": ("VERIFIED", "EQUALS_EXPECTED"), "A-URL": ("VERIFIED", "PREDICATE_HOLDS")}
    assert all(r["evidence"] == {"path": "lanes/browser/observations.json", "digest": sha256_bytes(data)} for r in res.values())
    assert all(r["harness_verdict"] == "PASS" for r in res.values())


def test_a_value_that_differs_from_the_frozen_one_fails_that_assertion_only(up, golden_frozen):
    res = judged(up, golden_frozen, observation_bytes(good_rows(notif=False)))
    assert states(res)["A-NOTIF-ON"] == ("FAILED", "EXPECTED_VALUE_DIFFERS")
    assert states(res)["A-SAVED"][0] == "VERIFIED" and states(res)["A-URL"][0] == "VERIFIED"


def test_a_url_that_does_not_match_the_frozen_pattern_fails_with_the_predicate_reason(up, golden_frozen):
    rows = good_rows()
    rows[2] = row("A-URL", ORIGIN + "/settings")
    assert states(judged(up, golden_frozen, observation_bytes(rows)))["A-URL"] == ("FAILED", "PREDICATE_VIOLATED")


def test_every_frozen_assertion_gets_exactly_one_result_in_id_order(up, golden_frozen):
    res = judge_lane(up, golden_frozen.lane("browser"), run_id=RUN, files=files_with(observation_bytes()))
    assert [r["assertion_id"] for r in res] == ["A-NOTIF-ON", "A-SAVED", "A-URL"]


def test_no_observation_file_means_missing_evidence_never_a_pass(up, golden_frozen):
    res = judged(up, golden_frozen, None)
    assert set(states(res).values()) == {("INCONCLUSIVE", "EVIDENCE_MISSING")} and all(r["evidence"] is None for r in res.values())


def test_an_assertion_without_a_row_is_missing_evidence_and_the_others_are_still_judged(up, golden_frozen):
    res = judged(up, golden_frozen, observation_bytes(good_rows()[:2]))
    assert states(res)["A-URL"] == ("INCONCLUSIVE", "EVIDENCE_MISSING") and states(res)["A-SAVED"][0] == "VERIFIED"


@pytest.mark.parametrize("resolution,count", [("UNRESOLVED", 0), ("AMBIGUOUS", 2)])
def test_an_element_that_was_not_found_exactly_once_is_inconclusive_not_a_fail(up, golden_frozen, resolution, count):
    rows = good_rows()
    rows[1] = row("A-NOTIF-ON", None, resolution=resolution, match_count=count)
    assert states(judged(up, golden_frozen, observation_bytes(rows)))["A-NOTIF-ON"][0] == "INCONCLUSIVE"


def test_a_value_of_the_wrong_type_is_not_equal(up, golden_frozen):
    rows = good_rows()
    rows[1] = row("A-NOTIF-ON", "true")                       # a string is not a boolean
    assert states(judged(up, golden_frozen, observation_bytes(rows)))["A-NOTIF-ON"] == ("FAILED", "EXPECTED_VALUE_DIFFERS")
    rows[1] = row("A-NOTIF-ON", 1)
    assert states(judged(up, golden_frozen, observation_bytes(rows)))["A-NOTIF-ON"] == ("FAILED", "EXPECTED_VALUE_DIFFERS")


def test_a_digest_only_observation_cannot_pass_an_equality(up, golden_frozen):
    rows = good_rows()
    rows[0] = row("A-SAVED", None, digest="rcv1:" + "a" * 64)
    assert states(judged(up, golden_frozen, observation_bytes(rows)))["A-SAVED"][0] == "INCONCLUSIVE"


@pytest.mark.parametrize("field,value", [("verdict", "VERIFIED"), ("verified", True), ("expected", "Settings saved"), ("status", "PASS"), ("passed", True)])
def test_a_verdict_or_expected_value_in_an_observation_row_makes_the_file_unusable(up, golden_frozen, field, value):
    rows = good_rows()
    rows[0][field] = value
    res = judged(up, golden_frozen, observation_bytes(rows))
    assert set(states(res).values()) == {("INCONCLUSIVE", "EVIDENCE_UNUSABLE")}


def test_an_extra_top_level_field_makes_the_file_unusable(up, golden_frozen):
    res = judged(up, golden_frozen, observation_bytes(verdict="VERIFIED"))
    assert set(states(res).values()) == {("INCONCLUSIVE", "EVIDENCE_UNUSABLE")}


@pytest.mark.parametrize("override", [{"run_id": "other.browser"}, {"lane_id": "robot"}, {"schema": "something-else"}, {"schema_version": "2.0"}])
def test_an_observation_file_recorded_for_another_run_lane_or_format_is_unusable(up, golden_frozen, override):
    assert set(states(judged(up, golden_frozen, observation_bytes(**override))).values()) == {("INCONCLUSIVE", "EVIDENCE_UNUSABLE")}


def test_a_replay_from_another_run_is_unusable(up, golden_frozen):
    data = observation_bytes(run="r0-other")
    assert set(states(judged(up, golden_frozen, data)).values()) == {("INCONCLUSIVE", "EVIDENCE_UNUSABLE")}


def test_duplicate_rows_and_duplicate_keys_make_the_file_unusable(up, golden_frozen):
    rows = good_rows() + [row("A-SAVED", "Settings saved")]
    assert set(states(judged(up, golden_frozen, observation_bytes(rows))).values()) == {("INCONCLUSIVE", "EVIDENCE_UNUSABLE")}
    assert set(states(judged(up, golden_frozen, b'{"a": 1, "a": 2}')).values()) == {("INCONCLUSIVE", "EVIDENCE_UNUSABLE")}


@pytest.mark.parametrize("data", [b"", b"null", b"[]", b"{not json", b'{"schema": 1.5}', b"\xef\xbb\xbf{}"])
def test_garbage_is_unusable_evidence(up, golden_frozen, data):
    assert set(states(judged(up, golden_frozen, data)).values()) == {("INCONCLUSIVE", "EVIDENCE_UNUSABLE")}


def test_a_changed_frozen_assertion_is_an_integrity_failure_not_a_verdict(up, golden_frozen):
    """The lane's assertions no longer hash to the pin it was frozen with."""
    lane = golden_frozen.lane("browser")
    forged = [copy.deepcopy(a) for a in lane.assertions]
    forged[0]["predicate"]["expected"] = "forged"
    tampered = dataclasses.replace(lane, assertions=tuple(forged))
    res = {r["assertion_id"]: r for r in judge_lane(up, tampered, run_id=RUN, files=files_with(observation_bytes()))}
    assert set(states(res).values()) == {("INCONCLUSIVE", "ASSERTION_INTEGRITY")}


def test_a_pin_that_is_not_the_frozen_one_is_an_integrity_failure(up, golden_frozen):
    """The lane's documents are untouched but the pin they were frozen with is not the one the lane carries."""
    tampered = dataclasses.replace(golden_frozen.lane("browser"), harness_pin="rcv1:" + "0" * 64)
    res = {r["assertion_id"]: r for r in judge_lane(up, tampered, run_id=RUN, files=files_with(observation_bytes()))}
    assert set(states(res).values()) == {("INCONCLUSIVE", "ASSERTION_INTEGRITY")}


def test_an_assertion_with_a_script_executor_has_no_judge_in_a_browser_lane(up, golden_frozen):
    lane = golden_frozen.lane("browser")
    docs = [copy.deepcopy(a) for a in lane.assertions]
    docs[0]["executor"] = "SCRIPT"
    res = judge_lane(up, dataclasses.replace(lane, assertions=tuple(docs)), run_id=RUN, files=files_with(observation_bytes()))
    assert {r["state"] for r in res} == {"INCONCLUSIVE"}


def test_parse_observations_is_strict_and_returns_rows_by_id():
    rows = parse_observations(observation_bytes(), "browser", f"{RUN}.browser")
    assert set(rows) == {"A-SAVED", "A-NOTIF-ON", "A-URL"}
    with pytest.raises(EvidenceUnusable) as exc:
        parse_observations(observation_bytes(), "browser", "wrong.browser")
    assert exc.value.code == "WRONG_CONTEXT"


def test_the_observation_document_is_sorted_and_canonical():
    doc = observation_document("browser", f"{RUN}.browser", "playwright-chromium", list(reversed(good_rows())))
    assert [r["assertion_id"] for r in doc["observations"]] == ["A-NOTIF-ON", "A-SAVED", "A-URL"]
    assert observation_bytes() == dumps_canonical(doc)


def test_the_observation_path_is_per_lane():
    assert observation_path("browser") == "lanes/browser/observations.json"
