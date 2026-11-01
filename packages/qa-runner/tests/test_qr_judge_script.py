# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The SCRIPT executor for a Robot lane: the hash-pinned check program, run by the harness verifier over the observation record, compared with the value frozen in the
assertion. The record is exactly what the importer derives from the engine's own report; it never carries the expected value."""
import copy
import dataclasses
import json

import pytest

from qa_evidence.canon import dumps_canonical, sha256_bytes
from qa_runner.golden import robot_plan
from qa_runner.judge import derived_record, EvidenceUnusable, judge_lane
from qa_runner.plan import freeze_plan
from qr_data import DEFECT_TOTALS, GOOD_TOTALS, RUN, robot_files, robot_record, robot_xml


@pytest.fixture(scope="module")
def robot(up):
    return freeze_plan(up, robot_plan()).lane("robot")


def judged(up, lane, files, run=RUN):
    (r,) = judge_lane(up, lane, run_id=run, files=files)
    return r


def test_the_recorded_values_that_equal_the_frozen_ones_are_verified_with_the_record_as_evidence(up, robot):
    files = robot_files()
    r = judged(up, robot, files)
    assert (r["state"], r["reason_code"], r["harness_verdict"]) == ("VERIFIED", "EQUALS_EXPECTED", "PASS")
    assert r["evidence"] == {"path": "lanes/robot/observations.json", "digest": sha256_bytes(files["lanes/robot/observations.json"])}


def test_the_values_a_defective_target_produces_fail_the_assertion_even_though_the_engine_passed(up, robot):
    """What the engine itself reports (here PASS) plays no part: the verdict is the comparison of the record with the frozen value."""
    r = judged(up, robot, robot_files(robot_xml(DEFECT_TOTALS, status="PASS")))
    assert (r["state"], r["reason_code"]) == ("FAILED", "EXPECTED_VALUE_DIFFERS")


def test_one_value_off_is_enough_to_fail(up, robot):
    values = dict(GOOD_TOTALS, order_104_total_cents=9006)
    assert judged(up, robot, robot_files(robot_xml(values)))["state"] == "FAILED"


def test_a_missing_value_or_an_extra_value_does_not_equal_the_frozen_set(up, robot):
    missing = {k: v for k, v in GOOD_TOTALS.items() if k != "order_103_total_cents"}
    assert judged(up, robot, robot_files(robot_xml(missing)))["state"] == "FAILED"
    assert judged(up, robot, robot_files(robot_xml(dict(GOOD_TOTALS, order_105_total_cents=1))))["state"] == "FAILED"


def test_a_string_where_an_integer_was_frozen_is_not_equal(up, robot):
    assert judged(up, robot, robot_files(robot_xml(dict(GOOD_TOTALS, order_101_total_cents="9450x"))))["state"] == "FAILED"


def test_a_missing_record_or_a_missing_native_report_is_missing_evidence(up, robot):
    files = robot_files()
    for drop in ("lanes/robot/observations.json", "lanes/robot/native/output.xml"):
        got = {k: v for k, v in files.items() if k != drop}
        r = judged(up, robot, got)
        assert (r["state"], r["reason_code"]) == ("INCONCLUSIVE", "EVIDENCE_MISSING") and r["evidence"] is None


def test_a_record_that_does_not_belong_to_the_native_report_next_to_it_is_unusable(up, robot):
    """The record says the target was clean, the engine's own report says it was not: the record is not derived from that report."""
    clean_record = robot_record(robot_xml())                                  # a clean record next to a native report that says something else
    r = judged(up, robot, {"lanes/robot/native/output.xml": robot_xml(DEFECT_TOTALS), "lanes/robot/observations.json": clean_record})
    assert (r["state"], r["reason_code"]) == ("INCONCLUSIVE", "EVIDENCE_UNUSABLE")


@pytest.mark.parametrize("edit", [
    lambda d: d["spec"].update(expected={"documents": 1}),
    lambda d: d["spec"]["observations"].update(verdict="PASS"),
    lambda d: d.update(extra=1),
    lambda d: d["spec"].update(run_id="other.robot"),
    lambda d: d["spec"].update(output_xml_sha256="sha256:" + "0" * 64),
    lambda d: d["metadata"].update(name="browser"),
    lambda d: d["spec"].update(tests=["Suite.Other"]),
])
def test_a_record_that_differs_in_any_way_from_the_derived_one_is_unusable(up, robot, edit):
    doc = json.loads(robot_record())
    edit(doc)
    r = judged(up, robot, robot_files(record=dumps_canonical(doc)))
    assert (r["state"], r["reason_code"]) == ("INCONCLUSIVE", "EVIDENCE_UNUSABLE")


def test_a_record_that_is_not_in_canonical_bytes_is_unusable(up, robot):
    pretty = json.dumps(json.loads(robot_record()), indent=4).encode()
    assert judged(up, robot, robot_files(record=pretty))["reason_code"] == "EVIDENCE_UNUSABLE"
    assert judged(up, robot, robot_files(record=b"{not json"))["reason_code"] == "EVIDENCE_UNUSABLE"


def test_a_replay_of_another_runs_record_is_unusable(up, robot):
    other = robot_files(record=robot_record(run="r0-other"))
    assert judged(up, robot, other)["reason_code"] == "EVIDENCE_UNUSABLE"


@pytest.mark.parametrize("tag", ["expected", "verdict", "passed", "status"])
def test_a_native_report_with_an_observation_that_reads_as_a_verdict_cannot_be_imported(up, robot, tag):
    native = robot_xml(extra_tags=(f"qa-observe:{tag}=9450",))
    with pytest.raises(EvidenceUnusable):
        derived_record(native, "robot", f"{RUN}.robot")
    r = judged(up, robot, {"lanes/robot/native/output.xml": native, "lanes/robot/observations.json": robot_record()})
    assert r["reason_code"] == "EVIDENCE_UNUSABLE"


def test_the_check_program_receives_the_record_alone_and_never_an_expected_value(up, robot, monkeypatch):
    from redevops_qa_checks.adapter import CheckAdapter
    seen = []
    original = CheckAdapter.run_check

    def spy(self, w, subject):
        seen.append((subject.to_json(), sorted(str(p.relative_to(self._engine.case_root)) for p in self._engine.case_root.rglob("*") if p.is_file())))
        return original(self, w, subject)
    monkeypatch.setattr(CheckAdapter, "run_check", spy)
    assert judged(up, robot, robot_files())["state"] == "VERIFIED"
    ((subject, staged),) = seen
    flat = json.dumps(subject).lower()
    assert "expected" not in flat and "predicate" not in flat and "verdict" not in flat and "9450" not in flat
    assert staged == ["lanes/robot/observations.json"]
    assert subject["check_program_ref"]["id"] == "evidence.robot-observations"


def test_other_files_of_the_bundle_are_not_staged_for_the_check(up, robot, monkeypatch):
    from redevops_qa_checks.adapter import CheckAdapter
    staged = []
    original = CheckAdapter.run_check

    def spy(self, w, subject):
        staged.extend(str(p.relative_to(self._engine.case_root)) for p in self._engine.case_root.rglob("*") if p.is_file())
        return original(self, w, subject)
    monkeypatch.setattr(CheckAdapter, "run_check", spy)
    files = dict(robot_files(), **{"lanes/robot/suite/OrderApi.py": b"x", "logs/orchestrator.log": b"y", "plan.lock.json": b"{}"})
    judged(up, robot, files)
    assert staged == ["lanes/robot/observations.json"]


def test_a_changed_frozen_assertion_or_pin_is_an_integrity_failure(up, robot):
    tampered = dataclasses.replace(robot, harness_pin="rcv1:" + "0" * 64)
    assert judged(up, tampered, robot_files())["reason_code"] == "ASSERTION_INTEGRITY"
    forged = [copy.deepcopy(a) for a in robot.assertions]
    forged[0]["predicate"]["expected"]["observations"]["order_101_total_cents"] = 10500
    assert judged(up, dataclasses.replace(robot, assertions=tuple(forged)), robot_files())["reason_code"] == "ASSERTION_INTEGRITY"


def test_a_check_program_hash_that_is_not_the_registered_one_is_an_integrity_failure(up, robot):
    """The assertion pins a program hash; with another hash (the program was changed after freezing) the verifier refuses before anything runs."""
    forged = [copy.deepcopy(a) for a in robot.assertions]
    forged[0]["check_program_ref"]["program_hash"] = "sha256:" + "0" * 64
    r = judged(up, dataclasses.replace(robot, assertions=tuple(forged)), robot_files())
    assert (r["state"], r["reason_code"]) == ("INCONCLUSIVE", "ASSERTION_INTEGRITY")


def test_a_robot_lane_with_a_playwright_assertion_is_refused(up, robot):
    forged = [copy.deepcopy(a) for a in robot.assertions]
    forged[0]["executor"] = "PLAYWRIGHT"
    assert judged(up, dataclasses.replace(robot, assertions=tuple(forged)), robot_files())["state"] == "INCONCLUSIVE"


def test_a_native_report_that_cannot_be_imported_leaves_the_assertion_inconclusive(up, robot):
    files = robot_files()
    files["lanes/robot/native/output.xml"] = b"<robot/>"
    assert judged(up, robot, files)["reason_code"] == "EVIDENCE_UNUSABLE"
