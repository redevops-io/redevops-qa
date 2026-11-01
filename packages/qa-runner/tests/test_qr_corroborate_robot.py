# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The Robot lane's own files against each other, the plan's pins and the target's request log (review findings B1 and M2 of the review of #31). The files are those of REAL runs of the
real Robot Framework (``golden/robot-*.tar``); each test changes them one way at a time. A library swapped for one that never asks the target, an ``output.xml`` edited with the record
re-derived from it, a summary or an adapter result that names another report: none of these is a verdict."""
import hashlib
import json

import pytest

from qa_evidence.canon import dumps_canonical
from qa_runner.golden import robot_plan
from qa_runner.judge import derived_record, judge_lane
from qa_runner.plan import freeze_plan
from qr_data import ROBOT_RUN, robot_golden

BASE = "lanes/robot/"
XML, SUMMARY, RESULT, OBS = BASE + "native/output.xml", BASE + "native/robot-summary.json", BASE + "native/adapter-result.json", BASE + "observations.json"
REQS, LIB, SUITE = BASE + "target-requests.jsonl", BASE + "suite/OrderApi.py", BASE + "suite/order_discount.robot"


@pytest.fixture(scope="module")
def lane(up):
    return freeze_plan(up, robot_plan()).lane("robot")


def judged(up, lane, files, defect="none"):
    (r,) = judge_lane(up, lane, run_id=ROBOT_RUN[defect], files=files)
    return r["state"], r["reason_code"]


def jedit(files, path, fn):
    out = dict(files)
    doc = json.loads(out[path])
    fn(doc)
    out[path] = json.dumps(doc, sort_keys=True, indent=1).encode()
    return out


UNUSABLE = ("INCONCLUSIVE", "EVIDENCE_UNUSABLE")


def test_the_real_run_is_verified_and_the_real_discount_defect_fails(up, lane):
    assert judged(up, lane, robot_golden("none")) == ("VERIFIED", "EQUALS_EXPECTED")
    assert judged(up, lane, robot_golden("discount"), "discount") == ("FAILED", "EXPECTED_VALUE_DIFFERS")


def test_a_library_that_never_asked_the_target_is_not_verified(up, lane):
    """Review finding B1: a swapped library that returned the right numbers without calling the app was VERIFIED against a defective target."""
    files = robot_golden("none")
    files[REQS] = b""
    assert judged(up, lane, files) == UNUSABLE
    del files[REQS]
    assert judged(up, lane, files) == UNUSABLE


@pytest.mark.parametrize("order", ["101", "102", "103", "104"])
def test_a_request_the_suite_must_have_made_that_the_target_never_saw_is_not_accepted(up, lane, order):
    files = robot_golden("none")
    kept = [l for l in files[REQS].decode().splitlines() if not l.endswith('"/api/orders/%s"}' % order) and f"/api/orders/{order}" not in l]
    assert len(kept) < len(files[REQS].decode().splitlines())
    files[REQS] = ("\n".join(kept) + "\n").encode()
    assert judged(up, lane, files) == UNUSABLE


def test_a_request_the_plan_does_not_allow_is_not_accepted(up, lane):
    files = robot_golden("none")
    files[REQS] += json.dumps({"method": "POST", "target": "/settings"}).encode() + b"\n"
    assert judged(up, lane, files) == UNUSABLE


@pytest.mark.parametrize("name,path,content", [
    ("a library that is not the reviewed one", LIB, b"def get_order_total_cents(order_id):\n    return 9450\n"),
    ("a suite that is not the reviewed one", SUITE, b"*** Test Cases ***\nNothing\n    Log    nothing\n"),
])
def test_a_suite_or_library_that_is_not_the_pinned_one_is_not_accepted(up, lane, name, path, content):
    files = robot_golden("none")
    files[path] = content
    assert judged(up, lane, files) == UNUSABLE, name


def test_an_extra_file_among_the_suite_files_is_not_accepted(up, lane):
    files = robot_golden("none")
    files[BASE + "suite/extra.py"] = b"x = 1\n"
    assert judged(up, lane, files) == UNUSABLE


def forge_report(files, values):
    """What the reviewer did: edit ``output.xml`` and re-derive the observation record from it with the public importer."""
    xml = files[XML].decode()
    for k, v in values.items():
        import re
        xml = re.sub(r"(qa-observe:%s=)\d+" % k, r"\g<1>%d" % v, xml)
    out = dict(files)
    out[XML] = xml.encode()
    out[OBS] = dumps_canonical(derived_record(out[XML], "robot", f"{ROBOT_RUN['discount']}.robot"))
    return out


GOOD = {"order_101_total_cents": 9450, "order_103_total_cents": 9000, "order_104_total_cents": 9005}


def test_an_output_xml_edited_with_the_record_derived_from_it_is_not_accepted(up, lane):
    """Review finding M2: the unchanged ``robot-summary.json`` still names the digest of the original report."""
    files = forge_report(robot_golden("discount"), GOOD)
    assert judge_lane(up, lane, run_id=ROBOT_RUN["discount"], files=files)[0]["state"] == "INCONCLUSIVE"


@pytest.mark.parametrize("name,path,edit_fn", [
    ("the summary names another report", SUMMARY, lambda d: d.update(raw_output_sha256="0" * 64)),
    ("the summary lists another status", SUMMARY, lambda d: d["tests"][0].update(status="FAIL")),
    ("the summary lists no tests", SUMMARY, lambda d: d.update(tests=[])),
    ("the adapter result belongs to another run", RESULT, lambda d: d.update(run_id="r0-other.robot")),
    ("the adapter result is of another adapter", RESULT, lambda d: d.update(adapter_id="somebody-else")),
    ("the adapter result did not complete", RESULT, lambda d: d.update(status="ERROR")),
    ("the adapter result names another report", RESULT, lambda d: [a.update(sha256="0" * 64) for a in d["artifacts"] if a["path"] == "output.xml"]),
    ("the adapter result names another summary", RESULT, lambda d: [a.update(sha256="0" * 64) for a in d["artifacts"] if a["path"] == "robot-summary.json"]),
    ("the adapter result lists another status", RESULT, lambda d: d["native_assertions"][0].update(status="FAIL")),
    ("the adapter result says FAIL for tests that pass", RESULT, lambda d: d.update(status="FAIL")),
])
def test_the_engines_own_files_must_agree_with_each_other(up, lane, name, path, edit_fn):
    assert judged(up, lane, jedit(robot_golden("none"), path, edit_fn)) == UNUSABLE, name


def rehash(files, **edits):
    """The adapter result made to agree with the files as they are now (a forger who rewrites several files consistently): only the checks between the files' CONTENTS are left."""
    def fix(doc):
        for a in doc["artifacts"]:
            a["sha256"] = hashlib.sha256(files[{"output.xml": XML, "robot-summary.json": SUMMARY}[a["path"]]]).hexdigest()
    return jedit(files, RESULT, fix)


def test_a_summary_that_names_another_report_is_not_accepted_even_when_the_adapter_result_agrees(up, lane):
    files = robot_golden("none")
    assert judged(up, lane, files) == ("VERIFIED", "EQUALS_EXPECTED")
    files[XML] = files[XML] + b"<!-- edited after the run -->\n"                    # a report edited after the run, the record derived from it again
    files[OBS] = dumps_canonical(derived_record(files[XML], "robot", f"{ROBOT_RUN['none']}.robot"))
    files = rehash(files)                                                           # and the adapter result made to name the report as it is now
    assert judged(up, lane, files) == UNUSABLE


def test_a_summary_and_an_adapter_result_that_disagree_on_a_test_are_not_accepted_even_when_the_hashes_agree(up, lane):
    files = jedit(robot_golden("none"), SUMMARY, lambda d: d["tests"][0].update(status="FAIL"))
    files = rehash(files)
    assert judged(up, lane, files) == UNUSABLE


@pytest.mark.parametrize("path", [SUMMARY, RESULT])
def test_a_missing_summary_or_adapter_result_is_not_accepted(up, lane, path):
    files = robot_golden("none")
    del files[path]
    assert judged(up, lane, files) == UNUSABLE


def test_a_summary_with_a_duplicate_key_is_not_accepted(up, lane):
    files = robot_golden("none")
    files[SUMMARY] = files[SUMMARY].replace(b'"schema":', b'"schema": "x", "schema":', 1)
    assert judged(up, lane, files) == UNUSABLE


def test_a_verdict_the_reference_check_contradicts_is_not_verified(up, lane):
    """The plan ties the Robot assertion to the discount rule of the reference check: a clean-looking record against a target the check finds deviating is not verified."""
    files = jedit(robot_golden("none"), "logs/reference-check.json", lambda d: d.update(deviations=[{"check": "discount-rule", "where": "/api/orders/101", "expected": 9450, "actual": 10500}]))
    assert judged(up, lane, files)[0] == "INCONCLUSIVE"
    del files["logs/reference-check.json"]
    assert judged(up, lane, files) == ("INCONCLUSIVE", "EVIDENCE_MISSING")


def test_the_pinned_digests_of_the_reviewed_files_are_the_ones_of_the_shipped_files(up, lane):
    from qa_runner import suites
    for rel, digest in lane.suite_files.items():
        assert digest == "sha256:" + hashlib.sha256((suites.SUITE_DIR / rel).read_bytes()).hexdigest()
