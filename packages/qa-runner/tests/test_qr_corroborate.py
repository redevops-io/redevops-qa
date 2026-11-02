# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The lane's own claims against the harness run record, the target's request log and the reference check (review finding H1). The files are those of REAL runs (``golden/browser-*.tar``);
each test changes one of them. A lane child that never touched the target, an adapter that returns constant values, a record that does not belong to the run: none of these is a verdict."""
import copy
import json

import pytest

from qa_evidence.canon import dumps_canonical
from qa_runner.golden import golden_plan
from qa_runner.judge import judge_lane
from qa_runner.plan import freeze_plan
from qr_data import BROWSER_RUN, browser_files

RECORD = "lanes/browser/native/run-record.json"
RESULT = "lanes/browser/native/lane-result.json"
OBS = "lanes/browser/observations.json"
REQS = "lanes/browser/target-requests.jsonl"
PROBE = "logs/reference-check.json"
PROFILE = "lanes/browser/egress-profile.json"


@pytest.fixture(scope="module")
def lane(up):
    return freeze_plan(up, golden_plan()).lane("browser")


def judged(up, lane, files, defect="none"):
    return {r["assertion_id"]: (r["state"], r["reason_code"]) for r in judge_lane(up, lane, run_id=BROWSER_RUN[defect], files=files)}


def edit(files, path, fn):
    out = dict(files)
    doc = json.loads(out[path])
    fn(doc)
    out[path] = dumps_canonical(doc)
    return out


def unusable(states):
    return set(states.values()) == {("INCONCLUSIVE", "EVIDENCE_UNUSABLE")}


def test_the_real_run_is_verified_and_the_real_settings_defect_fails_exactly_its_assertion(up, lane):
    assert set(judged(up, lane, browser_files("none")).values()) == {("VERIFIED", "EQUALS_EXPECTED"), ("VERIFIED", "PREDICATE_HOLDS")}
    s = judged(up, lane, browser_files("settings"), "settings")
    assert s["A-NOTIF-ON"] == ("FAILED", "EXPECTED_VALUE_DIFFERS") and s["A-SAVED"][0] == s["A-URL"][0] == "VERIFIED"


def test_a_lane_that_never_touched_the_target_is_not_verified(up, lane):
    """The test double of the first version: a pass written without a run record and with an empty target log."""
    files = {k: v for k, v in browser_files("none").items() if k not in (RECORD, REQS)}
    files[RECORD] = b'{"schema": "test-double"}\n'
    files[REQS] = b""
    assert unusable(judged(up, lane, files))


@pytest.mark.parametrize("name,edit_fn", [
    ("an event payload of the run record edited", lambda d: d["events"][5]["payload"].update(run_id="other-run")),
    ("an event dropped", lambda d: d["events"].pop(7)),
    ("a receipt dropped", lambda d: (d["receipts"].pop(), d["receipt_links"].pop())),
    ("the run record not sealed", lambda d: d.update(sealed=False)),
    ("the run record cancelled", lambda d: d.update(cancelled=True)),
    ("a manifest that names other assertions than the frozen ones", lambda d: d["manifest"].update(assertion_set_hash="sha256:" + "0" * 64)),
    ("the run record of another run", lambda d: d.update(run_id="r0-other.browser")),
    ("another outcome than the lane result", lambda d: d["classification"].update(outcome="PRODUCT_FAIL")),
    ("another exit code than the lane result", lambda d: d.update(exit_code=1)),
    ("no schema at all", lambda d: (d.clear(), d.update(schema="test-double"))),
])
def test_a_run_record_that_does_not_stand_is_not_accepted(up, lane, name, edit_fn):
    assert unusable(judged(up, lane, edit(browser_files("none"), RECORD, edit_fn))), name


@pytest.mark.parametrize("name,edit_fn", [
    ("not sealed", lambda d: d.update(sealed=False)),
    ("cancelled", lambda d: d.update(cancelled=True)),
    ("not completed", lambda d: d.update(status="ERROR")),
    ("another outcome", lambda d: d.update(outcome="PRODUCT_FAIL")),
])
def test_a_lane_result_that_does_not_say_completed_sealed_and_not_cancelled_is_not_accepted(up, lane, name, edit_fn):
    assert unusable(judged(up, lane, edit(browser_files("none"), RESULT, edit_fn))), name


def test_an_observation_that_is_not_what_the_run_record_says_was_read_is_not_accepted(up, lane):
    files = edit(browser_files("settings"), OBS, lambda d: [o.update(value=True) for o in d["observations"] if o["assertion_id"] == "A-NOTIF-ON"])
    assert unusable(judged(up, lane, files, "settings"))        # the adapter's claim 'the box is ticked' against a record that says it was not


def test_the_executed_spec_must_be_the_frozen_one(up, lane):
    assert unusable(judged(up, lane, edit(browser_files("none"), PROFILE, lambda d: d["private"][0].update(ports=[1]))))


def test_a_run_record_checked_against_other_assertions_than_the_frozen_ones_is_not_accepted(up):
    plan = golden_plan()
    plan["lanes"][0]["spec"]["assertions"][0]["predicate"]["expected"] = "Settings not saved"
    other = freeze_plan(up, plan).lane("browser")
    assert other.harness_pin != freeze_plan(up, golden_plan()).lane("browser").harness_pin
    assert unusable(judged(up, other, browser_files("none")))


def test_the_run_record_of_another_run_of_the_same_plan_is_not_accepted(up, lane):
    files = browser_files("none")
    files[RECORD] = browser_files("settings")[RECORD]
    assert unusable(judged(up, lane, files))


# ---- the target's own request log -----------------------------------------------------------------------------------------------------------
def lines(files):
    return [json.loads(l) for l in files[REQS].decode().splitlines()]


def with_log(files, entries):
    out = dict(files)
    out[REQS] = b"".join(json.dumps(e, sort_keys=True).encode() + b"\n" for e in entries)
    return out


@pytest.mark.parametrize("missing", [("POST", "/login"), ("POST", "/settings"), ("GET", "/settings")])
def test_a_request_the_plan_requires_that_the_target_never_saw_is_not_accepted(up, lane, missing):
    files = browser_files("none")
    kept = [e for e in lines(files) if (e["method"], e["target"].split("?")[0]) != missing]
    assert unusable(judged(up, lane, with_log(files, kept)))


def test_a_missing_request_log_is_not_accepted(up, lane):
    assert unusable(judged(up, lane, {k: v for k, v in browser_files("none").items() if k != REQS}))


def test_an_empty_request_log_is_not_accepted(up, lane):
    assert unusable(judged(up, lane, with_log(browser_files("none"), [])))
    files = browser_files("none")
    del files[REQS]
    assert unusable(judged(up, lane, files))


@pytest.mark.parametrize("extra", [{"method": "GET", "target": "/api/orders/101"}, {"method": "POST", "target": "/admin"}, {"method": "GET", "target": "/etc/passwd"}])
def test_a_request_the_plan_does_not_allow_is_not_accepted(up, lane, extra):
    files = browser_files("none")
    assert unusable(judged(up, lane, with_log(files, lines(files) + [dict(lines(files)[0], **extra)])))


def test_a_log_line_that_cannot_be_read_is_not_accepted(up, lane):
    files = browser_files("none")
    files[REQS] += b"{not json\n"
    assert unusable(judged(up, lane, files))


# ---- the reference check ---------------------------------------------------------------------------------------------------------------------
def test_a_verdict_the_reference_check_contradicts_is_not_verified(up, lane):
    """The lane says the notification setting was saved (VERIFIED); the independent probe of the target found that saving does not persist."""
    files = browser_files("none")
    files[PROBE] = browser_files("settings")[PROBE]
    states = judged(up, lane, files)
    assert states["A-NOTIF-ON"] == ("INCONCLUSIVE", "EVIDENCE_UNUSABLE") and states["A-SAVED"][0] == "VERIFIED"


def test_a_missing_reference_check_leaves_the_probed_assertion_unverified(up, lane):
    files = browser_files("none")
    del files[PROBE]
    states = judged(up, lane, files)
    assert states["A-NOTIF-ON"] == ("INCONCLUSIVE", "EVIDENCE_MISSING") and states["A-URL"][0] == "VERIFIED"


def test_a_reference_check_that_agrees_with_a_failure_leaves_the_failure(up, lane):
    assert judged(up, lane, browser_files("settings"), "settings")["A-NOTIF-ON"][0] == "FAILED"


# ---- the plan fixes these expectations in the plan digest -----------------------------------------------------------------------------------------
def test_the_request_expectations_and_probes_are_part_of_the_plan_digest(up):
    base = freeze_plan(up, golden_plan())
    for mutate in (lambda l: l["requests"]["required"].pop(), lambda l: l["requests"]["allowed"].append("GET /admin"), lambda l: l["probes"].update({"A-NOTIF-ON": "ui-only"}),
                   lambda l: l["probes"].update({"A-SAVED": "settings-persistence"})):
        plan = golden_plan()
        mutate(plan["lanes"][0])
        assert freeze_plan(up, plan).plan_digest != base.plan_digest


# ---- review of #33: the run record against itself, the blobs, the egress profile -------------------------------------------------------------------
BLOBS = "lanes/browser/native/blobs/"


def test_the_fixtures_carry_the_blobs_the_run_record_refers_to():
    assert len([p for p in browser_files("none") if p.startswith(BLOBS)]) >= 8


def test_blobs_that_are_missing_or_altered_are_not_accepted(up, lane):
    """Review finding M2: 16 of 16 referenced blobs could be deleted or replaced with GARBAGE and the run stayed VERIFIED (the harness's own MISSING_BLOB and BLOB_CONTENT checks were never asked)."""
    files = browser_files("none")
    assert not unusable(judged(up, lane, files))
    assert unusable(judged(up, lane, {p: d for p, d in files.items() if not p.startswith(BLOBS)}))
    assert unusable(judged(up, lane, {p: (b"GARBAGE" if p.startswith(BLOBS) else d) for p, d in files.items()}))
    one = next(p for p in files if p.startswith(BLOBS))
    assert unusable(judged(up, lane, {**files, one: files[one] + b"x"}))


def test_a_run_record_whose_events_say_otherwise_than_its_manifest_is_not_accepted(up, lane, monkeypatch):
    """Review finding M1: a forger who recomputes the manifest, the seal and the last event hash leaves the AssertionResult events contradicting the manifest, and the integrity check does not relate them.
    The integrity check is stubbed here (it models the forger who satisfied it); the contradiction is what is left to see."""
    class Clean:
        findings = ()
    monkeypatch.setattr(up.harness.integrity, "verify_run_evidence", lambda **kw: Clean())
    files = edit(browser_files("settings"), RECORD, lambda d: [e["payload"]["check"].update(verdict="PASS") for e in d["events"] if e["kind"] == "AssertionResult" and e["payload"]["assertion_id"] == "A-NOTIF-ON"])
    assert unusable(judged(up, lane, files, "settings"))
    monkeypatch.undo()
    assert not unusable(judged(up, lane, browser_files("settings"), "settings"))


@pytest.mark.parametrize("name,edit_fn", [
    ("an AssertionResult event that is not the manifest's result", lambda r: [e["payload"].update(actual=True) for e in r["events"] if e["kind"] == "AssertionResult"][:1]),
    ("an AssertionResult event dropped", lambda r: r["events"].remove(next(e for e in r["events"] if e["kind"] == "AssertionResult"))),
    ("an AssertionResult event added", lambda r: r["events"].insert(-1, copy.deepcopy(next(e for e in r["events"] if e["kind"] == "AssertionResult")))),
    ("the seal carries another classification", lambda r: r["events"][-1]["payload"]["classification"].update(outcome="PASS")),
    ("the record states another classification than the seal", lambda r: r["classification"].update(outcome="PASS")),
    ("the manifest has another outcome than the classification", lambda r: r["manifest"].update(outcome="PASS")),
])
def test_a_run_record_that_contradicts_itself_is_named(up, name, edit_fn):
    from qa_runner.corroborate import record_contradicts_itself
    rec = json.loads(browser_files("settings")[RECORD])
    assert record_contradicts_itself(rec, None) is None
    edit_fn(rec)
    assert record_contradicts_itself(rec, None) is not None, name


@pytest.mark.parametrize("name,edit_fn", [
    ("another label", lambda d: d["private"][0].update(label="somewhere")),
    ("an extra network", lambda d: d["private"][0]["networks"].append("10.0.0.0/8")),
    ("an extra port", lambda d: d["private"][0]["ports"].append(22)),
    ("an extra scheme", lambda d: d["private"][0]["schemes"].append("https")),
    ("an extra entry", lambda d: d["private"].append(copy.deepcopy(d["private"][0]))),
    ("an extra key", lambda d: d.update(public=[])),
])
def test_an_egress_profile_that_is_not_exactly_the_plans_for_the_origin_it_names_is_not_accepted(up, lane, name, edit_fn):
    """Review finding L5 (profile fields): only the host and the first port were read."""
    assert unusable(judged(up, lane, edit(browser_files("none"), PROFILE, edit_fn))), name


def test_an_assertion_the_plan_declares_ui_only_does_not_need_the_reference_check_and_the_others_still_do(up, lane):
    """Retest R2: every assertion names a probe or says ui-only; ui-only is not a fact of the reference check, so it is neither vetoed by it nor waits for it."""
    files = {p: d for p, d in browser_files("none").items() if p != PROBE}
    states = judged(up, lane, files)
    assert states["A-SAVED"][0] == states["A-URL"][0] == "VERIFIED" and states["A-NOTIF-ON"] == ("INCONCLUSIVE", "EVIDENCE_MISSING")
    from qa_runner.corroborate import probe_verdicts
    assert probe_verdicts(lane, files) == {"A-NOTIF-ON": "missing"}


@pytest.mark.parametrize("name,edit_fn", [
    ("an extra key", lambda d: d.update(note="x")),
    ("checked changed", lambda d: d.update(checked=["discount-rule"])),
    ("deviations not a list", lambda d: d.update(deviations={})),
    ("a deviation of an unknown check", lambda d: d.update(deviations=[{"check": "x", "where": "/", "expected": 1, "actual": 2}])),
    ("a deviation with a missing field", lambda d: d.update(deviations=[{"check": "discount-rule", "where": "/"}])),
    ("a deviation with an extra field", lambda d: d.update(deviations=[{"check": "discount-rule", "where": "/", "expected": 1, "actual": 2, "z": 3}])),
])
def test_a_reference_check_document_of_another_shape_is_missing_not_clean(up, lane, name, edit_fn):
    """Retest N9: the shape of the document was not validated; only the check names were read, so a reshaped or padded document passed as a clean check."""
    files = edit(browser_files("none"), PROBE, edit_fn)
    assert judged(up, lane, files)["A-NOTIF-ON"] == ("INCONCLUSIVE", "EVIDENCE_MISSING"), name
