# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The reviewed Robot suite run by the real Robot Framework 7.5 through the kit supervisor and the Robot adapter, against the real fixture app. The suite records
observations; the verifier (the SCRIPT executor over the hash-pinned check program) compares them with the value frozen in the plan; the engine's own PASS or FAIL is
kept apart. Every result below comes from a real engine run."""
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from qa_evidence.verify import verify_files
from qa_runner import constants as K, suites
from qa_runner.errors import PlanError
from qa_runner.golden import robot_plan
from qa_runner.orchestrate import RunOptions, run_plan
from qa_runner.plan import freeze_plan
from qa_runner.procs import child_env

pytestmark = pytest.mark.robot_real


@pytest.fixture(scope="module")
def frozen(up):
    return freeze_plan(up, robot_plan())


def run(up, frozen, defect="none", **kw):
    return run_plan(up, frozen, RunOptions(defect=defect, **kw))


def rep(s):
    return json.loads(s.bundle.files["report.json"])


def test_clean_target_real_engine_pass_and_every_assertion_verified(up, frozen):
    s = run(up, frozen, "none")
    r = rep(s)
    assert (s.outcome, s.exit_code, s.lanes) == ("VERIFIED", 0, (("robot", "NATIVE_PASS"),)), r["accounting"]
    assert r["lanes"][0]["engine"] == {"name": "robot-framework", "version": "7.5"}
    assert verify_files(s.bundle.files, plan_digest=frozen.plan_digest).ok


def test_seeded_discount_defect_the_engines_own_check_fails_and_so_does_the_frozen_assertion(up, frozen):
    s = run(up, frozen, "discount")
    r = rep(s)
    assert (s.outcome, s.exit_code, s.lanes) == ("FAILED", 1, (("robot", "NATIVE_FAIL"),))
    assert r["accounting"]["results"][0]["verdict"]["state"] == "FAILED" and r["lanes"][0]["native"]["counts"] == {"passed": 0, "failed": 1, "errored": 0, "skipped": 0}
    observed = json.loads(s.bundle.files["lanes/robot/observations.json"])["spec"]["observations"]
    assert observed == {"order_101_total_cents": 10500, "order_102_total_cents": 9999, "order_103_total_cents": 10000, "order_104_total_cents": 10005}
    assert verify_files(s.bundle.files, plan_digest=frozen.plan_digest).ok


def test_the_settings_defect_does_not_touch_the_order_rule(up, frozen):
    assert run(up, frozen, "settings").outcome == "VERIFIED"


def test_the_record_is_derived_from_the_engines_own_report_and_carries_no_expected_value(up, frozen):
    s = run(up, frozen, "none")
    record = json.loads(s.bundle.files["lanes/robot/observations.json"])
    native = s.bundle.files["lanes/robot/native/output.xml"]
    assert record["spec"]["output_xml_sha256"] == "sha256:" + hashlib.sha256(native).hexdigest()
    text = s.bundle.files["lanes/robot/observations.json"].decode()
    assert "expected" not in text.lower() and "verdict" not in text.lower() and record["spec"]["engine_release"] == "7.5"
    assert b"qa-observe:order_101_total_cents=9450" in native


def test_the_reviewed_files_in_the_bundle_are_the_frozen_ones(up, frozen):
    s = run(up, frozen, "none")
    lock = json.loads(s.bundle.files["plan.lock.json"])
    for rel, digest in lock["lanes"][0]["suite_files"].items():
        assert "sha256:" + hashlib.sha256(s.bundle.files[f"lanes/robot/suite/{rel}"]).hexdigest() == digest


def test_a_library_changed_after_freezing_is_refused_before_the_engine_starts(up, frozen, tmp_path, monkeypatch):
    copy = tmp_path / "suite"
    shutil.copytree(suites.SUITE_DIR, copy)
    (copy / "OrderApi.py").write_text((copy / "OrderApi.py").read_text() + "\n# changed\n")
    monkeypatch.setattr(suites, "SUITE_DIR", copy)
    s = run(up, frozen, "none")
    assert s.lanes == (("robot", "NATIVE_ERROR"),) and s.outcome == "INCONCLUSIVE" and "lanes/robot/native/output.xml" not in s.bundle.files


CANNED = '''
_TOTALS = {"101": 9450, "102": 9999, "103": 9000, "104": 9005}


def get_order_total_cents(order_id):
    return _TOTALS[str(order_id)]
'''


def swapped_suite(tmp_path, monkeypatch):
    copy = tmp_path / "suite"
    shutil.copytree(suites.SUITE_DIR, copy)
    api = (copy / "OrderApi.py").read_text()
    (copy / "OrderApi.py").write_text(api[:api.index("def get_order_total_cents")] + CANNED)       # the library no longer calls the app
    monkeypatch.setattr(suites, "SUITE_DIR", copy)


def test_a_swapped_library_is_refused_when_the_plan_is_the_committed_one(up, tmp_path, monkeypatch):
    """Review finding B1: `run examples/robot-plan.json` with a library that is not the reviewed one was VERIFIED against a defective target (the digests were computed from whatever was installed)."""
    committed = json.loads((Path(__file__).resolve().parents[2] / "examples" / "robot-plan.json").read_text(encoding="utf-8"))
    assert freeze_plan(up, committed).plan_digest == frozen_digest(up)
    swapped_suite(tmp_path, monkeypatch)
    with pytest.raises(PlanError) as exc:
        freeze_plan(up, committed)
    assert exc.value.code == "SUITE_MISMATCH" and "OrderApi.py" in str(exc.value)


def frozen_digest(up):
    return freeze_plan(up, robot_plan()).plan_digest


@pytest.mark.parametrize("defect", ["none", "discount"])
def test_a_swapped_library_that_never_asks_the_target_is_not_verified_even_when_the_plan_was_updated_to_match(up, tmp_path, monkeypatch, defect):
    """Review finding B1, second line of defence: the target's own request log must show the four order requests the reviewed library makes."""
    swapped_suite(tmp_path, monkeypatch)
    s = run(up, freeze_plan(up, robot_plan()), defect)
    r = rep(s)
    assert s.outcome == "INCONCLUSIVE" and r["accounting"]["verified"] == 0 and r["accounting"]["results"][0]["verdict"]["reason_code"] == "EVIDENCE_UNUSABLE"


IGNORES = '''
_TOTALS = {"101": 9450, "102": 9999, "103": 9000, "104": 9005}
'''


def swapped_suite_that_asks_and_ignores(tmp_path, monkeypatch):
    """A library that still calls GET /api/orders/<id> (so the request log is right) and returns constants instead of the answer."""
    copy = tmp_path / "suite"
    shutil.copytree(suites.SUITE_DIR, copy)
    api = (copy / "OrderApi.py").read_text()
    assert "    return total" in api
    (copy / "OrderApi.py").write_text(api.replace("    return total", "    return _TOTALS[order_id]") + IGNORES)
    monkeypatch.setattr(suites, "SUITE_DIR", copy)


def test_a_library_that_asks_and_ignores_the_answers_is_not_verified_against_a_defective_target_and_the_plan_cannot_drop_its_probe(up, tmp_path, monkeypatch):
    """Retest R2: with the plan regenerated for the edited files the committed probe vetoes it (INCONCLUSIVE); with the probe removed or declared ui-only the plan is refused at freeze, so there is no
    plan under which the swapped library reaches VERIFIED on the discount-defective target."""
    swapped_suite_that_asks_and_ignores(tmp_path, monkeypatch)
    s = run(up, freeze_plan(up, robot_plan()), "discount")
    assert s.outcome == "INCONCLUSIVE" and rep(s)["accounting"]["verified"] == 0
    for edit, code in ((lambda p: p["lanes"][0].pop("probes"), "MISSING_FIELD"), (lambda p: p["lanes"][0].update(probes={}), "BAD_PROBES"),
                       (lambda p: p["lanes"][0].update(probes={"A-ORDER-RULE": "ui-only"}), "BAD_PROBES")):
        plan = robot_plan()
        edit(plan)
        with pytest.raises(PlanError) as exc:
            freeze_plan(up, plan)
        assert exc.value.code == code


def test_an_order_assertion_labelled_with_the_settings_fact_is_refused_at_freeze_so_a_library_that_ignores_the_answers_cannot_hide_behind_it(up, tmp_path, monkeypatch):
    """Retest R2b: the library asks and ignores the answers; the plan is regenerated for it and the order assertion is labelled `settings-persistence` (a check that never looks at orders), so the
    discount-defective target would have been VERIFIED. The pairing is refused at freeze, naming what the fact speaks for."""
    swapped_suite_that_asks_and_ignores(tmp_path, monkeypatch)
    plan = robot_plan()
    plan["lanes"][0]["probes"] = {"A-ORDER-RULE": "settings-persistence"}
    with pytest.raises(PlanError) as exc:
        freeze_plan(up, plan)
    assert exc.value.code == "BAD_PROBES" and "cannot cover assertion 'A-ORDER-RULE'" in str(exc.value)


def test_a_suite_that_imports_a_library_nobody_reviewed_is_refused_by_the_adapter(up, tmp_path, monkeypatch):
    """The plan is frozen with this (edited) suite, so the hashes agree; the adapter still refuses a library that is not on the reviewed list."""
    copy = tmp_path / "suite"
    shutil.copytree(suites.SUITE_DIR, copy)
    robot_file = copy / "order_discount.robot"
    robot_file.write_text(robot_file.read_text().replace("Library           OrderApi.py", "Library           OrderApi.py\nLibrary           OperatingSystem"))
    monkeypatch.setattr(suites, "SUITE_DIR", copy)
    edited = freeze_plan(up, robot_plan())
    s = run(up, edited, "none")
    assert s.lanes == (("robot", "NATIVE_ERROR"),) and s.outcome == "INCONCLUSIVE" and rep(s)["lanes"][0]["native"]["raw_status"] == "error-library_refused"


def test_a_lane_that_outlives_its_deadline_is_a_timeout_and_no_engine_process_survives(up, frozen, tmp_path, monkeypatch):
    copy = tmp_path / "suite"
    shutil.copytree(suites.SUITE_DIR, copy)
    robot_file = copy / "order_discount.robot"
    robot_file.write_text(robot_file.read_text().replace("Order Discount Rule\n", "Order Discount Rule\n    Sleep    600\n", 1))
    monkeypatch.setattr(suites, "SUITE_DIR", copy)
    s = run(up, freeze_plan(up, robot_plan()), "none", lane_deadline_s=3)
    assert s.lanes == (("robot", "NATIVE_TIMEOUT"),) and s.outcome == "INCONCLUSIVE" and s.exit_code == K.EXIT_ENVIRONMENT


def test_the_command_line_end_to_end_with_the_robot_plan(tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(robot_plan()))
    env = child_env(str(tmp_path))
    for defect, code, outcome in (("none", 0, "VERIFIED"), ("discount", 1, "FAILED")):
        out = tmp_path / f"out-{defect}"
        done = subprocess.run([sys.executable, "-s", "-m", "qa_runner", "run", str(plan), "--out", str(out), "--defect", defect], env=env, cwd=str(tmp_path),
                              capture_output=True, text=True, timeout=180)
        assert done.returncode == code and f": {outcome} (" in done.stdout, done.stdout + done.stderr
        assert "re-verification in a fresh process (the same code as the run, not independent code): ACCEPTED" in done.stdout
        (bundle,) = list(out.iterdir())
        assert subprocess.run([sys.executable, "-s", "-m", "qa_evidence", "verify", str(bundle)], env=env, capture_output=True, timeout=60).returncode == 0
