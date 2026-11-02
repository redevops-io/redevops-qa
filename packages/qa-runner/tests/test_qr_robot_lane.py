# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The Robot lane as the parent sees it. The engine here is a TEST DOUBLE (``fake_robot.py``) that asks the real target for the order totals; the real Robot Framework
runs the real suite in ``tests/real``. The target (the fixture app) and the supervisor are real."""
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from qa_adapter_kit.supervisor import CancelToken
from qa_evidence.verify import verify_files
from qa_runner import constants as K, suites
from qa_runner.golden import golden_plan, robot_lane, robot_plan
from qa_runner.orchestrate import RunOptions, run_plan
from qa_runner.plan import freeze_plan
from qa_runner.procs import FixtureApp
from qa_runner.procs import child_env
from qr_support import descendants, fake_robot, process_table, reap, wait_for, wait_gone


@pytest.fixture(scope="module")
def frozen(up):
    return freeze_plan(up, robot_plan())


def run(up, frozen, mode, defect="none", deadline=60, **kw):
    return run_plan(up, frozen, RunOptions(defect=defect, robot_launcher=fake_robot(mode), lane_deadline_s=deadline, run_id="r0-test", **kw))


def rep(s):
    return json.loads(s.bundle.files["report.json"])


def verdict(s):
    return rep(s)["accounting"]["results"][0]["verdict"]


def test_a_clean_target_is_a_native_pass_and_a_test_double_is_never_verified(up, frozen):
    """The engine here is a double, so the lane carries no verdict whatever it wrote; VERIFIED for the real engine is in ``tests/real``."""
    s = run(up, frozen, "live")
    assert (s.outcome, s.exit_code, s.lanes) == ("INCONCLUSIVE", K.EXIT_INCONCLUSIVE, (("robot", "NATIVE_PASS"),))
    assert (verdict(s)["state"], verdict(s)["reason_code"]) == ("INCONCLUSIVE", "TEST_DOUBLE") and rep(s)["extensions"]["test_double"] == "lane-command"
    assert verify_files(s.bundle.files, plan_digest=frozen.plan_digest).ok


def test_the_discount_defect_is_a_native_fail_of_the_engine(up, frozen):
    s = run(up, frozen, "live", defect="discount")
    r = rep(s)
    assert s.lanes == (("robot", "NATIVE_FAIL"),) and verdict(s)["reason_code"] == "TEST_DOUBLE"
    assert r["lanes"][0]["native"]["counts"] == {"passed": 0, "failed": 1, "errored": 0, "skipped": 0} and r["lanes"][0]["native"]["exit_code"] == 1
    assert verify_files(s.bundle.files, plan_digest=frozen.plan_digest).ok


def test_the_bundle_holds_the_engine_report_the_record_and_the_reviewed_files(up, frozen):
    s = run(up, frozen, "live")
    names = set(s.bundle.files)
    assert {"lanes/robot/native/output.xml", "lanes/robot/native/adapter-result.json", "lanes/robot/observations.json", "lanes/robot/suite/OrderApi.py",
            "lanes/robot/suite/order_discount.robot", "lanes/robot/egress-profile.json", "plan.lock.json"} <= names
    roles = {f["path"]: f["role"] for f in s.bundle.manifest["files"]}
    assert roles["lanes/robot/native/output.xml"] == "native-artifact" and roles["lanes/robot/observations.json"] == "observation"
    assert roles["lanes/robot/suite/OrderApi.py"] == "record"
    lock = json.loads(s.bundle.files["plan.lock.json"])
    import hashlib
    for rel, digest in lock["lanes"][0]["suite_files"].items():
        assert "sha256:" + hashlib.sha256(s.bundle.files[f"lanes/robot/suite/{rel}"]).hexdigest() == digest


def test_the_egress_profile_of_a_robot_lane_says_it_is_not_enforced(up, frozen):
    s = run(up, frozen, "live")
    profile = json.loads(s.bundle.files["lanes/robot/egress-profile.json"])
    assert profile["profile"] == "not-enforced" and "own sockets" in profile["note"]


def test_the_native_result_and_the_verdict_stay_separate_for_the_robot_lane(up, frozen):
    r = rep(run(up, frozen, "live", defect="discount"))
    assert r["lanes"][0]["native"]["status"] == "NATIVE_FAIL" and r["accounting"]["results"][0]["native_status"] == "NATIVE_FAIL"
    assert r["accounting"]["results"][0]["verdict"]["state"] == "INCONCLUSIVE"


def test_an_engine_that_hangs_is_a_timeout_and_never_verified(up, frozen):
    t0 = time.monotonic()
    s = run(up, frozen, "hang", deadline=2)
    assert time.monotonic() - t0 < 30 and (s.outcome, s.exit_code, s.lanes) == ("INCONCLUSIVE", K.EXIT_ENVIRONMENT, (("robot", "NATIVE_TIMEOUT"),))
    assert verdict(s)["state"] == "INCONCLUSIVE" and "lanes/robot/observations.json" not in s.bundle.files


def test_a_stray_process_the_engine_leaves_is_ended_with_the_run(up, frozen, tmp_path):
    pidfile = tmp_path / "engine.pid"
    s = run(up, frozen, f"pidfile:{pidfile}", deadline=2)
    assert s.lanes == (("robot", "NATIVE_TIMEOUT"),)
    assert wait_gone(int(pidfile.read_text()))


def test_an_engine_that_exits_without_a_report_is_an_engine_error(up, frozen):
    for mode in ("exit2", "no-output"):
        s = run(up, frozen, mode)
        assert s.outcome == "INCONCLUSIVE" and s.exit_code == K.EXIT_ENVIRONMENT and s.lanes[0][1] == "NATIVE_ERROR", mode


def test_a_report_with_an_observation_named_like_an_expected_value_leaves_no_record_and_is_never_verified(up, frozen):
    s = run(up, frozen, "tag-expected")
    assert s.lanes == (("robot", "NATIVE_PASS"),) and s.outcome == "INCONCLUSIVE" and verdict(s)["state"] == "INCONCLUSIVE"
    assert "lanes/robot/observations.json" not in s.bundle.files
    assert "could not be imported" in s.bundle.files["logs/orchestrator.log"].decode()


def test_suite_files_that_changed_after_freezing_are_refused_before_anything_runs(up, frozen, tmp_path, monkeypatch):
    copy = tmp_path / "suite"
    shutil.copytree(suites.SUITE_DIR, copy)
    (copy / "OrderApi.py").write_text((copy / "OrderApi.py").read_text() + "\n# edited after the plan was frozen\n")
    monkeypatch.setattr(suites, "SUITE_DIR", copy)
    s = run(up, frozen, "live")
    assert s.lanes == (("robot", "NATIVE_ERROR"),) and s.outcome == "INCONCLUSIVE" and rep(s)["lanes"][0]["native"]["raw_status"] == "suite-hash-mismatch"
    assert "lanes/robot/native/output.xml" not in s.bundle.files


def test_a_target_that_does_not_start_leaves_the_robot_lane_unavailable(up, frozen, monkeypatch):
    from qa_runner.errors import EnvironmentFault

    def refuse(self, timeout_s=20.0):
        raise EnvironmentFault("FIXTURE_APP_NOT_STARTED", "test")
    monkeypatch.setattr(FixtureApp, "start", refuse)
    s = run(up, frozen, "live")
    assert s.lanes == (("robot", "NATIVE_UNAVAILABLE"),) and s.exit_code == K.EXIT_ENVIRONMENT


def test_a_run_cancelled_before_the_lane_starts_skips_it(up, frozen):
    cancel = CancelToken()
    cancel.cancel()
    s = run(up, frozen, "live", cancel=cancel)
    assert s.lanes == (("robot", "NATIVE_SKIPPED"),) and s.cancelled and s.exit_code == K.EXIT_ENVIRONMENT


def test_a_two_lane_plan_runs_both_lanes_in_order_when_the_browser_lane_is_a_double(up):
    """The browser lane is the test double of PR 4; the Robot lane is the Robot double. The accounting covers both lanes exactly once."""
    from qr_support import fake
    plan = golden_plan()
    plan["lanes"].append(robot_lane())
    fz = freeze_plan(up, plan)
    s = run_plan(up, fz, RunOptions(lane_command=fake("pass"), robot_launcher=fake_robot("live"), lane_deadline_s=60, run_id="r0-test"))
    assert s.lanes == (("browser", "NATIVE_PASS"), ("robot", "NATIVE_PASS")) and s.outcome == "INCONCLUSIVE"
    r = rep(s)
    assert r["accounting"]["frozen"] == 4 == r["accounting"]["inconclusive"] and {x["lane_id"] for x in r["accounting"]["results"]} == {"browser", "robot"}


def test_killing_the_parent_without_warning_ends_the_engine_and_what_it_started(tmp_path):
    """Review finding M1: after SIGKILL of the runner the Robot engine (and a stray child of it) kept running; nothing watched the parent."""
    here = Path(__file__).resolve().parent
    proc = subprocess.Popen([sys.executable, "-s", str(here / "slow_robot_parent.py")], env=child_env(str(tmp_path)), cwd=str(tmp_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            start_new_session=True)
    seen = set()
    try:
        def engine_running():
            table = process_table()
            kids = descendants(proc.pid, table)
            seen.update(kids)
            return any("slow_robot.py" in table[k][2] for k in kids if k in table) and any("guard-stray" in table[k][2] for k in kids if k in table)
        assert wait_for(engine_running, 60), "the engine and its stray child never started"
        seen.update(descendants(proc.pid))
        proc.kill()
        proc.communicate(timeout=30)
        assert [p for p in seen if not wait_gone(p, 25)] == []
    finally:
        reap(proc, seen)


def test_the_engine_is_started_under_the_guard_that_watches_the_parent(up, frozen, tmp_path, monkeypatch):
    import qa_runner.lane_robot as lr
    seen = {}

    class Stop(Exception):
        pass

    def adapter(python, **kw):
        seen.update(kw)
        raise Stop

    monkeypatch.setattr(lr, "RobotSuiteAdapter", adapter)
    with pytest.raises(Stop):
        lr._run_inner(frozen.lane("robot"), run_id="r0-x", origin="http://127.0.0.1:9", workdir=str(tmp_path), cancel=None, deadline_s=5, log=[])
    assert seen["launcher"] == (lr.GUARD,) and Path(lr.GUARD).name == "robot_guard.py" and Path(lr.GUARD).is_file()


def test_the_native_files_of_the_engine_are_read_through_the_bounded_read(up, frozen, tmp_path, monkeypatch):
    """Retest R1 for the Robot lane: a report that is a FIFO or a symlink is not read (and not waited for); the lane ends as an error with no record."""
    import os
    import qa_runner.safe_read as sr
    seen = []
    real = sr.read_regular
    monkeypatch.setattr(sr, "read_regular", lambda path, **kw: seen.append((os.path.basename(path), kw)) or real(path, **kw))
    s = run(up, frozen, "live")
    names = {n for n, _ in seen}
    assert "outcome.json" in names and any(n.endswith(".bin") for n in names)                      # in the parent: the lane child's outcome and the numbered data files it names
    assert all(kw["follow_symlinks"] is False and kw["max_bytes"] <= 64 * 1024 * 1024 for _, kw in seen)


def test_a_robot_lane_over_the_evidence_budget_is_an_engine_error_that_keeps_what_fits(up, frozen):
    """Retest N2 for the Robot lane: the engine's files do not all fit a 6000 byte budget, nothing is deleted, the lane says so and is never verified."""
    s = run_plan(up, frozen, RunOptions(robot_launcher=fake_robot("live"), lane_deadline_s=60, run_id="r0-test", max_evidence_bytes=6000))
    r = rep(s)
    assert s.lanes == (("robot", "NATIVE_ERROR"),) and r["lanes"][0]["native"]["raw_status"] == "evidence-over-cap" and "evidence_incomplete" in r["extensions"]
    assert s.outcome == "INCONCLUSIVE" and s.exit_code == K.EXIT_ENVIRONMENT and verify_files(s.bundle.files).ok
