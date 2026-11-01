# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""What the parent does with a lane child that finishes, fails, hangs, crashes or leaves a stray process behind. The children here are a TEST DOUBLE
(``fake_lane.py``); the real browser lane is exercised in ``tests/browser``. The target (the fixture app) is real."""
import json
import threading
import time

import pytest

from qa_adapter_kit.supervisor import CancelToken
from qa_evidence.verify import verify_files
from qa_runner import constants as K
from qa_runner.errors import EnvironmentFault, PlanError
from qa_runner.orchestrate import RunOptions, exit_code_for, run_plan
from qa_runner.procs import FixtureApp
from qr_support import alive, fake, gateway_down, wait_gone


def run(up, frozen, mode, *extra, deadline=30, **kw):
    return run_plan(up, frozen, RunOptions(lane_command=fake(mode, *extra), lane_deadline_s=deadline, run_id="r0-test", **kw))


def report(summary):
    return json.loads(summary.bundle.files["report.json"])


def test_a_finished_lane_with_matching_observations_is_verified_and_exits_zero(up, golden_frozen):
    s = run(up, golden_frozen, "pass")
    assert (s.outcome, s.exit_code, s.lanes) == ("VERIFIED", K.EXIT_VERIFIED, (("browser", "NATIVE_PASS"),))
    assert verify_files(s.bundle.files, plan_digest=s.plan_digest).ok


def test_a_failed_assertion_fails_the_run_and_exits_one(up, golden_frozen):
    s = run(up, golden_frozen, "settings-bug")
    r = report(s)
    assert (s.outcome, s.exit_code) == ("FAILED", K.EXIT_FAILED) and s.lanes == (("browser", "NATIVE_FAIL"),)
    assert {x["assertion_id"]: x["verdict"]["state"] for x in r["accounting"]["results"]} == {"A-NOTIF-ON": "FAILED", "A-SAVED": "VERIFIED", "A-URL": "VERIFIED"}


def test_an_executor_environment_failure_is_an_engine_error_even_when_the_observations_look_right(up, golden_frozen):
    s = run(up, golden_frozen, "env-fail")
    assert (s.outcome, s.exit_code, s.lanes) == ("INCONCLUSIVE", K.EXIT_ENVIRONMENT, (("browser", "NATIVE_ERROR"),))


def test_an_engine_failure_with_every_assertion_verified_is_inconclusive_and_exits_four(up, golden_frozen):
    s = run(up, golden_frozen, "native-fail-verified")
    assert (s.outcome, s.reason_code, s.exit_code) == ("INCONCLUSIVE", "NATIVE_FAIL_VERIFIED_ASSERTIONS", K.EXIT_INCONCLUSIVE)


def test_a_lane_that_outlives_its_deadline_is_a_timeout_never_verified(up, golden_frozen):
    t0 = time.monotonic()
    s = run(up, golden_frozen, "hang", deadline=1)
    assert time.monotonic() - t0 < 20
    assert (s.outcome, s.exit_code, s.lanes) == ("INCONCLUSIVE", K.EXIT_ENVIRONMENT, (("browser", "NATIVE_TIMEOUT"),))
    r = report(s)
    assert r["accounting"]["inconclusive"] == 3 and r["accounting"]["verified"] == 0 and r["lanes"][0]["native"]["raw_status"] == "timeout"
    assert verify_files(s.bundle.files).ok


def test_a_crashing_lane_is_an_engine_error_with_its_exit_code_and_never_verified(up, golden_frozen):
    s = run(up, golden_frozen, "exit7")
    assert (s.outcome, s.exit_code, s.lanes) == ("INCONCLUSIVE", K.EXIT_ENVIRONMENT, (("browser", "NATIVE_ERROR"),))
    assert report(s)["lanes"][0]["native"]["exit_code"] == 7


@pytest.mark.parametrize("mode", ["garbage", "unknown-field", "nonsense"])
def test_an_unreadable_or_forged_lane_result_is_never_verified(up, golden_frozen, mode):
    s = run(up, golden_frozen, mode)
    assert s.outcome == "INCONCLUSIVE" and s.exit_code != 0


def test_a_forged_verdict_field_in_the_observations_leaves_the_assertions_inconclusive(up, golden_frozen):
    s = run(up, golden_frozen, "unknown-field")
    r = report(s)
    assert {x["verdict"]["reason_code"] for x in r["accounting"]["results"]} == {"EVIDENCE_UNUSABLE"} and r["verdict"]["outcome"] == "INCONCLUSIVE"


def test_the_inrun_verifier_disagreeing_with_the_recomputation_certifies_nothing(up, golden_frozen):
    s = run(up, golden_frozen, "disagree")
    r = report(s)
    assert s.outcome == "INCONCLUSIVE" and {x["assertion_id"]: x["verdict"]["reason_code"] for x in r["accounting"]["results"]}["A-NOTIF-ON"] == "VERIFIER_ERROR"


def test_a_gateway_that_cannot_start_fails_the_lane_closed_and_no_browser_is_started(up, golden_frozen):
    s = run_plan(up, golden_frozen, RunOptions(lane_command=gateway_down, lane_deadline_s=30, run_id="r0-test"))
    r = report(s)
    assert (s.outcome, s.exit_code, s.lanes) == ("INCONCLUSIVE", K.EXIT_ENVIRONMENT, (("browser", "NATIVE_ERROR"),))
    assert r["lanes"][0]["native"]["raw_status"] == "lane-error" and r["accounting"]["verified"] == 0 and r["accounting"]["inconclusive"] == 3
    assert "lanes/browser/native/run-record.json" not in s.bundle.files          # nothing ran: there is no run record to show


def test_a_stray_process_the_lane_leaves_is_ended_with_the_lane(up, golden_frozen, tmp_path):
    pidfile = tmp_path / "orphan.pid"
    s = run(up, golden_frozen, "orphan", str(pidfile), deadline=2)
    assert s.lanes == (("browser", "NATIVE_TIMEOUT"),)
    pid = int(pidfile.read_text())
    assert wait_gone(pid), "the grandchild that ignored SIGTERM survived the lane"


def test_cancelling_during_a_lane_ends_the_lane_and_the_run_is_not_verified(up, golden_frozen, tmp_path):
    cancel = CancelToken()
    threading.Timer(1.0, cancel.cancel).start()
    t0 = time.monotonic()
    s = run_plan(up, golden_frozen, RunOptions(lane_command=fake("hang"), lane_deadline_s=60, run_id="r0-test", cancel=cancel))
    assert time.monotonic() - t0 < 30
    r = report(s)
    assert s.cancelled and s.outcome == "INCONCLUSIVE" and s.exit_code == K.EXIT_ENVIRONMENT
    assert r["lanes"][0]["native"]["status"] == "NATIVE_ERROR" and r["lanes"][0]["native"]["raw_status"] == "cancelled"


def test_a_run_cancelled_before_the_lane_starts_skips_it_and_still_accounts_for_every_assertion(up, golden_frozen):
    cancel = CancelToken()
    cancel.cancel()
    s = run_plan(up, golden_frozen, RunOptions(lane_command=fake("pass"), run_id="r0-test", cancel=cancel))
    r = report(s)
    assert r["lanes"][0]["native"]["status"] == "NATIVE_SKIPPED" and r["accounting"]["inconclusive"] == 3 and s.exit_code == K.EXIT_ENVIRONMENT


def test_a_target_that_does_not_start_leaves_the_lane_unavailable_and_everything_inconclusive(up, golden_frozen, monkeypatch):
    def refuse(self, timeout_s=20.0):
        raise EnvironmentFault("FIXTURE_APP_NOT_STARTED", "test")
    monkeypatch.setattr(FixtureApp, "start", refuse)
    s = run(up, golden_frozen, "pass")
    r = report(s)
    assert s.lanes == (("browser", "NATIVE_UNAVAILABLE"),) and r["accounting"]["inconclusive"] == 3 and s.exit_code == K.EXIT_ENVIRONMENT
    assert "target not started" in s.bundle.files["logs/orchestrator.log"].decode()


def test_the_target_is_stopped_when_the_run_ends(up, golden_frozen, monkeypatch):
    pids = []
    original = FixtureApp.start

    def spy(self, timeout_s=20.0):
        out = original(self, timeout_s)
        pids.append(self.pid)
        return out
    monkeypatch.setattr(FixtureApp, "start", spy)
    run(up, golden_frozen, "pass")
    assert pids and wait_gone(pids[0])


def test_the_target_is_stopped_even_when_the_run_raises(up, golden_frozen, monkeypatch):
    pids = []
    original = FixtureApp.start

    def spy(self, timeout_s=20.0):
        out = original(self, timeout_s)
        pids.append(self.pid)
        return out
    monkeypatch.setattr(FixtureApp, "start", spy)
    import qa_runner.orchestrate as orch

    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(orch, "run_browser_lane", boom)
    with pytest.raises(RuntimeError):
        run(up, golden_frozen, "pass")
    assert pids and wait_gone(pids[0])


def test_the_target_started_with_the_defect_the_run_names_and_the_defect_is_recorded(up, golden_frozen):
    s = run(up, golden_frozen, "pass", defect="settings")
    r = report(s)
    assert r["extensions"]["target_defect"] == "settings"
    assert "defect settings" in s.bundle.files["logs/orchestrator.log"].decode()


def test_the_request_log_of_the_target_is_part_of_the_bundle(up, golden_frozen):
    s = run(up, golden_frozen, "pass")
    assert "logs/target-requests.jsonl" in s.bundle.files


@pytest.mark.parametrize("run_id", ["", "-x", "a" * 41, "a b", "a/b", "a\n"])
def test_a_bad_run_id_is_refused_before_anything_starts(up, golden_frozen, run_id):
    with pytest.raises(PlanError) as exc:
        run_plan(up, golden_frozen, RunOptions(run_id=run_id, lane_command=fake("pass")))
    assert exc.value.code == "BAD_RUN_ID"


def test_an_unknown_defect_is_refused(up, golden_frozen):
    with pytest.raises(PlanError) as exc:
        run_plan(up, golden_frozen, RunOptions(defect="everything", lane_command=fake("pass")))
    assert exc.value.code == "BAD_DEFECT"


def test_a_lane_deadline_option_lowers_the_plan_deadline(up, golden_frozen):
    t0 = time.monotonic()
    s = run_plan(up, golden_frozen, RunOptions(lane_command=fake("hang"), lane_deadline_s=1, run_id="r0-test"))
    assert time.monotonic() - t0 < 20 and s.lanes == (("browser", "NATIVE_TIMEOUT"),)


def test_a_lane_deadline_option_never_raises_the_plan_deadline(up):
    from qa_runner.golden import golden_plan
    from qa_runner.plan import freeze_plan
    plan = golden_plan()
    plan["lanes"][0]["deadline_s"] = 1
    frozen = freeze_plan(up, plan)
    t0 = time.monotonic()
    s = run_plan(up, frozen, RunOptions(lane_command=fake("hang"), lane_deadline_s=1000, run_id="r0-test"))
    assert time.monotonic() - t0 < 20 and s.lanes == (("browser", "NATIVE_TIMEOUT"),)


@pytest.mark.parametrize("outcome,status,code", [("VERIFIED", "NATIVE_PASS", 0), ("FAILED", "NATIVE_FAIL", 1), ("INCONCLUSIVE", "NATIVE_PASS", 4), ("INCONCLUSIVE", "NATIVE_ERROR", 3),
                                                 ("INCONCLUSIVE", "NATIVE_TIMEOUT", 3), ("INCONCLUSIVE", "NATIVE_UNAVAILABLE", 3), ("INCONCLUSIVE", "NATIVE_SKIPPED", 3)])
def test_the_exit_code_table(outcome, status, code):
    rep = {"verdict": {"outcome": outcome}, "lanes": [{"native": {"status": status}}]}
    assert exit_code_for(rep) == code
    assert exit_code_for({"verdict": {"outcome": "INCONCLUSIVE"}, "lanes": [{"native": {"status": "NATIVE_PASS"}}]}, cancelled=True) == 3
    assert exit_code_for({"verdict": {"outcome": "VERIFIED"}, "lanes": [{"native": {"status": "NATIVE_PASS"}}]}) == 0
