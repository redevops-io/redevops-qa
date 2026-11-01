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


def states_of(summary):
    return {x["assertion_id"]: (x["verdict"]["state"], x["verdict"]["reason_code"]) for x in report(summary)["accounting"]["results"]}


@pytest.mark.parametrize("mode", ["pass", "settings-bug", "native-fail-verified", "disagree", "unknown-field"])
def test_a_lane_run_by_a_test_double_can_never_be_verified_or_failed_whatever_it_writes(up, golden_frozen, mode):
    """Review finding H1. The double of these tests wrote a pass with an empty target log and the run was VERIFIED, exit 0. Now it is labelled, INCONCLUSIVE (TEST_DOUBLE), exit 4."""
    s = run(up, golden_frozen, mode)
    r = report(s)
    assert (s.outcome, s.exit_code) == ("INCONCLUSIVE", K.EXIT_INCONCLUSIVE), mode
    assert set(states_of(s).values()) == {("INCONCLUSIVE", "TEST_DOUBLE")} and r["extensions"]["test_double"] == "lane-command"


def test_an_executor_environment_failure_is_an_engine_error_even_when_the_observations_look_right(up, golden_frozen):
    s = run(up, golden_frozen, "env-fail")
    assert (s.outcome, s.exit_code, s.lanes) == ("INCONCLUSIVE", K.EXIT_ENVIRONMENT, (("browser", "NATIVE_ERROR"),))


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


def test_rows_that_are_not_rows_are_not_recorded_and_leave_everything_inconclusive(up, golden_frozen):
    s = run(up, golden_frozen, "junk-rows")
    assert s.outcome == "INCONCLUSIVE" and "lanes/browser/observations.json" not in s.bundle.files
    assert {v[0] for v in states_of(s).values()} == {"INCONCLUSIVE"} and verify_files(s.bundle.files).ok


@pytest.mark.parametrize("outcome,reason,status", [("PASS", None, "NATIVE_PASS"), ("PRODUCT_FAIL", None, "NATIVE_FAIL"), ("ENVIRONMENT_FAIL", "LANE_DEADLINE", "NATIVE_TIMEOUT"),
                                                  ("ENVIRONMENT_FAIL", None, "NATIVE_ERROR"), ("WHATEVER", None, "NATIVE_ERROR")])
def test_the_engine_status_comes_from_the_executors_own_outcome(outcome, reason, status):
    from qa_runner.natives import native_from_harness
    assert native_from_harness(outcome, reason)[0] == status


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


def test_the_temporary_directory_is_removed_when_the_run_fails(up, golden_frozen, monkeypatch, tmp_path):
    """Review findings M5/M6: a run that failed after the target started used to leave /tmp/redevops-qa-* behind."""
    import tempfile
    import qa_runner.orchestrate as orch
    made = []
    original = orch.make_workdir

    def spy():
        d = original()
        made.append(d)
        return d
    monkeypatch.setattr(orch, "make_workdir", spy)
    monkeypatch.setattr(orch, "run_browser_lane", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        run(up, golden_frozen, "pass")
    assert made and not __import__("os").path.exists(made[0])


@pytest.mark.parametrize("deadline", [0, -5, 3601])
def test_a_lane_deadline_outside_1_to_3600_is_refused_before_anything_starts(up, golden_frozen, deadline, monkeypatch):
    started = []
    monkeypatch.setattr(FixtureApp, "start", lambda self, timeout_s=20.0: started.append(1))
    with pytest.raises(PlanError) as exc:
        run_plan(up, golden_frozen, RunOptions(lane_command=fake("pass"), lane_deadline_s=deadline))
    assert exc.value.code == "BAD_DEADLINE" and started == []


def test_the_fixture_must_report_the_defect_the_run_asked_for(monkeypatch, tmp_path):
    """Review finding L4: the app prints its defect in the ready line; the run used to record its own argument without looking."""
    import qa_runner.procs as procs
    real = procs.subprocess.Popen

    def popen_for_another_defect(argv, *a, **k):
        return real([("none" if x == "discount" else x) for x in argv], *a, **k)        # the process runs 'none' although the run asked for 'discount'
    monkeypatch.setattr(procs.subprocess, "Popen", popen_for_another_defect)
    app = FixtureApp("discount", str(tmp_path / "r.jsonl"), home=str(tmp_path))
    with pytest.raises(EnvironmentFault) as exc:
        app.start()
    assert exc.value.code == "FIXTURE_APP_WRONG_DEFECT" and app.running is False


def test_a_generated_run_id_has_64_random_bits_and_fits_the_lane_ids_and_is_not_read_as_a_cut_off_digest(up):
    from qa_runner.orchestrate import new_run_id
    ids = {new_run_id() for _ in range(200)}
    from agent_harness.qa.blobs import find_truncated_digests
    assert not find_truncated_digests({"run_id": next(iter(ids)) + ".browser"})
    assert len(ids) == 200 and all(K.RUN_ID_RE.fullmatch(i) and len(i.rsplit("-", 1)[1]) == 13 for i in ids)
