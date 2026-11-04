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


@pytest.fixture(scope="module")
def frozen_open(up):
    """The same lane with the profile that asks for nothing: ``not-enforced``."""
    return freeze_plan(up, robot_plan("not-enforced"))


def test_the_egress_profile_of_a_robot_lane_that_says_not_enforced_says_it_is_not_enforced(up, frozen_open):
    s = run(up, frozen_open, "live")
    profile = json.loads(s.bundle.files["lanes/robot/egress-profile.json"])
    assert profile["profile"] == "not-enforced" and "own sockets" in profile["note"] and "lanes/robot/egress-log.jsonl" not in s.bundle.files


def test_the_report_states_that_egress_is_not_enforced_for_a_not_enforced_robot_lane_in_json_text_and_html(up, frozen_open, tmp_path):
    from qa_evidence.inspector import inspect_bundle
    from qa_evidence.render import render_html, render_text
    s = run(up, frozen_open, "live")
    (lim,) = [x for x in rep(s)["limitations"] if x["id"] == K.ROBOT_EGRESS_LIMITATION_ID]
    assert lim["text"] == K.robot_egress_limitation_text(["robot"]) and "NOT enforced" in lim["text"] and "(robot)" in lim["text"]
    assert "guard, not a sandbox" in lim["text"] and "Nothing in this report shows" in lim["text"]
    assert K.ROBOT_EGRESS_LAYERS_ID not in [x["id"] for x in rep(s)["limitations"]]
    target = tmp_path / "bundle"
    s.bundle.write_directory(str(target))
    ins = inspect_bundle(str(target))
    assert lim["text"] in render_text(ins) and "egress-not-enforced-robot" in render_html(ins)


def test_the_egress_profile_of_a_robot_lane_that_asks_for_the_layers_is_the_allow_list_and_the_log_names_the_layers(up, frozen):
    from qa_runner import egresslog
    from qa_runner.egress import policy_config
    s = run(up, frozen, "live")
    origin = json.loads(s.bundle.files["lanes/robot/egress-profile.json"])
    port = origin["private"][0]["ports"][0]
    assert origin == policy_config("origin-only", f"http://127.0.0.1:{port}")
    header, events, problems = egresslog.parse(s.bundle.files["lanes/robot/egress-log.jsonl"])
    assert not problems and header["layers"] == list(egresslog.ALL_LAYERS) and header["allowed"] == [f"127.0.0.1/32:{port}"] and header["selftest"]["forbidden_tcp_refused"] is True
    assert {e["verdict"] for e in events} <= {"allow"}                      # the double asks the target and nothing else
    roles = {f["path"]: f["role"] for f in s.bundle.manifest["files"]}
    assert roles["lanes/robot/egress-log.jsonl"] == "log"


def test_the_report_states_the_layers_and_what_they_do_not_stop_for_a_robot_lane_that_asks_for_them(up, frozen, tmp_path):
    from qa_evidence.inspector import inspect_bundle
    from qa_evidence.render import render_html, render_text
    s = run(up, frozen, "live")
    (lim,) = [x for x in rep(s)["limitations"] if x["id"] == K.ROBOT_EGRESS_LAYERS_ID]
    assert lim["text"] == K.robot_egress_layers_text(["robot"]) and "(robot)" in lim["text"] and "What this does not stop" in lim["text"] and "egress-denied" in lim["text"]
    assert K.ROBOT_EGRESS_LIMITATION_ID not in [x["id"] for x in rep(s)["limitations"]]
    assert "NOT enforced" not in lim["text"]
    target = tmp_path / "bundle"
    s.bundle.write_directory(str(target))
    ins = inspect_bundle(str(target))
    assert lim["text"] in render_text(ins) and K.ROBOT_EGRESS_LAYERS_ID in render_html(ins)


def test_a_lane_that_asks_for_layers_that_cannot_be_installed_is_not_started(up, frozen, monkeypatch):
    """No weaker mode: the lane child cannot install the layers (here: the installer refuses), so the engine never starts and the lane is unavailable, with the reason in its egress log."""
    import qa_runner.lane_robot as lane_robot
    from qa_runner import netfence

    def refuse(policy, layers=netfence.ALL_LAYERS):
        raise netfence.FenceUnavailable("landlock-network-rules-unavailable", "the engine must not start")
    monkeypatch.setattr(netfence, "install", refuse)
    out = frozen_unavailable_outcome(up, frozen, lane_robot, refuse)
    assert (out.native_status, out.raw_status) == ("NATIVE_UNAVAILABLE", "egress-unavailable")
    row = json.loads(out.files["lanes/robot/egress-log.jsonl"][0].decode())
    assert row["event"] == "unavailable" and row["reason"] == "landlock-network-rules-unavailable" and not out.native_files and "lanes/robot/native/output.xml" not in out.files


def frozen_unavailable_outcome(up, frozen, lane_robot, refuse):
    """What the lane child writes when ``netfence.install`` raises: run its ``main`` in this process with a lane input, as the supervised child does."""
    import os
    import tempfile
    from qa_evidence.canon import dumps_canonical
    from qa_runner.egress import policy_config
    from qa_runner.safe_read import Budget
    fl = frozen.lane("robot")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out"
        out.mkdir()
        cfg = {"schema": K.LANE_INPUT_SCHEMA, "schema_version": K.SCHEMA_VERSION, "lane_id": "robot", "engine": fl.engine, "suite": fl.suite, "suite_files": dict(fl.suite_files), "run_id": "r0-x",
               "origin": "http://127.0.0.1:1", "deadline_s": 5, "out_dir": str(out), "workdir": tmp, "suite_dir": str(suites.SUITE_DIR), "launcher": None, "parent_pid": None,
               "evidence_budget": 1 << 20, "egress": "origin-only", "egress_policy": policy_config("origin-only", "http://127.0.0.1:1")}
        (Path(tmp) / "in.json").write_bytes(dumps_canonical(cfg))
        import signal
        saved = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}          # main() installs its own handlers: put them back
        try:
            assert lane_robot.main([str(Path(tmp) / "in.json")]) == 0
        finally:
            for sig, handler in saved.items():
                signal.signal(sig, handler)
        outcome, _ = lane_robot._read_outcome(fl, out, Budget(1 << 20, root=tmp))
    return outcome


def test_a_plan_without_a_robot_lane_does_not_carry_the_statement(up, golden_frozen):
    s = run_plan(up, golden_frozen, RunOptions(lane_command=lambda lane, path: [sys.executable, str(Path(__file__).resolve().parent / "fake_lane.py"), "pass", path], run_id="r0-test"))
    assert K.ROBOT_EGRESS_LIMITATION_ID not in [x["id"] for x in rep(s)["limitations"]]
    assert verify_files(s.bundle.files, plan_digest=golden_frozen.plan_digest).ok


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
    spy = lambda path, **kw: seen.append((os.path.basename(path), kw)) or real(path, **kw)      # noqa: E731
    monkeypatch.setattr(sr, "read_regular", spy)
    monkeypatch.setattr("qa_runner.lane_robot.read_regular", spy)                                  # the outcome file is read directly (not charged to the budget)
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


@pytest.mark.parametrize("cap", [1, 200, 600, 1_000, 1_500, 3_000, 5_000, 8_000, 12_000, 20_000, 40_000, 80_000, 160_000])
def test_a_robot_lane_cut_at_any_cap_is_labelled_evidence_over_cap_never_a_child_exit(up, frozen, cap):
    """Retest R2-6: the lane child was handed the whole remaining budget, so the parent had no room left for the child's own outcome file, lost the outcome and labelled the lane `child-exit-0`.
    At every cap the lane is either complete (nothing dropped) or an engine error `evidence-over-cap` that says what was not kept, and the bundle is valid."""
    s = run_plan(up, frozen, RunOptions(robot_launcher=fake_robot("live"), lane_deadline_s=60, run_id="r0-test", max_evidence_bytes=cap))
    r = rep(s)
    raw = r["lanes"][0]["native"]["raw_status"]
    incomplete = "evidence_incomplete" in r["extensions"]
    assert not raw.startswith("child-"), (cap, raw)
    if raw == "evidence-over-cap":
        assert r["lanes"][0]["native"]["status"] == "NATIVE_ERROR" and incomplete and s.exit_code == K.EXIT_ENVIRONMENT and s.outcome != "VERIFIED"
    else:                                              # the lane's own files all fit; at most a log did not, and then the run still says so and is never verified
        assert not incomplete or (s.outcome != "VERIFIED" and s.exit_code == K.EXIT_ENVIRONMENT)
    assert verify_files(s.bundle.files).ok


def test_an_outcome_file_with_a_field_of_the_wrong_kind_is_not_taken_in(tmp_path):
    """Retest R2-6: fields of the lane child's outcome that nothing used were accepted whatever they held."""
    from qa_runner import lane_robot
    from qa_runner.safe_read import Budget
    base = {"schema": K.LANE_RESULT_SCHEMA, "schema_version": K.SCHEMA_VERSION, "status": "COMPLETED", "engine_version": "7.5", "native_status": "NATIVE_PASS", "raw_status": "PASS",
            "exit_code": 0, "counts": {"passed": 1, "failed": 0, "errored": 0, "skipped": 0}, "log": [], "native": {}, "files": {}}
    lane = type("L", (), {"lane_id": "robot", "engine": "robot"})()

    def read(doc):
        out = tmp_path / f"o{len(list(tmp_path.iterdir()))}"
        out.mkdir()
        (out / "outcome.json").write_text(json.dumps(doc))
        return lane_robot._read_outcome(lane, out, Budget(10_000_000, root=str(tmp_path)))[0]
    assert read(base) is not None
    for edit in ({"counts": {"passed": "many"}}, {"counts": {"surprise": 1}}, {"counts": [1]}, {"exit_code": "0"}, {"exit_code": 100000}, {"native_status": "NATIVE_VERIFIED"}, {"engine_version": 7},
                 {"log": {"a": 1}}, {"files": {"x": "data/1.bin"}}, {"files": {"x": {"data": "data/1.bin"}}}):
        assert read({**base, **edit}) is None, edit
