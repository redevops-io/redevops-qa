# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Both real engines in ONE orchestrated run, serially, under one run id, with one frozen plan: the product's end-to-end path. Every result below comes from the real
Chromium and the real Robot Framework 7.5 against the real fixture app (Linux x86_64 in CI; macOS arm64 when I ran it locally, which is development evidence only)."""
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from qa_evidence.verify import verify_files
from qa_runner import constants as K, suites
from qa_runner.golden import demo_plan
from qa_runner.orchestrate import RunOptions, run_plan
from qa_runner.plan import freeze_plan
from qa_runner.procs import child_env
from qr_support import alive, descendants, process_table, reap, wait_gone

pytestmark = pytest.mark.e2e
HERE = Path(__file__).resolve().parent


@pytest.fixture(scope="module")
def frozen(up):
    return freeze_plan(up, demo_plan())


def run(up, frozen, defect="none", **kw):
    return run_plan(up, frozen, RunOptions(defect=defect, **kw))


def rep(s):
    return json.loads(s.bundle.files["report.json"])


def states(s):
    return {x["assertion_id"]: x["verdict"]["state"] for x in rep(s)["accounting"]["results"]}


def test_clean_target_both_lanes_pass_natively_and_all_assertions_are_verified(up, frozen):
    s = run(up, frozen, "none")
    r = rep(s)
    assert (s.outcome, s.exit_code, s.lanes) == ("VERIFIED", 0, (("browser", "NATIVE_PASS"), ("robot", "NATIVE_PASS"))), r["accounting"]
    assert states(s) == {"A-NOTIF-ON": "VERIFIED", "A-SAVED": "VERIFIED", "A-URL": "VERIFIED", "A-ORDER-RULE": "VERIFIED"}
    assert [(l["lane_id"], l["run_id"], l["engine"]["name"]) for l in r["lanes"]] == [("browser", f"{s.run_id}.browser", "playwright-chromium"), ("robot", f"{s.run_id}.robot", "robot-framework")]
    assert verify_files(s.bundle.files, plan_digest=frozen.plan_digest).ok


def test_discount_defect_the_robot_lane_assertion_fails_and_the_browser_lane_still_verifies(up, frozen):
    s = run(up, frozen, "discount")
    assert (s.outcome, s.exit_code, s.lanes) == ("FAILED", 1, (("browser", "NATIVE_PASS"), ("robot", "NATIVE_FAIL")))
    assert states(s) == {"A-NOTIF-ON": "VERIFIED", "A-SAVED": "VERIFIED", "A-URL": "VERIFIED", "A-ORDER-RULE": "FAILED"}
    assert verify_files(s.bundle.files, plan_digest=frozen.plan_digest).ok


def test_settings_defect_the_playwright_assertion_fails_and_the_robot_lane_still_verifies(up, frozen):
    s = run(up, frozen, "settings")
    assert (s.outcome, s.exit_code, s.lanes) == ("FAILED", 1, (("browser", "NATIVE_FAIL"), ("robot", "NATIVE_PASS")))
    assert states(s) == {"A-NOTIF-ON": "FAILED", "A-SAVED": "VERIFIED", "A-URL": "VERIFIED", "A-ORDER-RULE": "VERIFIED"}


def test_every_frozen_assertion_is_accounted_exactly_once_across_both_lanes_in_every_mode(up, frozen):
    for defect in K.DEFECTS:
        r = rep(run(up, frozen, defect))
        ids = [x["assertion_id"] for x in r["accounting"]["results"]]
        assert sorted(ids) == sorted(a["assertion_id"] for a in r["assertion_set"]["assertions"]) and len(set(ids)) == 4 == r["accounting"]["frozen"]
        assert r["accounting"]["unaccounted"] == 0


def test_the_bundle_of_the_two_engine_run_holds_each_engines_own_report_and_the_target_log(up, frozen):
    s = run(up, frozen, "none")
    names = set(s.bundle.files)
    assert {"lanes/browser/native/run-record.json", "lanes/robot/native/output.xml", "lanes/browser/observations.json", "lanes/robot/observations.json",
            "lanes/browser/gateway-log.jsonl", "lanes/robot/egress-profile.json", "logs/target-requests.jsonl", "plan.lock.json"} <= names


def test_partial_success_the_robot_lane_times_out_and_the_browser_lane_result_is_kept(up, tmp_path, monkeypatch):
    copy = tmp_path / "suite"
    shutil.copytree(suites.SUITE_DIR, copy)
    rb = copy / "order_discount.robot"
    rb.write_text(rb.read_text().replace("Order Discount Rule\n", "Order Discount Rule\n    Sleep    600\n", 1))
    monkeypatch.setattr(suites, "SUITE_DIR", copy)
    plan = demo_plan()
    plan["lanes"][1]["deadline_s"] = 3
    s = run(up, freeze_plan(up, plan))
    assert s.lanes == (("browser", "NATIVE_PASS"), ("robot", "NATIVE_TIMEOUT")) and (s.outcome, s.exit_code) == ("INCONCLUSIVE", K.EXIT_ENVIRONMENT)
    assert states(s) == {"A-NOTIF-ON": "VERIFIED", "A-SAVED": "VERIFIED", "A-URL": "VERIFIED", "A-ORDER-RULE": "INCONCLUSIVE"}


def test_a_failed_assertion_in_one_lane_outranks_a_timeout_in_the_other(up, tmp_path, monkeypatch):
    copy = tmp_path / "suite"
    shutil.copytree(suites.SUITE_DIR, copy)
    rb = copy / "order_discount.robot"
    rb.write_text(rb.read_text().replace("Order Discount Rule\n", "Order Discount Rule\n    Sleep    600\n", 1))
    monkeypatch.setattr(suites, "SUITE_DIR", copy)
    plan = demo_plan()
    plan["lanes"][1]["deadline_s"] = 3
    s = run(up, freeze_plan(up, plan), "settings")
    assert (s.outcome, s.exit_code) == ("FAILED", K.EXIT_FAILED) and dict(s.lanes) == {"browser": "NATIVE_FAIL", "robot": "NATIVE_TIMEOUT"}     # a demonstrated failure is reported as one; the timeout stays visible per lane
    assert states(s)["A-NOTIF-ON"] == "FAILED" and states(s)["A-ORDER-RULE"] == "INCONCLUSIVE"


def test_the_browser_lane_times_out_and_the_robot_lane_result_is_kept(up):
    plan = demo_plan()
    plan["lanes"][0]["deadline_s"] = 1
    s = run(up, freeze_plan(up, plan))
    assert s.lanes == (("browser", "NATIVE_TIMEOUT"), ("robot", "NATIVE_PASS")) and s.outcome == "INCONCLUSIVE" and s.exit_code == K.EXIT_ENVIRONMENT
    assert states(s)["A-ORDER-RULE"] == "VERIFIED" and states(s)["A-URL"] == "INCONCLUSIVE"


def spawn_cli(tmp_path, *argv):
    env = child_env(str(tmp_path))
    return subprocess.Popen([sys.executable, "-s", "-m", "qa_runner", *argv], env=env, cwd=str(tmp_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)


def wait_for(predicate, timeout=60.0, step=0.1):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        got = predicate()
        if got:
            return got
        time.sleep(step)
    return None


def test_cancelling_the_command_mid_run_ends_every_process_it_started_and_still_writes_an_inconclusive_bundle(tmp_path):
    proc = spawn_cli(tmp_path, "demo", "--out", str(tmp_path / "out"))
    seen = set()
    try:
        _cancel_body(tmp_path, proc, seen)
    finally:
        reap(proc, seen)          # a failed assertion below leaves nothing running


def _cancel_body(tmp_path, proc, seen):
    def browser_running():
        table = process_table()
        kids = descendants(proc.pid, table)
        seen.update(kids)
        return any("qa_runner.lane_browser" in table[k][2] for k in kids if k in table)
    assert wait_for(browser_running), "the browser lane never started"
    time.sleep(0.5)
    seen.update(descendants(proc.pid))
    proc.send_signal(signal.SIGTERM)
    out, err = proc.communicate(timeout=60)
    assert proc.returncode == K.EXIT_ENVIRONMENT, out + err
    assert "[cancelled]" in out and ": INCONCLUSIVE (" in out
    assert seen and all(wait_gone(pid, 15) for pid in seen), [pid for pid in seen if alive(pid)]
    (bundle,) = list((tmp_path / "out").iterdir())
    report = json.loads((bundle / "report.json").read_text())
    assert report["verdict"]["outcome"] == "INCONCLUSIVE" and {l["lane_id"]: l["native"]["status"] for l in report["lanes"]}["robot"] == "NATIVE_SKIPPED"
    assert subprocess.run([sys.executable, "-s", "-m", "qa_evidence", "verify", str(bundle)], env=child_env(str(tmp_path)), capture_output=True, timeout=60).returncode == 0


@pytest.mark.parametrize("which,marker,engine", [("robot", "qa_runner.lane_robot", "robot"), ("browser", "slow_browser_lane.py", "chrom")])
def test_killing_the_parent_without_warning_leaves_no_process_behind(tmp_path, which, marker, engine):
    """SIGKILL gives the parent no chance to clean up: the lane child, the engine (the Robot process or the browser) and the target must end by themselves."""
    env = child_env(str(tmp_path))
    proc = subprocess.Popen([sys.executable, "-s", str(HERE / "slow_parent.py"), which], env=env, cwd=str(tmp_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            start_new_session=True)
    seen = set()
    try:
        _kill_body(proc, seen, which, marker, engine)
    finally:
        reap(proc, seen)


def _kill_body(proc, seen, which, marker, engine):
    def engine_running():
        table = process_table()
        kids = descendants(proc.pid, table)
        seen.update(kids)
        lane = any(marker in table[k][2] for k in kids if k in table)
        return lane and any(engine in table[k][2].lower() and marker not in table[k][2] for k in kids if k in table)
    assert wait_for(engine_running, 90), f"the {which} lane's engine never started"
    time.sleep(1.0)
    seen.update(descendants(proc.pid))
    assert len(seen) >= 3, seen
    proc.kill()
    proc.communicate(timeout=30)
    leftover = [pid for pid in seen if not wait_gone(pid, 25)]
    assert leftover == [], f"processes survived the parent: {leftover}"


def test_the_command_line_demo_end_to_end_in_a_scrubbed_environment(tmp_path):
    env = child_env(str(tmp_path))
    for defect, code, outcome in (("none", 0, "VERIFIED"), ("discount", 1, "FAILED"), ("settings", 1, "FAILED")):
        out = tmp_path / f"out-{defect}"
        done = subprocess.run([sys.executable, "-s", "-m", "qa_runner", "demo", "--out", str(out), "--defect", defect], env=env, cwd=str(tmp_path), capture_output=True, text=True, timeout=240)
        assert done.returncode == code and f": {outcome} (" in done.stdout, done.stdout + done.stderr
        assert "VERDICT AS RECORDED" in done.stdout and "INDEPENDENT VERDICT" not in done.stdout and "not recomputed by any command" in done.stdout and "lane browser:" in done.stdout and "lane robot:" in done.stdout
        (bundle,) = list(out.iterdir())
        assert subprocess.run([sys.executable, "-s", "-m", "qa_evidence", "verify", str(bundle)], env=env, capture_output=True, timeout=60).returncode == 0
        report = subprocess.run([sys.executable, "-s", "-m", "qa_runner", "report", str(bundle)], env=env, capture_output=True, text=True, timeout=60)
        assert report.returncode == 0 and "NATIVE ENGINE RESULTS" in report.stdout


def test_freeze_then_run_the_lock_end_to_end(tmp_path):
    env = child_env(str(tmp_path))
    lock = tmp_path / "plan.lock.json"
    plan = HERE.parents[1] / "examples" / "demo-plan.json"
    frozen = subprocess.run([sys.executable, "-s", "-m", "qa_runner", "freeze", str(plan), "--out", str(lock)], env=env, cwd=str(tmp_path), capture_output=True, text=True, timeout=60)
    assert frozen.returncode == 0 and "plan digest: sha256:" in frozen.stdout
    digest = [l for l in frozen.stdout.splitlines() if "plan digest:" in l][0].split("plan digest: ")[1].strip()
    done = subprocess.run([sys.executable, "-s", "-m", "qa_runner", "run", str(lock), "--out", str(tmp_path / "o")], env=env, cwd=str(tmp_path), capture_output=True, text=True, timeout=240)
    assert done.returncode == 0 and f"plan digest: {digest}" in done.stdout and "frozen by this run" not in done.stderr
    (bundle,) = list((tmp_path / "o").iterdir())
    verify = subprocess.run([sys.executable, "-s", "-m", "qa_evidence", "verify", str(bundle), "--plan-digest", digest], env=env, capture_output=True, text=True, timeout=60)
    assert verify.returncode == 0 and "matches the supplied value" in verify.stdout
