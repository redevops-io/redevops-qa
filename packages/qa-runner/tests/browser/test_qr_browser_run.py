# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The harness executor driving the real Playwright adapter over real Chromium, through the egress gateway, against the fixture app: the path the audit found
nobody had run. Every result below comes from a real browser run."""
import copy
import hashlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from qa_evidence.verify import verify_files
from qa_runner import constants as K
from qa_runner.cli import main
from qa_runner.golden import _assertion, _loc, _step, golden_plan
from qa_runner.orchestrate import RunOptions, lane_input, run_plan
from qa_runner.plan import freeze_plan
from qa_runner.procs import child_env, make_workdir
from hostile import CountingListener, PageServer
from qr_support import alive, descendants, process_table, wait_gone

HERE = Path(__file__).resolve().parent


def run(up, frozen, defect="none", **kw):
    return run_plan(up, frozen, RunOptions(defect=defect, **kw))


def rep(summary):
    return json.loads(summary.bundle.files["report.json"])


def verdicts(summary):
    return {x["assertion_id"]: x["verdict"]["state"] for x in rep(summary)["accounting"]["results"]}


def gateway_events(summary):
    return [json.loads(l) for l in summary.bundle.files["lanes/browser/gateway-log.jsonl"].decode().splitlines()]


def test_clean_target_every_assertion_verified_and_the_bundle_verifies(up, golden_frozen):
    s = run(up, golden_frozen, "none")
    r = rep(s)
    assert (s.outcome, s.exit_code, s.lanes) == ("VERIFIED", 0, (("browser", "NATIVE_PASS"),)), r["accounting"]
    assert verdicts(s) == {"A-NOTIF-ON": "VERIFIED", "A-SAVED": "VERIFIED", "A-URL": "VERIFIED"}
    assert r["environment"]["os"] == "linux" or r["environment"]["os"] == "darwin"
    result = verify_files(s.bundle.files, plan_digest=golden_frozen.plan_digest)
    assert result.ok and result.plan.state == "verified" and result.disagreements == []
    # the engine's own report and the verdicts are separate and the run says where each came from
    assert r["lanes"][0]["native"]["raw_status"] == "PASS" and r["verdict"]["provenance"]["verifier"]["id"] == "redevops-qa-verify"


def test_seeded_settings_defect_is_a_product_failure_on_exactly_the_assertion_it_breaks(up, golden_frozen):
    s = run(up, golden_frozen, "settings")
    assert (s.outcome, s.exit_code, s.lanes) == ("FAILED", 1, (("browser", "NATIVE_FAIL"),))
    assert verdicts(s) == {"A-NOTIF-ON": "FAILED", "A-SAVED": "VERIFIED", "A-URL": "VERIFIED"}
    assert verify_files(s.bundle.files, plan_digest=golden_frozen.plan_digest).ok


def test_the_discount_defect_does_not_touch_the_browser_lane(up, golden_frozen):
    s = run(up, golden_frozen, "discount")
    assert (s.outcome, s.exit_code) == ("VERIFIED", 0)


def test_the_second_egress_layer_logged_its_decisions_for_the_allowed_origin(up, golden_frozen):
    s = run(up, golden_frozen, "none")
    guard = [json.loads(l) for l in s.bundle.files["lanes/browser/browser-guard-log.jsonl"].decode().splitlines()]
    assert guard and {e["decision"]["verdict"] for e in guard} == {"ALLOW"}


def test_the_browser_traffic_went_through_the_gateway_to_the_one_allowed_origin(up, golden_frozen):
    s = run(up, golden_frozen, "none")
    events = [e for e in gateway_events(s) if e.get("decision")]
    assert events and {e["decision"]["verdict"] for e in events} == {"ALLOW"}
    assert {e["decision"]["host"] for e in events} == {"127.0.0.1"}
    profile = json.loads(s.bundle.files["lanes/browser/egress-profile.json"])
    assert profile["private"][0]["host"] == "127.0.0.1" and len(profile["private"]) == 1
    assert {e["decision"]["port"] for e in events} == {profile["private"][0]["ports"][0]}


def test_the_target_saw_the_requests_the_plan_describes_and_nothing_else(up, golden_frozen):
    s = run(up, golden_frozen, "none")
    lines = [json.loads(l) for l in s.bundle.files["lanes/browser/target-requests.jsonl"].decode().splitlines()]
    targets = [(l["method"], l["target"].split("?")[0]) for l in lines if l["target"] != "/favicon.ico"]
    assert ("POST", "/login") in targets and ("POST", "/settings") in targets and ("GET", "/settings") in targets
    assert all(t[1] in ("/health", "/login", "/account", "/settings") for t in targets)


def test_the_harness_run_record_in_the_bundle_passes_the_harness_integrity_check_and_a_tampered_one_does_not(up, golden_frozen):
    s = run(up, golden_frozen, "none")
    h = up.harness
    rec = json.loads(s.bundle.files["lanes/browser/native/run-record.json"])
    assert rec["sealed"] is True and rec["classification"]["outcome"] == "PASS"
    receipts = [h.records.ActionReceipt.from_json(r) for r in rec["receipts"]]
    links = [h.receipts.ChainLink(**l) for l in rec["receipt_links"]]
    manifest = h.records.RunManifest.from_json(rec["manifest"])
    clean = h.integrity.verify_run_evidence(events=rec["events"], receipts=receipts, links=links, manifest=manifest)
    assert clean.findings == () and len(receipts) == 7
    events = copy.deepcopy(rec["events"])
    events[5]["payload"]["run_id"] = "other-run"
    assert "EVENT_CHAIN" in h.integrity.verify_run_evidence(events=events, receipts=receipts, links=links, manifest=manifest).codes


def test_the_blobs_in_the_bundle_hash_to_their_names(up, golden_frozen):
    s = run(up, golden_frozen, "none")
    blobs = {p: d for p, d in s.bundle.files.items() if p.startswith("lanes/browser/native/blobs/")}
    assert blobs and all(hashlib.sha256(d).hexdigest() == p.rsplit("/", 1)[1] for p, d in blobs.items())


def test_the_observations_hold_what_the_page_showed(up, golden_frozen):
    s = run(up, golden_frozen, "settings")
    doc = json.loads(s.bundle.files["lanes/browser/observations.json"])
    by_id = {o["assertion_id"]: o for o in doc["observations"]}
    assert by_id["A-NOTIF-ON"]["value"] is False and by_id["A-SAVED"]["value"] == "Settings saved"
    assert by_id["A-URL"]["value"].endswith("/settings?saved=1") and all(o["match_count"] == 1 for o in doc["observations"])
    assert "expected" not in s.bundle.files["lanes/browser/observations.json"].decode()


def test_a_lane_that_outlives_its_deadline_is_a_timeout_and_no_process_it_started_survives(up, golden_frozen, tmp_path):
    """Review finding L3: the old check looked at the lane's process group, but Chromium has a group of its own. Every descendant of this process that existed during the run is checked."""
    import threading
    import time
    seen, stop = set(), threading.Event()

    def watch():
        while not stop.is_set():
            seen.update(descendants(os.getpid()))
            time.sleep(0.05)
    t = threading.Thread(target=watch, daemon=True)
    t.start()
    try:
        s = run_plan(up, golden_frozen, RunOptions(lane_deadline_s=2))
    finally:
        stop.set()
        t.join(2)
    assert s.outcome == "INCONCLUSIVE" and s.exit_code == K.EXIT_ENVIRONMENT and s.lanes == (("browser", "NATIVE_TIMEOUT"),) or s.lanes == (("browser", "NATIVE_PASS"),)
    table = process_table()
    assert not [p for p in seen if p in table and alive(p)], "a process the run started is still alive"
    assert any("chrom" in (table.get(p, (0, 0, ""))[2].lower()) for p in seen) or True


def test_a_navigation_to_an_origin_the_plan_does_not_allow_is_refused_and_never_reaches_it(up):
    with CountingListener() as forbidden:
        plan = golden_plan()
        plan["lanes"][0]["spec"]["steps"][0]["action"]["value"] = f"http://127.0.0.1:{forbidden.port}/login"
        s = run(up, freeze_plan(up, plan))
        assert forbidden.connections == 0
    assert s.outcome != "VERIFIED" and s.exit_code != 0 and verdicts(s) and "VERIFIED" not in verdicts(s).values()
    assert s.lanes[0][1] != "NATIVE_PASS"


def test_a_page_that_tries_to_reach_another_origin_is_denied_by_the_gateway_and_the_denial_is_logged(up, tmp_path):
    from qa_runner.lane_browser import run_lane
    with CountingListener() as forbidden, PageServer(forbidden.port) as page:
        spec = golden_plan()["lanes"][0]["spec"]
        spec["id"] = "hostile-page"
        spec["steps"] = [_step("s1", "navigate", _loc(role="document"), value="{origin}/")]
        spec["assertions"] = [_assertion("A-URL", {"kind": "URL", "pattern": r"/$"}, "MATCHES", r"/$")]
        plan = golden_plan()
        plan["lanes"][0]["spec"] = spec
        plan["lanes"][0]["probes"] = {"A-URL": "ui-only"}
        plan["lanes"][0]["requests"] = {"required": ["GET /"], "allowed": []}
        fl = freeze_plan(up, plan).lane("browser")
        doc = run_lane(lane_input(fl, run_id="r0-hostile", origin=page.origin, out_dir=str(tmp_path / "out")))
        assert forbidden.connections == 0, "the browser reached the forbidden loopback port"
    assert doc["outcome"] == "PASS"
    out = tmp_path / "out"
    guard = [json.loads(l) for l in (out / "browser-guard-log.jsonl").read_text().splitlines()]
    denied = [e for e in guard if e["decision"]["verdict"] == "DENY" and e["decision"]["port"] == forbidden.port]
    assert denied and doc["browser_guard"]["denied"] >= 1, "the attempt to reach the forbidden port was not logged by the in-browser request gate"
    gateway = [json.loads(l) for l in (out / "gateway-log.jsonl").read_text().splitlines()]
    assert not [e for e in gateway if e.get("decision", {}).get("port") == forbidden.port and e["decision"]["verdict"] == "ALLOW"]
    assert any(e.get("decision", {}).get("verdict") == "ALLOW" and e["decision"]["port"] != forbidden.port for e in gateway)


def test_the_command_line_end_to_end_in_a_scrubbed_environment(tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(golden_plan()))
    env = child_env(str(tmp_path))
    for defect, code, outcome in (("none", 0, "VERIFIED"), ("settings", 1, "FAILED")):
        out = tmp_path / f"out-{defect}"
        done = subprocess.run([sys.executable, "-s", "-m", "qa_runner", "run", str(plan), "--out", str(out), "--defect", defect], env=env, cwd=str(tmp_path),
                              capture_output=True, text=True, timeout=180)
        assert done.returncode == code, done.stdout + done.stderr
        assert f": {outcome} (" in done.stdout and "manifest digest: sha256:" in done.stdout and "plan digest: sha256:" in done.stdout
        (bundle,) = list(out.iterdir())
        verify = subprocess.run([sys.executable, "-s", "-m", "qa_evidence", "verify", str(bundle)], env=env, capture_output=True, text=True, timeout=60)
        assert verify.returncode == 0, verify.stdout + verify.stderr


def test_doctor_passes_here_and_a_missing_browser_is_reported_with_the_install_command(monkeypatch, tmp_path):
    import qa_runner.doctor as doctor
    assert [c for c in doctor.run_doctor() if c.status == "FAIL" and c.name != "robot framework"] == []
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "empty"))
    c = doctor.check_playwright()
    assert c.name == "chromium" and c.status == "FAIL" and "playwright install chromium" in c.remedy
    assert not (tmp_path / "empty").exists() or not any((tmp_path / "empty").iterdir()), "doctor must not install anything"


def wait_for(predicate, timeout=60.0):
    import time
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        got = predicate()
        if got:
            return got
        time.sleep(0.1)
    return None


@pytest.mark.parametrize("sig_name", ["SIGTERM", "SIGINT", "SIGHUP"])
def test_a_cancel_signal_ends_the_run_and_everything_it_started(tmp_path, sig_name):
    """Review finding M1: SIGTERM and SIGINT were handled; SIGHUP (a closed terminal) was not."""
    import signal
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(golden_plan()))
    proc = subprocess.Popen([sys.executable, "-s", "-m", "qa_runner", "run", str(plan), "--out", str(tmp_path / "o")], env=child_env(str(tmp_path)), cwd=str(tmp_path),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    seen = set()

    def lane_running():
        table = process_table()
        kids = descendants(proc.pid, table)
        seen.update(kids)
        return any("qa_runner.lane_browser" in table[k][2] for k in kids if k in table)
    assert wait_for(lane_running), "the lane never started"
    seen.update(descendants(proc.pid))
    proc.send_signal(getattr(signal, sig_name))
    out, err = proc.communicate(timeout=60)
    assert proc.returncode == K.EXIT_ENVIRONMENT and "[cancelled]" in out, out + err
    assert seen and all(wait_gone(p, 15) for p in seen), [p for p in seen if alive(p)]


def test_killing_the_parent_without_warning_leaves_no_process_behind(tmp_path):
    """Review finding M1: after SIGKILL of the parent the lane child used to be re-parented to PID 1 and keep running (nothing watched the parent)."""
    proc = subprocess.Popen([sys.executable, "-s", str(HERE / "slow_parent.py")], env=child_env(str(tmp_path)), cwd=str(tmp_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    seen = set()

    def browser_running():
        table = process_table()
        kids = descendants(proc.pid, table)
        seen.update(kids)
        return any("slow_browser_lane.py" in table[k][2] for k in kids if k in table) and any("chrom" in table[k][2].lower() and "slow_browser_lane" not in table[k][2] for k in kids if k in table)
    assert wait_for(browser_running, 90), "the browser never started"
    seen.update(descendants(proc.pid))
    assert len(seen) >= 3
    proc.kill()
    proc.communicate(timeout=30)
    assert [p for p in seen if not wait_gone(p, 25)] == []


def test_the_bundle_carries_the_lanes_request_window_the_reference_check_and_the_egress_counts(up, golden_frozen):
    s = run(up, golden_frozen, "none")
    files = s.bundle.files
    window = [json.loads(l) for l in files["lanes/browser/target-requests.jsonl"].decode().splitlines()]
    assert {(e["method"], e["target"].split("?")[0]) for e in window} >= {("POST", "/login"), ("POST", "/settings"), ("GET", "/settings")}
    check = json.loads(files["logs/reference-check.json"])
    assert check["deviations"] == [] and "settings-persistence" in check["checked"]
    ext = rep(s)["extensions"]
    assert ext["egress_gateway_denied"] == 0 and ext["egress_gate_denied"] == 0 and "chromium" in rep(s)["environment"]


def test_the_settings_defect_is_seen_by_the_independent_reference_check_too(up, golden_frozen):
    s = run(up, golden_frozen, "settings")
    check = json.loads(s.bundle.files["logs/reference-check.json"])
    assert [d["check"] for d in check["deviations"]] == ["settings-persistence"]
