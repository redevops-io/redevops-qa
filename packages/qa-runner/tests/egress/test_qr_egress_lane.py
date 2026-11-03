# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Egress in the ORCHESTRATED browser lane: the hostile page against the lane as the product runs it (both egress layers on), and the lane when its gateway is lost in the middle of a run."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from qa_evidence.canon import dumps_canonical
from qa_runner import constants as K
from qa_runner.golden import _assertion, _loc, _step, golden_plan
from qa_runner.orchestrate import RunOptions, lane_input, run_plan
from qa_runner.plan import freeze_plan
from qa_runner.procs import child_env
from hostile_world import PAGE, PAGE_WITHOUT_WEBSOCKET, HostileWorld

HERE = Path(__file__).resolve().parent
SHIM = str(HERE / "gateway_lost_lane.py")


def hostile_lane(up, tmp_path, page):
    """The orchestrated browser lane (the real lane code: the gateway, the launch configuration and the in-browser request gate) given a plan whose one step opens ``page`` on the allowed origin."""
    with HostileWorld(page) as world:
        spec = golden_plan()["lanes"][0]["spec"]
        spec["id"] = "hostile-page"
        spec["steps"] = [_step("s1", "navigate", _loc(role="document"), value="{origin}/page")]
        spec["assertions"] = [_assertion("A-URL", {"kind": "URL", "pattern": r"/page$"}, "MATCHES", r"/page$")]
        plan = golden_plan()
        plan["lanes"][0]["spec"] = spec
        plan["lanes"][0]["probes"] = {"A-URL": "ui-only"}
        plan["lanes"][0]["requests"] = {"required": ["GET /page"], "allowed": []}
        fl = freeze_plan(up, plan).lane("browser")
        out = tmp_path / "out"
        inp = tmp_path / "input.json"
        inp.write_bytes(dumps_canonical(lane_input(fl, run_id="r0-hostile", origin=world.origin, out_dir=str(out))))
        home = tmp_path / "home"
        home.mkdir()
        # a child process, as the orchestrator starts it: a lane whose navigation times out leaves its browser worker behind in a process that goes on to start another browser
        done = subprocess.run([sys.executable, "-s", "-X", "faulthandler", "-m", "qa_runner.lane_browser", str(inp)], env=child_env(str(home)), cwd=str(tmp_path), capture_output=True, text=True, timeout=180)
        assert done.returncode in (0, 3), done.stderr[-800:]
        doc = json.loads((out / "lane-result.json").read_text())
        return doc, world.snapshot(), world.a_port, world.b_port, out


def test_the_orchestrated_lane_given_the_hostile_page_loads_it_and_the_hostile_origin_sees_nothing(up, tmp_path):
    doc, seen, a, b, out = hostile_lane(up, tmp_path, PAGE_WITHOUT_WEBSOCKET)
    assert doc["outcome"] == "PASS" and doc["sealed"] is True, {k: doc[k] for k in ("outcome", "reason", "states", "exit_code")}
    assert seen["b_hits"] == frozenset(), sorted(seen["b_hits"])
    assert seen["udp"] == 0
    assert {"/page", "/allowed-self"} <= seen["a_seen"], sorted(seen["a_seen"])           # the page loaded and ran: the silence is not a browser that did nothing
    gateway = [json.loads(l) for l in (out / "gateway-log.jsonl").read_text().splitlines()]
    allowed = {(e["decision"]["host"], e["decision"]["port"]) for e in gateway if e.get("decision", {}).get("verdict") == "ALLOW"}
    assert allowed == {("127.0.0.1", a)}, allowed
    guard = [json.loads(l) for l in (out / "browser-guard-log.jsonl").read_text().splitlines()]
    denied = [e for e in guard if e["decision"]["verdict"] == "DENY" and e["decision"]["port"] == b]
    assert denied and doc["browser_guard"]["denied"] >= 1, "the in-browser request gate did not log the attempts on the hostile origin"


def test_the_orchestrated_lane_given_the_full_hostile_page_including_the_websocket_still_sends_the_hostile_origin_nothing(up, tmp_path):
    """The WebSocket attempt stalls the page's load, so the lane's outcome is not asserted here (it is INCONCLUSIVE where this was written, never a pass of an unprotected run); what is asserted is the point:
    the hostile TCP origin and the UDP listener see nothing."""
    doc, seen, a, b, out = hostile_lane(up, tmp_path, PAGE)
    assert seen["b_hits"] == frozenset(), sorted(seen["b_hits"])
    assert seen["udp"] == 0
    assert doc["status"] == "COMPLETED"


def lane_command(mode):
    return lambda lane, input_path: [sys.executable, "-s", SHIM, mode, input_path]


def requests_of(summary):
    lines = summary.bundle.files["lanes/browser/target-requests.jsonl"].decode().splitlines()
    return [(l["method"], l["target"].split("?")[0]) for l in map(json.loads, lines) if l["target"] != "/favicon.ico"]


def test_the_control_with_the_gateway_left_alone_runs_the_whole_plan_through_it(up, golden_frozen):
    s = run_plan(up, golden_frozen, RunOptions(lane_command=lane_command("keep"), lane_deadline_s=90, run_id="r0-keep"))
    assert s.lanes == (("browser", "NATIVE_PASS"),), s.lanes
    assert ("POST", "/login") in requests_of(s) and ("POST", "/settings") in requests_of(s)


def test_the_gateway_killed_after_the_first_page_fails_the_lane_closed_and_the_browser_never_goes_direct(up, golden_frozen):
    s = run_plan(up, golden_frozen, RunOptions(lane_command=lane_command("kill"), lane_deadline_s=90, run_id="r0-lost"))
    report = json.loads(s.bundle.files["report.json"])
    assert (s.outcome, s.exit_code, s.lanes) == ("INCONCLUSIVE", K.EXIT_ENVIRONMENT, (("browser", "NATIVE_ERROR"),)), (s.outcome, s.lanes)
    assert report["accounting"]["verified"] == 0 and report["accounting"]["failed"] == 0 and report["accounting"]["inconclusive"] == 3
    assert "lanes/browser/native/run-record.json" not in s.bundle.files           # the lane did not complete: no run record is offered as evidence
    stderr = s.bundle.files["logs/browser.stderr.txt"].decode("utf-8", "replace")
    assert "GatewayLost" in stderr, stderr[-600:]
    seen = requests_of(s)
    assert ("GET", "/login") in seen, seen                                          # the first page did load, through the gateway, before it was killed
    assert [r for r in seen if r[0] != "GET" or r[1] not in ("/health", "/login")] == [], f"the browser reached the target after its gateway was killed: {seen}"
