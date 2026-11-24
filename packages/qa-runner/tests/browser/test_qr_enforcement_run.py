# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The enforcement journey in a real browser, against a loopback stand-in for a live Edge Sentinel whose enforcement page is on: the run FAILS while the page says the address is not blocked,
ends CORROBORATED (never VERIFIED) once it says blocked, is INDETERMINATE-or-failed and never a pass when the edge could not be read, and is refused when the target did not switch the page on."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from qa_runner import constants as K
from qa_runner import plan as plan_mod
from qa_runner.cli import main as cli_main
from qa_runner.orchestrate import RunOptions, run_plan
from qa_runner.plan import freeze_plan
from qr_tamper import codes, verify_files_in

ROOT = Path(__file__).resolve().parents[4]
SHIPPED = ROOT / "packages" / "qa-runner" / "examples" / "edge-sentinel-enforcement-plan.json"
PAGE = "/enforcement/203.0.113.7"


class LiveStandIn:
    """/health of a live instance with the page on, and the page itself saying ``state`` (changed between runs, as a real ban changes it)."""

    def __init__(self, state="not blocked", probe=True, page_status=200):
        outer = self
        self.state, self.paths = state, []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.paths.append(self.path)
                status = 200
                if self.path == "/health":
                    body, kind = json.dumps({"status": "ok", "demo": {"enabled": False}, "enforcement_probe": {"enabled": probe}}).encode(), "application/json"
                elif self.path == PAGE:
                    status = page_status
                    body = ("<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Edge enforcement</title></head><body><main><h1>Edge enforcement</h1>"
                            f"<p>Address <code>203.0.113.7</code> is <strong data-testid='enforcement-state'>{outer.state}</strong> at the edge.</p></main></body></html>").encode()
                    kind = "text/html"
                else:
                    status, body, kind = 404, b"not found", "text/plain"
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def plan_for(origin):
    doc = json.loads(SHIPPED.read_text(encoding="utf-8"))
    doc["target"]["origin"] = origin
    return doc


@pytest.fixture(autouse=True)
def linux_claim_for_a_developer_machine(monkeypatch):
    real = plan_mod.v1_scope_problems
    monkeypatch.setattr(plan_mod, "v1_scope_problems", lambda plan, system=None: real(plan, system="linux"))


def rep(summary):
    return json.loads(summary.bundle.files["report.json"])


def test_the_same_plan_fails_before_the_ban_and_is_corroborated_after_it(up, tmp_path):
    with LiveStandIn(state="not blocked") as es:
        frozen = freeze_plan(up, plan_for(es.origin))
        before = run_plan(up, frozen, RunOptions())
        assert before.outcome == "FAILED" and before.lanes == (("browser", "NATIVE_FAIL"),), rep(before)["accounting"]
        v = verify_files_in(tmp_path, before.bundle.files, name="before.tar", plan_digest=frozen.plan_digest)
        assert v.accepted and codes(v) == [], "a failed run still leaves evidence that verifies"

        es.state = "blocked"                                      # the remediation happened at the target; the plan and its digest did not change
        after = run_plan(up, frozen, RunOptions())
        r = rep(after)
        assert (after.outcome, after.exit_code, after.lanes) == ("CORROBORATED", K.EXIT_CORROBORATED, (("browser", "NATIVE_PASS"),)), r["accounting"]
        assert r["verification_ceiling"] == "CORROBORATED" and r["verdict"]["reason_code"] == "ALL_ASSERTIONS_CORROBORATED"
        ext = r["extensions"]
        assert ext["target"] == "external-origin" and ext["target_origin"] == es.origin and ext["target_enforcement_probe_confirmed"] == "enforcement_probe.enabled=true"
        assert "target_fixture_mode_confirmed" not in ext, "a live instance is never recorded as fixture mode"
        assert set(es.paths) == {"/health", PAGE}, "the runner's check of /health and the browser's one page: nothing else of the target was asked for"
        v = verify_files_in(tmp_path, after.bundle.files, name="after.tar", plan_digest=frozen.plan_digest)
        assert v.accepted and v.exit_code == K.EXIT_CORROBORATED and codes(v) == []


def test_an_edge_that_could_not_be_read_is_never_a_pass(up):
    with LiveStandIn(state="unknown", page_status=503) as es:
        s = run_plan(up, freeze_plan(up, plan_for(es.origin)), RunOptions())
        assert s.outcome not in ("VERIFIED", "CORROBORATED") and s.exit_code != K.EXIT_CORROBORATED


def test_a_target_that_did_not_switch_the_page_on_is_refused_before_a_lane_starts(up, tmp_path, capsys):
    with LiveStandIn(probe=False) as es:
        path = tmp_path / "plan.json"
        path.write_text(json.dumps(plan_for(es.origin)), encoding="utf-8")
        code = cli_main(["run", str(path), "--out", str(tmp_path / "out")])
        err = capsys.readouterr().err
        assert code == K.EXIT_ENVIRONMENT and "NOT_ENFORCEMENT_PROBE" in err and "enforcement_probe.enabled=true" in err
        assert es.paths == ["/health"], "only the check of /health reached the target"
