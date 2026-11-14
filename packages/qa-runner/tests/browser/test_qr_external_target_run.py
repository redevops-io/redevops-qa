# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""P2-1 run path against an external origin, in a real browser: a loopback stand-in for Edge Sentinel in fixture mode (its /health says demo.enabled=true). The run goes through the egress gateway, needs
no fixture app, and ends CORROBORATED (never VERIFIED), with the bundle saying that nothing independent backs it (AC-2, AC-6, AC-7, AC-9, AC-12), refused when the target is not in fixture mode."""
import copy
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
from hostile import CountingListener
from qr_tamper import codes, edit_json, rechain, verify_files_in

ROOT = Path(__file__).resolve().parents[4]
TEMPLATE = ROOT / "packages" / "qa-runner" / "examples" / "edge-sentinel-fixture-plan.json"


class StandIn:
    """The loopback origin: /health (fixture mode or not), a page that tries to reach ``forbidden`` and a redirect to it."""

    def __init__(self, demo=True, forbidden_port=0):
        outer = self
        self.paths = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.paths.append(self.path)
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{forbidden_port}/x")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == "/health":
                    body, kind = json.dumps({"status": "ok", "demo": {"enabled": demo}}).encode(), "application/json"
                else:
                    body, kind = (f"<!doctype html><title>t</title><h1>stand-in</h1><img src='http://127.0.0.1:{forbidden_port}/p.png'>").encode(), "text/html"
                self.send_response(200)
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


def external_plan(origin, path="/health", pattern="/health$"):
    plan = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    plan["target"] = {"kind": "external-origin", "origin": origin, "declared_by": "operator", "credential_refs": [], "mutating": False}
    lane = plan["lanes"][0]
    lane["spec"]["steps"][0]["action"]["value"] = "{origin}" + path
    lane["spec"]["assertions"][0]["predicate"]["expected"] = pattern
    lane["spec"]["assertions"][0]["subject"]["pattern"] = pattern
    lane["requests"] = {"required": ["GET " + path], "allowed": []}
    return plan


@pytest.fixture(autouse=True)
def linux_claim_for_a_developer_machine(monkeypatch):
    """CI is Linux; on a developer's Mac the platform guard (AC-12, tested apart) would refuse every run here."""
    real = plan_mod.v1_scope_problems
    monkeypatch.setattr(plan_mod, "v1_scope_problems", lambda plan, system=None: real(plan, system="linux"))


def rep(summary):
    return json.loads(summary.bundle.files["report.json"])


def test_ac9_a_run_of_the_fixture_mode_target_ends_corroborated_never_verified_and_the_bundle_says_why(up, tmp_path):
    with StandIn() as es:
        frozen = freeze_plan(up, external_plan(es.origin))
        s = run_plan(up, frozen, RunOptions())
        r = rep(s)
        assert (s.outcome, s.exit_code, s.lanes) == ("CORROBORATED", K.EXIT_CORROBORATED, (("browser", "NATIVE_PASS"),)), r["accounting"]
        assert r["verdict"]["reason_code"] == "ALL_ASSERTIONS_CORROBORATED" and r["verification_ceiling"] == "CORROBORATED"
        assert [x["id"] for x in r["limitations"]].count(K.NO_RESTATEMENT_ID) == 1 and "never VERIFIED" in next(x["text"] for x in r["limitations"] if x["id"] == K.NO_RESTATEMENT_ID)
        ext = r["extensions"]
        assert ext["target"] == "external-origin" and ext["target_origin"] == es.origin and ext["target_fixture_mode_confirmed"] == "demo.enabled=true" and ext["target_declared_by"] == "operator"
        assert "Linux x86_64" in ext["platform_claim"]
        assert "logs/reference-check.json" not in s.bundle.files, "an external target has no reference check"
        assert es.paths.count("/health") >= 2, "the runner's fixture-mode check and the browser's navigation"
        v = verify_files_in(tmp_path, s.bundle.files, plan_digest=frozen.plan_digest)
        assert v.accepted and v.exit_code == K.EXIT_CORROBORATED and codes(v) == []


def test_ac9_the_ceiling_cannot_be_dropped_or_relabelled_by_someone_who_rechains_the_bundle(up, tmp_path):
    with StandIn() as es:
        s = run_plan(up, freeze_plan(up, external_plan(es.origin)), RunOptions())
    files = dict(s.bundle.files)

    def upgrade(doc):
        doc.pop("verification_ceiling")
        doc["verdict"].update(outcome="VERIFIED", reason_code="ALL_ASSERTIONS_VERIFIED")
    forged = rechain(edit_json(files, "report.json", upgrade))
    v = verify_files_in(tmp_path, forged)
    assert not v.accepted and "CEILING_MISMATCH" in codes(v)
    # the strongest forger also has to remove the statement that nothing independent backs the run
    def without_statement(doc):
        upgrade(doc)
        doc["limitations"] = [x for x in doc["limitations"] if x["id"] != K.NO_RESTATEMENT_ID]
    v = verify_files_in(tmp_path, rechain(edit_json(files, "report.json", without_statement)), name="c.tar")
    assert not v.accepted and {"CEILING_MISMATCH", "EGRESS_STATEMENT_MISSING"} & set(codes(v))


def test_a_target_that_is_not_in_fixture_mode_is_refused_before_a_lane_starts(up, tmp_path, capsys):
    with StandIn(demo=False) as es:
        path = tmp_path / "p.json"
        path.write_text(json.dumps(external_plan(es.origin)))
        assert cli_main(["run", str(path), "--out", str(tmp_path / "ev")]) == K.EXIT_ENVIRONMENT
        err = capsys.readouterr().err
        assert "NOT_FIXTURE_MODE" in err and "demo.enabled=true" in err
        assert es.paths == ["/health"], "only the fixture-mode check reached the target"
        assert not (tmp_path / "ev").exists() or not list((tmp_path / "ev").iterdir())


def test_ac6_a_page_of_the_target_that_reaches_for_another_loopback_port_is_refused_and_the_refusal_is_in_the_bundle(up, tmp_path):
    with CountingListener() as forbidden, StandIn(forbidden_port=0) as _:
        pass
    with CountingListener() as forbidden:
        with StandIn(forbidden_port=forbidden.port) as es:
            frozen = freeze_plan(up, external_plan(es.origin, "/", "/$"))
            s = run_plan(up, frozen, RunOptions())
            assert forbidden.connections == 0, "the browser reached the forbidden port"
    r = rep(s)
    log = [json.loads(l) for l in s.bundle.files["lanes/browser/gateway-log.jsonl"].decode().splitlines()]
    guard = [json.loads(l) for l in s.bundle.files["lanes/browser/browser-guard-log.jsonl"].decode().splitlines()]
    assert any(e["decision"]["verdict"] == "DENY" and e["decision"]["port"] == forbidden.port for e in guard), "the attempt is not in the bundle"
    assert not [e for e in log if e["decision"]["verdict"] == "ALLOW" and e["decision"]["port"] == forbidden.port]
    assert r["extensions"].get("egress_gate_denied", 0) + r["extensions"].get("egress_gateway_denied", 0) >= 1
    assert s.outcome == "CORROBORATED" and verify_files_in(tmp_path, s.bundle.files).accepted


def test_ac7_a_redirect_from_the_target_to_another_origin_is_not_followed_and_the_attempt_is_recorded(up, tmp_path):
    with CountingListener() as forbidden:
        with StandIn(forbidden_port=forbidden.port) as es:
            s = run_plan(up, freeze_plan(up, external_plan(es.origin, "/redirect", "/redirect$")), RunOptions())
            assert forbidden.connections == 0
    assert s.outcome != "CORROBORATED", "a navigation that was refused cannot corroborate anything"
    log = [json.loads(l) for l in s.bundle.files["lanes/browser/gateway-log.jsonl"].decode().splitlines()] + [json.loads(l) for l in s.bundle.files["lanes/browser/browser-guard-log.jsonl"].decode().splitlines()]
    assert any(e["decision"]["verdict"] == "DENY" and e["decision"]["port"] == forbidden.port for e in log)
