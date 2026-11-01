# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The parts of the browser lane that need no browser: the attestations handed to the harness executor, the recording adapter, the egress profile."""
import copy
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from qa_runner.egress import policy_config
from qa_runner.errors import PlanError
from qa_runner.golden import golden_plan
from qa_runner.lane_browser import AppChecks, RecordingAdapter


class Health(BaseHTTPRequestHandler):
    body = b'{"status": "ok"}'
    code = 200

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(self.code)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)


def serve(body=b'{"status": "ok"}', code=200):
    handler = type("H", (Health,), {"body": body, "code": code})
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.mark.parametrize("body,code,expected", [(b'{"status": "ok"}', 200, True), (b'{"status": "down"}', 200, False), (b"not json", 200, False), (b'{"status": "ok"}', 500, False)])
def test_environment_health_is_the_target_s_own_answer(body, code, expected):
    server, origin = serve(body, code)
    try:
        assert AppChecks(origin).environment_healthy("before") is expected
    finally:
        server.shutdown()
        server.server_close()


def test_a_target_that_does_not_answer_is_unhealthy():
    server, origin = serve()
    server.shutdown()
    server.server_close()
    assert AppChecks(origin).environment_healthy("before") is False


def test_preconditions_and_fixtures_nothing_here_can_attest_are_unknown_never_true(up):
    h = up.harness
    spec = h.records.TestSpec.from_json(copy.deepcopy(golden_plan()["lanes"][0]["spec"]))
    checks = AppChecks("http://127.0.0.1:1")
    assert checks.preconditions_met(spec) is True and checks.fixtures_match(spec) is True        # the spec declares none
    doc = copy.deepcopy(golden_plan()["lanes"][0]["spec"])
    doc["preconditions"] = ["a user exists"]
    doc["fixtures"] = [{"id": "seed", "content_hash": "sha256:" + "0" * 64}]
    declared = h.records.TestSpec.from_json(doc)
    assert checks.preconditions_met(declared) is None and checks.fixtures_match(declared) is None


class _Observed:
    def __init__(self, value):
        self.value = value
        self.resolution = type("R", (), {"value": "RESOLVED"})()
        self.match_count = 1
        self.value_digest = None


class _Subject:
    def __init__(self, name):
        self.name = name

    def to_json(self):
        return {"name": self.name}


class _Inner:
    api_version = "qa-adapter/1"

    def __init__(self):
        self.closed = False

    def assert_(self, session, subject):
        return _Observed(subject.name)

    def egress_decisions(self, handle):
        return ("decision",)

    def egress_counts(self, handle):
        return {"allowed": 1}

    def close_session(self, handle):
        self.closed = True
        return "closed"

    def anything(self):
        return "delegated"


def test_the_recording_adapter_delegates_everything_and_keeps_what_assert_returned_in_order():
    inner = _Inner()
    rec = RecordingAdapter(inner)
    assert rec.api_version == "qa-adapter/1" and rec.anything() == "delegated"
    first, second = rec.assert_(None, _Subject("a")), rec.assert_(None, _Subject("b"))
    assert [r["subject"] for r in rec.reads] == [{"name": "a"}, {"name": "b"}] and rec.reads[0]["observed"] is first and rec.reads[1]["observed"] is second


def test_the_recording_adapter_drains_the_guard_decisions_before_the_session_closes():
    inner = _Inner()
    rec = RecordingAdapter(inner)
    assert rec.close_session("h") == "closed" and inner.closed and rec.guard_decisions == ["decision"] and rec.guard_counts == {"allowed": 1}


def test_the_origin_only_profile_allows_exactly_one_loopback_origin():
    cfg = policy_config("origin-only", "http://127.0.0.1:4321")
    assert cfg == {"private": [{"host": "127.0.0.1", "networks": ["127.0.0.1/32"], "schemes": ["http"], "ports": [4321], "label": "target-origin"}]}


@pytest.mark.parametrize("origin", ["https://127.0.0.1:1", "http://localhost:1", "http://127.0.0.1", "http://10.0.0.1:80", "http://example.com:80", "ftp://127.0.0.1:1"])
def test_the_origin_only_profile_refuses_anything_else(origin):
    with pytest.raises(PlanError):
        policy_config("origin-only", origin)


def test_an_unknown_egress_profile_is_refused():
    with pytest.raises(PlanError):
        policy_config("open", "http://127.0.0.1:1")


def test_the_policy_the_profile_builds_is_the_harness_policy_and_allows_only_that_origin(up):
    h = up.harness
    policy = h.egress.EgressPolicy.from_config(policy_config("origin-only", "http://127.0.0.1:4321"))
    assert len(policy.entries) == 1 and policy.entries[0].ports == (4321,) and policy.entries[0].private_ok
    guard = h.egress.EgressGuard(policy, h.egress.NoResolver())
    assert guard.check("http://127.0.0.1:4321/login").verdict.value == "ALLOW"
    assert guard.check("http://127.0.0.1:4322/login").verdict.value == "DENY"
    assert guard.check("http://127.0.0.2:4321/login").verdict.value == "DENY"
    assert guard.check("https://127.0.0.1:4321/login").verdict.value == "DENY"
