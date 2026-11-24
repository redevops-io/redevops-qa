# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The enforcement journey runs against a live Edge Sentinel, so it is held to the one page that instance opened: the shipped plan passes, any plan with its id that asks for something else
is refused before a lane starts, and the target has to say on /health that the page is on (and that it is not a fixture core)."""
import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from qa_runner import plan as plan_mod
from qa_runner.orchestrate import EnvironmentFault, check_enforcement_probe, check_fixture_mode, target_statement

SHIPPED = Path(__file__).resolve().parents[1] / "examples" / "edge-sentinel-enforcement-plan.json"


def shipped(origin="http://127.0.0.1:8203"):
    doc = json.loads(SHIPPED.read_text(encoding="utf-8"))
    doc["target"]["origin"] = origin
    return doc


def problems(doc):
    return [p["code"] for p in plan_mod.v1_scope_problems(doc, system="linux")]


def test_the_shipped_plan_is_in_scope_reads_one_page_and_asserts_the_word_blocked():
    doc = shipped()
    assert doc["plan_id"] == plan_mod.ENFORCEMENT_PLAN_ID and problems(doc) == []
    (lane,) = doc["lanes"]
    assert lane["requests"] == {"allowed": [], "required": ["GET /enforcement/203.0.113.7"]} and doc["target"]["mutating"] is False and doc["target"]["credential_refs"] == []
    (step,) = lane["spec"]["steps"]
    assert step["action"] == {"kind": "navigate", "value": "{origin}/enforcement/203.0.113.7"} and step["side_effect"] == "NONE"
    state = next(a for a in lane["spec"]["assertions"] if a["assertion_id"] == "A-ENFORCEMENT-STATE")
    assert state["subject"]["locator"] == {"frame_path": [], "test_id": "enforcement-state"} and state["predicate"] == {"expected": "blocked", "op": "EQUALS"}
    assert set(lane["probes"].values()) == {"ui-only"}, "nothing independent backs what the page says: the run is capped at CORROBORATED and says so"


def mutate(fn):
    doc = shipped()
    fn(doc["lanes"][0])
    return doc


@pytest.mark.parametrize("change", [
    lambda l: l["requests"].__setitem__("required", ["GET /health"]),
    lambda l: l["requests"].__setitem__("allowed", ["GET /api/activity"]),
    lambda l: l["requests"].__setitem__("required", ["POST /enforcement/203.0.113.7"]),
    lambda l: l["requests"].__setitem__("required", ["GET /enforcement/8.8.8.8"]),
    lambda l: l["requests"].__setitem__("required", ["GET /enforcement/203.0.113.7/../../api/v1/cases"]),
    lambda l: l["requests"].__setitem__("required", []),
    lambda l: l["spec"]["steps"][0]["action"].__setitem__("value", "{origin}/api/activity"),
    lambda l: l["spec"]["steps"][0]["action"].__setitem__("value", "http://127.0.0.1:9/enforcement/203.0.113.7"),
    lambda l: l["spec"]["steps"][0]["action"].__setitem__("kind", "click"),
    lambda l: l["spec"]["steps"].append({"action": {"kind": "fill", "value": "x"}}),
    lambda l: l["spec"].__setitem__("steps", []),
])
def test_a_plan_with_the_enforcement_id_that_asks_for_anything_else_is_out_of_scope(change):
    assert "ENFORCEMENT_PLAN_OUT_OF_SCOPE" in problems(mutate(change))


@pytest.mark.parametrize("address", ["192.0.2.1", "198.51.100.200", "203.0.113.7", "2001:db8::1"])
def test_every_documentation_range_is_in_scope(address):
    def change(l):
        l["requests"]["required"] = [f"GET /enforcement/{address}"]
        l["spec"]["steps"][0]["action"]["value"] = "{origin}/enforcement/" + address
    assert problems(mutate(change)) == []


def test_the_rule_binds_the_enforcement_plan_only_and_the_other_external_rules_still_apply_to_it():
    fixture = json.loads((SHIPPED.parent / "edge-sentinel-fixture-plan.json").read_text(encoding="utf-8"))
    assert problems(fixture) == []
    far = shipped("http://10.0.0.5:8203")
    assert problems(far) == ["TARGET_OUT_OF_SCOPE"]
    assert [p["code"] for p in plan_mod.v1_scope_problems(shipped(), system="darwin")] == ["PLATFORM_UNSUPPORTED"]


class Health:
    def __init__(self, body, status=200):
        outer = self
        self.paths = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.paths.append(self.path)
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def test_a_live_target_with_the_page_on_is_accepted_and_only_health_is_read():
    with Health({"status": "ok", "demo": {"enabled": False}, "enforcement_probe": {"enabled": True}}) as es:
        check_enforcement_probe(es.origin)
        assert es.paths == ["/health"]


@pytest.mark.parametrize("body", [
    {"status": "ok"}, {"enforcement_probe": {"enabled": False}}, {"enforcement_probe": {"enabled": "true"}}, {"enforcement_probe": True}, {"demo": {"enabled": False}},
    {"demo": {"enabled": True}, "enforcement_probe": {"enabled": True}}, [], b"not json",
])
def test_a_target_that_has_not_switched_the_page_on_or_is_a_fixture_core_is_refused(body):
    with Health(body) as es:
        with pytest.raises(EnvironmentFault) as e:
            check_enforcement_probe(es.origin)
        assert e.value.code == "NOT_ENFORCEMENT_PROBE" and es.paths == ["/health"]


def test_nothing_listening_and_a_non_loopback_origin_are_refused():
    with pytest.raises(EnvironmentFault) as e:
        check_enforcement_probe("http://127.0.0.1:9")
    assert e.value.code == "NOT_ENFORCEMENT_PROBE"
    with pytest.raises(EnvironmentFault) as e:
        check_enforcement_probe("http://example.com:8203")
    assert e.value.code == "TARGET_OUT_OF_SCOPE"


def test_the_two_presentations_do_not_stand_in_for_each_other():
    with Health({"demo": {"enabled": False}, "enforcement_probe": {"enabled": True}}) as live:
        with pytest.raises(EnvironmentFault) as e:
            check_fixture_mode(live.origin)
        assert e.value.code == "NOT_FIXTURE_MODE", "a live instance is never accepted by the fixture-mode journey"
    assert target_statement(plan_mod.ENFORCEMENT_PLAN_ID) == "enforcement_probe.enabled=true"
    assert target_statement("edge-sentinel-fixture-readonly") == "demo.enabled=true" and target_statement("anything-else") == "demo.enabled=true"
