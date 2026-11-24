# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The enforcement profile: a live loopback Edge Sentinel that switched its read-only enforcement page on is a second kind of external target. It is registered by what its /health says,
runs its own profile and no other, needs a person's approval like every external run, and stays capped at CORROBORATED."""
import http.server
import json
import threading

import pytest

from qa_service import catalog
from qa_service.runs import wait_idle

from test_qs_v1 import app, login, User  # noqa: F401  (the signed-in clients of the v1 tests)


def serve(health):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(health).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, f"http://127.0.0.1:{s.server_address[1]}"


@pytest.fixture
def sentinel():
    servers = []

    def make(**health):
        s, origin = serve({"status": "ok", **health})
        servers.append(s)
        return origin
    yield make
    for s in servers:
        s.shutdown()
        s.server_close()


LIVE = {"demo": {"enabled": False}, "enforcement_probe": {"enabled": True}}
FIXTURE = {"demo": {"enabled": True}}


def test_a_target_is_registered_as_what_its_health_says_and_as_nothing_when_it_says_neither(app, sentinel):
    srv, c, u = app
    admin = u["alice-admin"]
    status, live, _ = admin.call("POST", "/v1/targets", {"name": "live", "origin": sentinel(**LIVE)})
    assert status == 201 and live["presentation"] == "enforcement-probe" and live["last_probe"]["detail"] == "enforcement_probe.enabled=true"
    assert live["level_ceiling"] == "CORROBORATED" and live["run_approval"] == "required" and live["mutating"] is False and live["credential_refs"] == []
    fixture = admin.call("POST", "/v1/targets", {"name": "fixture", "origin": sentinel(**FIXTURE)})[1]
    assert fixture["presentation"] == "fixture-mode"
    both = admin.call("POST", "/v1/targets", {"name": "both", "origin": sentinel(demo={"enabled": True}, enforcement_probe={"enabled": True})})[1]
    assert both["presentation"] == "fixture-mode", "a fixture core has no edge to read: fixture mode wins"
    for health in ({}, {"demo": {"enabled": False}}, {"enforcement_probe": {"enabled": False}}, {"enforcement_probe": {"enabled": "yes"}}, {"enforcement_probe": True}):
        s, doc, _ = admin.call("POST", "/v1/targets", {"name": "neither", "origin": sentinel(**health)})
        assert (s, doc["error"]) == (422, "NOT_FIXTURE_MODE"), health


def test_each_external_target_runs_its_own_profile_and_no_other(app, sentinel):
    srv, c, u = app
    admin, op = u["alice-admin"], u["olivia-op"]
    live = admin.call("POST", "/v1/targets", {"name": "live", "origin": sentinel(**LIVE)})[1]
    fixture = admin.call("POST", "/v1/targets", {"name": "fixture", "origin": sentinel(**FIXTURE)})[1]

    def offered(target):
        return {p["id"]: p for p in op.call("GET", f"/v1/profiles?target_id={target['id']}")[1]["items"]}
    assert offered(live)["edge-sentinel-enforcement"]["available"] is True
    assert offered(live)["edge-sentinel-fixture-readonly"]["unavailable"]["code"] == "TARGET_KIND_MISMATCH"
    assert offered(fixture)["edge-sentinel-fixture-readonly"]["available"] is True
    assert offered(fixture)["edge-sentinel-enforcement"]["unavailable"]["code"] == "TARGET_KIND_MISMATCH"
    assert offered(live)["fixture-browser"]["unavailable"]["code"] == "TARGET_KIND_MISMATCH"
    for target, wrong in ((live, "edge-sentinel-fixture-readonly"), (fixture, "edge-sentinel-enforcement"), (live, "fixture-browser")):
        assert op.call("POST", "/v1/estimates", {"target_id": target["id"], "profile": wrong})[0] == 422
    assert op.call("POST", "/v1/estimates", {"profile": "edge-sentinel-enforcement"})[0] == 422, "the built-in fixture app is not an Edge Sentinel"
    est = op.call("POST", "/v1/estimates", {"target_id": live["id"], "profile": "edge-sentinel-enforcement"})[1]
    s, doc, _ = op.call("POST", "/v1/runs", {"target_id": live["id"], "profile": "edge-sentinel-fixture-readonly", "estimate_digest": est["digest"]})
    assert s == 422 and doc["error"] in ("plan_unavailable", "estimate_required"), "an estimate of one profile does not start a run of another"


def test_a_run_of_the_enforcement_profile_waits_for_approval_and_is_given_the_enforcement_plan(app, sentinel):
    srv, c, u = app
    op, op2 = u["olivia-op"], u["oscar-op2"]
    origin = sentinel(**LIVE)
    t = u["alice-admin"].call("POST", "/v1/targets", {"name": "live", "origin": origin})[1]
    est = op.call("POST", "/v1/estimates", {"target_id": t["id"], "profile": "edge-sentinel-enforcement"})[1]
    assert est["origin"] == origin and est["verification_ceiling"] == "CORROBORATED" and est["will_refuse"] is False
    status, run, _ = op.call("POST", "/v1/runs", {"target_id": t["id"], "profile": "edge-sentinel-enforcement", "estimate_digest": est["digest"]})
    assert status == 202 and run["state"] == "awaiting_approval" and run["level_ceiling"] == "CORROBORATED" and run["profile"] == "edge-sentinel-enforcement"
    assert op.call("POST", "/v1/runs", {"target_id": t["id"], "profile": "edge-sentinel-enforcement", "defect": "settings", "estimate_digest": est["digest"]})[0] == 422
    assert op2.call("POST", f"/v1/runs/{run['id']}/approval", {"approved": True, "estimate_digest": est["digest"]})[0] == 200
    assert wait_idle(srv.store, 30)
    plan = json.loads((srv.cfg.data_dir / "runs" / run["id"] / "plan.json").read_text())
    assert plan["plan_id"] == "edge-sentinel-enforcement-readonly"
    assert plan["target"] == {"kind": "external-origin", "origin": origin, "declared_by": "operator", "credential_refs": [], "mutating": False}
    done = op.call("GET", f"/v1/runs/{run['id']}")[1]
    assert done["state"] == "finished" and done["level"] in ("CORROBORATED", None) and done["level"] != "VERIFIED"


def test_a_target_registered_before_presentations_existed_is_a_fixture_mode_target():
    old = {"id": "tgt-0123456789ab", "kind": "external-origin", "origin": "http://127.0.0.1:8203"}
    assert catalog.presentation_of(old) == "fixture-mode"
    assert catalog.profile_mismatch("edge-sentinel-fixture-readonly", old) is None
    assert catalog.profile_mismatch("edge-sentinel-enforcement", old)["code"] == "TARGET_KIND_MISMATCH"


def test_every_external_profile_names_a_presentation_and_a_shipped_template():
    from pathlib import Path
    examples = Path(__file__).resolve().parents[2] / "qa-runner" / "examples"
    seen = set()
    for pid, p in catalog.PROFILES.items():
        if "external-origin" in p["targets"]:
            assert p["presentation"] in catalog.PRESENTATIONS and p["presentation"] not in seen and (examples / p["template"]).is_file(), pid
            seen.add(p["presentation"])
            assert p["targets"] == ["external-origin"] and p["engines"] == ["playwright"]
    assert seen == set(catalog.PRESENTATIONS)
