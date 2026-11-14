# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""API v1: local users and sessions (roles, CSRF, rate limit), targets, profiles, estimates, runs that need approval, events, cancel, evidence, and the static interface with its CSP."""
import http.client
import http.server
import json
import threading
import time
import urllib.request

import pytest

from qa_service.runs import wait_idle

from qs_support import TOKEN


def login(c, name, password):
    conn = http.client.HTTPConnection(c.base.split("//")[1])
    body = json.dumps({"username": name, "password": password})
    conn.request("POST", "/v1/session", body=body, headers={"Content-Type": "application/json"})
    r = conn.getresponse()
    data = json.loads(r.read() or b"null")
    cookie = (r.getheader("Set-Cookie") or "").split(";")[0]
    conn.close()
    return r.status, data, cookie, r.getheader("Set-Cookie")


class User:
    """A signed-in browser-style client: cookie + CSRF header."""

    def __init__(self, c, cookie, csrf):
        self.c, self.cookie, self.csrf = c, cookie, csrf

    def call(self, method, path, body=None, csrf=True, headers=None):
        h = {"Cookie": self.cookie, **(headers or {})}
        if csrf and method not in ("GET", "HEAD"):
            h["X-CSRF-Token"] = self.csrf
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.c.base + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw and resp.headers.get("Content-Type", "").startswith("application/json") else raw), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            with exc:
                raw = exc.read()
                return exc.code, (json.loads(raw) if raw else None), dict(exc.headers)


@pytest.fixture
def app(make_server):
    srv, c = make_server()
    for name, role in (("alice-admin", "admin"), ("olivia-op", "operator"), ("vince-view", "viewer"), ("oscar-op2", "operator")):
        srv.users.add(name, role, "correct horse battery staple", created_by="test")
    users = {}
    for name in ("alice-admin", "olivia-op", "vince-view", "oscar-op2"):
        status, data, cookie, _ = login(c, name, "correct horse battery staple")
        assert status == 200
        users[name] = User(c, cookie, data["csrf"])
    return srv, c, users


# ------------------------------------------------------------------------------------------------ users and sessions
def test_login_sets_an_httponly_samesite_strict_cookie_and_returns_a_csrf_value(make_server):
    srv, c = make_server()
    srv.users.add("alice-admin", "admin", "correct horse battery staple")
    status, data, cookie, setcookie = login(c, "alice-admin", "correct horse battery staple")
    assert status == 200 and data["user"]["role"] == "admin" and "password_hash" not in json.dumps(data) and data["csrf"]
    assert "HttpOnly" in setcookie and "SameSite=Strict" in setcookie and "Path=/" in setcookie and cookie.startswith("qa_session=")


def test_wrong_password_unknown_user_and_disabled_user_are_the_same_401_and_leave_no_cookie(make_server):
    srv, c = make_server()
    u = srv.users.add("alice-admin", "admin", "correct horse battery staple")
    srv.users.add("bob-viewer", "viewer", "another long password here")
    srv.users.update(srv.users.get_by_name("bob-viewer")["user_id"], disabled=True)
    seen = {login(c, n, p)[:1] + (login(c, n, p)[3],) for n, p in (("alice-admin", "wrong wrong wrong"), ("nobody-here", "correct horse battery staple"), ("bob-viewer", "another long password here"))}
    assert seen == {(401, None)}


def test_logins_are_rate_limited(make_server):
    srv, c = make_server()
    srv.users.add("alice-admin", "admin", "correct horse battery staple")
    codes = [login(c, "alice-admin", "wrong wrong wrong")[0] for _ in range(10)]
    assert 401 in codes and codes[-1] == 429
    assert login(c, "alice-admin", "correct horse battery staple")[0] == 429, "even the right password waits"


def test_a_cookie_write_without_the_csrf_header_or_with_a_foreign_origin_is_refused_and_a_read_needs_neither(app):
    srv, c, u = app
    op = u["olivia-op"]
    assert op.call("GET", "/v1/runs")[0] == 200
    status, doc, _ = op.call("POST", "/v1/runs", {"plan": "browser"}, csrf=False)
    assert status == 403 and doc["error"] == "csrf_required"
    status, doc, _ = op.call("POST", "/v1/runs", {"plan": "browser"}, headers={"Origin": "http://evil.example"})
    assert status == 403 and doc["error"] == "csrf_required"
    assert op.call("POST", "/v1/runs", {"plan": "browser"}, headers={"Origin": c.base})[0] == 202
    assert wait_idle(srv.store, 20)


def test_the_roles_are_enforced_on_every_write(app):
    srv, c, u = app
    admin, op, view = u["alice-admin"], u["olivia-op"], u["vince-view"]
    assert view.call("GET", "/v1/runs")[0] == 200 and view.call("GET", "/v1/targets")[0] == 200
    for who, method, path, body, want in ((view, "POST", "/v1/runs", {"plan": "browser"}, 403), (view, "POST", "/v1/estimates", {"profile": "fixture-browser"}, 403),
                                           (op, "POST", "/v1/targets", {"name": "x"}, 403), (op, "GET", "/v1/users", None, 403), (view, "GET", "/v1/users", None, 403),
                                           (op, "POST", "/v1/users", {"name": "new-user", "role": "viewer", "password": "long enough password"}, 403)):
        assert who.call(method, path, body)[0] == want, (method, path)
    assert admin.call("GET", "/v1/users")[0] == 200
    assert admin.call("POST", "/v1/users", {"name": "new-user", "role": "viewer", "password": "long enough password"})[0] == 201


def test_the_service_token_reads_and_stages_but_never_decides_or_manages_users(app):
    srv, c, u = app
    assert c.json("GET", "/v1/targets")[0] == 200
    assert c.json("GET", "/v1/users")[0] == 403
    assert c.json("POST", "/v1/users", {"name": "robot-user", "role": "admin", "password": "long enough password"})[0] == 403
    assert c.json("POST", "/v1/targets", {"name": "x"})[0] == 403


def test_basic_auth_with_a_local_user_works_without_a_cookie_or_csrf(make_server):
    import base64
    srv, c = make_server()
    srv.users.add("carol-op", "operator", "correct horse battery staple")
    raw = base64.b64encode(b"carol-op:correct horse battery staple").decode()
    req = urllib.request.Request(c.base + "/v1/session", headers={"Authorization": "Basic " + raw})
    with urllib.request.urlopen(req) as r:
        assert json.load(r)["principal"] == {"kind": "user", "name": "carol-op", "role": "operator", "via": "basic"}
    bad = urllib.request.Request(c.base + "/v1/session", headers={"Authorization": "Basic " + base64.b64encode(b"carol-op:nope").decode()})
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(bad)
    assert exc.value.code == 401
    exc.value.close()


def test_logout_revokes_the_session_and_a_role_change_signs_the_user_out(app):
    srv, c, u = app
    op = u["olivia-op"]
    assert op.call("DELETE", "/v1/session")[0] == 204
    assert op.call("GET", "/v1/runs")[0] == 401
    view = u["vince-view"]
    srv.users.update(srv.users.get_by_name("vince-view")["user_id"], disabled=True)
    assert view.call("GET", "/v1/runs")[0] == 401, "a disabled user's session stops working at once"


def test_the_last_admin_cannot_be_removed_and_passwords_have_a_minimum(app):
    srv, c, u = app
    admin = u["alice-admin"]
    me = srv.users.get_by_name("alice-admin")["user_id"]
    assert admin.call("PATCH", f"/v1/users/{me}", {"role": "viewer"})[0] == 409
    assert admin.call("PATCH", f"/v1/users/{me}", {"disabled": True})[0] == 409
    assert admin.call("POST", "/v1/users", {"name": "short-pass", "role": "viewer", "password": "tooshort"})[0] == 422
    assert admin.call("POST", "/v1/users", {"name": "Bad Name", "role": "viewer", "password": "long enough password"})[0] == 422
    assert admin.call("POST", "/v1/users", {"name": "alice-admin", "role": "viewer", "password": "long enough password"})[0] == 409
    assert json.loads((srv.cfg.data_dir / "users.json").read_text())["users"][0]["password_hash"].startswith("scrypt$")
    import os, stat
    assert stat.S_IMODE(os.stat(srv.cfg.data_dir / "users.json").st_mode) == 0o600


# ------------------------------------------------------------------------------------------------ targets, profiles, estimates
class Health(http.server.BaseHTTPRequestHandler):
    demo = True

    def do_GET(self):
        body = json.dumps({"status": "ok", "demo": {"enabled": self.demo}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def es_target():
    servers = []

    def make(demo=True):
        handler = type("H", (Health,), {"demo": demo})
        s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        servers.append(s)
        return f"http://127.0.0.1:{s.server_address[1]}"
    yield make
    for s in servers:
        s.shutdown()
        s.server_close()


def test_the_builtin_fixture_target_and_the_profiles_are_listed_with_their_availability(app):
    srv, c, u = app
    targets = u["vince-view"].call("GET", "/v1/targets")[1]["items"]
    assert [t["id"] for t in targets] == ["tgt-000000000000"] and targets[0]["builtin"] and targets[0]["level_ceiling"] == "VERIFIED" and targets[0]["run_approval"] == "none"
    profiles = {p["id"]: p for p in u["vince-view"].call("GET", "/v1/profiles")[1]["items"]}
    assert profiles["fixture-browser"]["available"] and profiles["fixture-browser"]["unavailable"] is None
    es = profiles["edge-sentinel-fixture-readonly"]
    assert es["available"] is True and es["unavailable"] is None and es["targets"] == ["external-origin"]
    assert u["vince-view"].call("GET", "/v1/profiles?target_id=tgt-000000000000")[1]["items"][-1]["unavailable"]["code"] == "TARGET_KIND_MISMATCH"


def test_on_an_installation_that_cannot_run_lanes_the_external_profile_is_listed_unavailable_with_its_reason(make_server):
    from qa_service.capabilities import Facts
    srv, c = make_server(facts=Facts(machine="aarch64", missing_packages=("playwright", "robot")))
    es = {p["id"]: p for p in c.json("GET", "/v1/profiles")[1]["items"]}["edge-sentinel-fixture-readonly"]
    assert es["available"] is False and es["unavailable"]["code"] == "ARCHITECTURE_UNSUPPORTED" and es["unavailable"]["remedy"], "listed and disabled WITH its reason, never hidden"


def test_registering_a_loopback_fixture_mode_target_and_refusing_everything_else(app, es_target):
    srv, c, u = app
    admin = u["alice-admin"]
    origin = es_target()
    status, t, _ = admin.call("POST", "/v1/targets", {"name": "es fixture", "origin": origin})
    assert status == 201 and t["kind"] == "external-origin" and t["level_ceiling"] == "CORROBORATED" and t["run_approval"] == "required" and t["mutating"] is False and t["credential_refs"] == []
    assert t["declared_by"] == "operator" and t["declared_user"] == "alice-admin" and t["last_probe"]["ok"] is True and re.fullmatch(r"tgt-[0-9a-f]{12}", t["id"])
    assert admin.call("POST", "/v1/targets", {"name": "es fixture", "origin": origin})[0] == 409
    for body, status_want, code in (({"name": "real", "origin": "https://app.example"}, 422, "TARGET_OUT_OF_SCOPE"), ({"name": "path", "origin": origin + "/x"}, 422, "invalid"),
                                    ({"name": "real", "origin": es_target(demo=False)}, 422, "NOT_FIXTURE_MODE"), ({"name": "down", "origin": "http://127.0.0.1:9"}, 422, "NOT_FIXTURE_MODE"),
                                    ({"name": "x", "origin": origin, "credential_refs": ["env:X"]}, 422, "invalid"), ({"name": "x", "origin": origin, "run_approval": "none"}, 422, "invalid")):
        s, doc, _ = admin.call("POST", "/v1/targets", body)
        assert (s, doc["error"]) == (status_want, code), (body, doc)
    assert admin.call("DELETE", f"/v1/targets/{t['id']}")[0] == 204
    assert admin.call("DELETE", "/v1/targets/tgt-000000000000")[0] == 409


def test_an_estimate_is_made_from_the_service_built_plan_and_binds_a_digest(app, es_target):
    srv, c, u = app
    op = u["olivia-op"]
    status, est, _ = op.call("POST", "/v1/estimates", {"profile": "fixture-browser"})
    assert status == 201 and est["digest"].startswith("sha256:") and est["will_refuse"] is False and est["target_id"] == "tgt-000000000000" and est["contacts"].startswith("nothing")
    origin = es_target()
    t = u["alice-admin"].call("POST", "/v1/targets", {"name": "es", "origin": origin})[1]
    status, est2, _ = op.call("POST", "/v1/estimates", {"target_id": t["id"], "profile": "edge-sentinel-fixture-readonly"})
    assert status == 201 and est2["origin"] == origin and est2["verification_ceiling"] == "CORROBORATED" and est2["will_refuse"] is False and est2["problems"] == []
    assert op.call("POST", "/v1/estimates", {"target_id": t["id"], "profile": "fixture-browser"})[0] == 422
    assert op.call("POST", "/v1/estimates", {"profile": "nope"})[0] == 422
    assert op.call("POST", "/v1/estimates", {"profile": "fixture-browser", "path": "/etc/passwd"})[0] == 400


def test_a_run_of_an_external_target_waits_for_a_human_approval_of_its_estimate_and_ends_with_the_corroborated_level(app, es_target):
    srv, c, u = app
    op, op2 = u["olivia-op"], u["oscar-op2"]
    origin = es_target()
    t = u["alice-admin"].call("POST", "/v1/targets", {"name": "es", "origin": origin})[1]
    est = op.call("POST", "/v1/estimates", {"target_id": t["id"], "profile": "edge-sentinel-fixture-readonly"})[1]
    status, run, _ = op.call("POST", "/v1/runs", {"target_id": t["id"], "profile": "edge-sentinel-fixture-readonly", "estimate_digest": est["digest"]})
    assert status == 202 and run["state"] == "awaiting_approval" and run["level_ceiling"] == "CORROBORATED" and run["defect"] == "none"
    assert op.call("POST", "/v1/runs", {"target_id": t["id"], "profile": "edge-sentinel-fixture-readonly", "defect": "settings", "estimate_digest": est["digest"]})[0] == 422
    assert c.json("POST", f"/v1/runs/{run['id']}/approval", {"approved": True, "estimate_digest": est["digest"]})[0] == 403
    assert op2.call("POST", f"/v1/runs/{run['id']}/approval", {"approved": True, "estimate_digest": est["digest"]})[0] == 200
    assert wait_idle(srv.store, 30)
    done = op.call("GET", f"/v1/runs/{run['id']}")[1]
    assert (done["state"], done["exit_code"], done["outcome"], done["level"]) == ("finished", 8, "CORROBORATED", "CORROBORATED"), "an external run never reads VERIFIED"
    argv = json.loads(next((srv.cfg.data_dir / "runs" / run["id"] / "evidence").glob("*/bundle-manifest.json")).read_text())["argv"]
    plan = json.loads((srv.cfg.data_dir / "runs" / run["id"] / "plan.json").read_text())
    assert argv[0] == "run" and argv[1].endswith("plan.json") and plan["target"] == {"kind": "external-origin", "origin": origin, "declared_by": "operator", "credential_refs": [], "mutating": False}
    ev = op.call("GET", f"/v1/runs/{run['id']}/evidence")[1]
    assert ev["level"] == "CORROBORATED" and ev["independent_restatement"] is False and "no independent restatement" in ev["restatement_note"]


def test_level_is_capped_by_the_target_even_if_the_command_said_verified():
    from qa_service.runs import level_for
    assert level_for("VERIFIED", "CORROBORATED") == "CORROBORATED" and level_for("CORROBORATED", "CORROBORATED") == "CORROBORATED" and level_for("VERIFIED", "VERIFIED") == "VERIFIED"
    assert level_for("FAILED", "CORROBORATED") is None and level_for(None, "VERIFIED") is None


# ------------------------------------------------------------------------------------------------ approvals, events, cancel
def approval_target(u):
    return u["alice-admin"].call("POST", "/v1/targets", {"name": "fixture needing approval", "run_approval": "required"})[1]


def test_a_target_that_needs_approval_creates_a_run_that_waits_and_only_the_estimated_digest_starts_it(app):
    srv, c, u = app
    op, op2 = u["olivia-op"], u["oscar-op2"]
    t = approval_target(u)
    assert t["kind"] == "fixture-app" and t["run_approval"] == "required" and t["level_ceiling"] == "VERIFIED"
    assert op.call("POST", "/v1/runs", {"target_id": t["id"], "profile": "fixture-browser"})[1]["error"] == "estimate_required"
    est = op.call("POST", "/v1/estimates", {"target_id": t["id"], "profile": "fixture-browser"})[1]
    status, run, _ = op.call("POST", "/v1/runs", {"target_id": t["id"], "profile": "fixture-browser", "estimate_digest": est["digest"]})
    assert status == 202 and run["state"] == "awaiting_approval" and run["approval"]["state"] == "pending" and run["requested_by"] == {"user": "olivia-op", "via": "session"}
    time.sleep(0.3)
    assert op.call("GET", f"/v1/runs/{run['id']}")[1]["state"] == "awaiting_approval", "nothing started"
    assert c.json("POST", f"/v1/runs/{run['id']}/approval", {"approved": True, "estimate_digest": est["digest"]})[0] == 403, "the service token never approves"
    assert u["vince-view"].call("POST", f"/v1/runs/{run['id']}/approval", {"approved": True, "estimate_digest": est["digest"]})[0] == 403
    status, doc, _ = op2.call("POST", f"/v1/runs/{run['id']}/approval", {"approved": True, "estimate_digest": "sha256:" + "0" * 64})
    assert status == 409 and doc["error"] == "stale_approval"
    status, doc, _ = op2.call("POST", f"/v1/runs/{run['id']}/approval", {"approved": True, "estimate_digest": est["digest"], "rationale": "reviewed the estimate"})
    assert status == 200 and doc["state"] == "running" and doc["approval"]["actor_user"] == "oscar-op2" and doc["approval"]["actor_role"] == "operator" and doc["approval"]["via"] == "session"
    assert wait_idle(srv.store, 20)
    done = op.call("GET", f"/v1/runs/{run['id']}")[1]
    assert done["state"] == "finished" and done["outcome"] == "VERIFIED" and done["level"] == "VERIFIED" and done["target_id"] == t["id"]
    assert op2.call("POST", f"/v1/runs/{run['id']}/approval", {"approved": True, "estimate_digest": est["digest"]})[0] == 409, "an approval is single use"
    types = [e["type"] for e in op.call("GET", f"/v1/runs/{run['id']}/events")[1]["items"]]
    assert types == ["run.queued", "run.approval_requested", "run.approved", "run.started", "run.finished"]


def test_a_rejected_run_never_starts_and_the_two_person_rule_blocks_self_approval(make_server):
    srv, c = make_server(QA_REQUIRE_TWO_PERSON="1")
    for name, role in (("alice-admin", "admin"), ("olivia-op", "operator"), ("oscar-op2", "operator")):
        srv.users.add(name, role, "correct horse battery staple")
    cl = {}
    for name in ("alice-admin", "olivia-op", "oscar-op2"):
        s, d, ck, _ = login(c, name, "correct horse battery staple")
        cl[name] = User(c, ck, d["csrf"])
    t = cl["alice-admin"].call("POST", "/v1/targets", {"name": "needs approval", "run_approval": "required"})[1]
    est = cl["olivia-op"].call("POST", "/v1/estimates", {"target_id": t["id"], "profile": "fixture-browser"})[1]
    run = cl["olivia-op"].call("POST", "/v1/runs", {"target_id": t["id"], "profile": "fixture-browser", "estimate_digest": est["digest"]})[1]
    assert cl["olivia-op"].call("POST", f"/v1/runs/{run['id']}/approval", {"approved": True, "estimate_digest": est["digest"]})[0] == 403
    status, doc, _ = cl["oscar-op2"].call("POST", f"/v1/runs/{run['id']}/approval", {"approved": False, "estimate_digest": est["digest"], "rationale": "not now"})
    assert status == 200 and doc["state"] == "refused" and doc["approval"]["state"] == "rejected" and doc["approval"]["rationale"] == "not now"
    assert not list((srv.cfg.data_dir / "runs" / run["id"] / "evidence").iterdir())


def test_cancel_a_waiting_run_and_a_running_run(app):
    srv, c, u = app
    op = u["olivia-op"]
    t = approval_target(u)
    est = op.call("POST", "/v1/estimates", {"target_id": t["id"], "profile": "fixture-browser"})[1]
    run = op.call("POST", "/v1/runs", {"target_id": t["id"], "profile": "fixture-browser", "estimate_digest": est["digest"]})[1]
    assert op.call("POST", f"/v1/runs/{run['id']}/cancel")[1]["state"] == "cancelled"
    assert op.call("POST", f"/v1/runs/{run['id']}/cancel")[0] == 409


def test_cancelling_a_running_run_kills_it_and_says_so(make_server):
    srv, c = make_server(control={"sleep": 30})
    run = c.json("POST", "/v1/runs", {"plan": "browser"})[1]
    time.sleep(1.0)
    assert c.json("POST", f"/v1/runs/{run['id']}/cancel")[0] == 200
    assert wait_idle(srv.store, 20)
    done = c.json("GET", f"/v1/runs/{run['id']}")[1]
    assert done["state"] == "cancelled" and done["outcome"] is None
    assert [e["type"] for e in c.json("GET", f"/v1/runs/{run['id']}/events")[1]["items"]][-1] == "run.cancelled"


def test_events_are_polled_with_a_cursor_and_the_feed_says_when_it_is_over(app):
    srv, c, u = app
    op = u["olivia-op"]
    run = op.call("POST", "/v1/runs", {"plan": "browser"})[1]
    assert wait_idle(srv.store, 20)
    feed = op.call("GET", f"/v1/runs/{run['id']}/events")[1]
    assert feed["terminal"] is True and feed["head"] == len(feed["items"]) and [e["seq"] for e in feed["items"]] == list(range(1, feed["head"] + 1))
    tail = op.call("GET", f"/v1/runs/{run['id']}/events?after=2&limit=1")[1]
    assert [e["seq"] for e in tail["items"]] == [3] and tail["head"] == feed["head"]
    assert op.call("GET", f"/v1/runs/{run['id']}/events?after=x")[0] == 422


def test_the_history_is_filtered_and_paged_with_a_cursor_newest_first(app):
    srv, c, u = app
    op = u["olivia-op"]
    ids = []
    for _ in range(3):
        ids.append(op.call("POST", "/v1/runs", {"plan": "browser"})[1]["id"])
        assert wait_idle(srv.store, 20)
        time.sleep(1.05)             # run ids carry the second
    page = op.call("GET", "/v1/runs?limit=2")[1]
    assert [r["id"] for r in page["items"]] == ids[::-1][:2] and page["next_cursor"]
    rest = op.call("GET", "/v1/runs?limit=2&cursor=" + page["next_cursor"])[1]
    assert [r["id"] for r in rest["items"]] == ids[::-1][2:] and rest["next_cursor"] is None
    assert len(op.call("GET", "/v1/runs?outcome=FAILED")[1]["items"]) == 0 and len(op.call("GET", "/v1/runs?state=finished")[1]["items"]) == 3
    assert op.call("GET", "/v1/runs?cursor=!!!")[0] == 422


# ------------------------------------------------------------------------------------------------ evidence
def test_evidence_lists_files_by_index_and_serves_only_listed_files(app):
    srv, c, u = app
    op = u["olivia-op"]
    run = op.call("POST", "/v1/runs", {"plan": "browser"})[1]
    assert wait_idle(srv.store, 20)
    ev = op.call("GET", f"/v1/runs/{run['id']}/evidence")[1]
    assert ev["level"] == "VERIFIED" and ev["ceiling"] == "VERIFIED" and ev["independent_restatement"] is True and ev["verification"]["accepted"] is True
    assert [f["path"] for f in ev["files"]] == ["bundle-manifest.json", "logs/x.txt"] and ev["files"][1]["index"] == 1
    status, body, headers = op.call("GET", f"/v1/runs/{run['id']}/evidence/files/1")
    assert status == 200 and body == b"x\n" and "attachment" in headers["Content-Disposition"] and headers["Content-Type"] == "application/octet-stream"
    assert op.call("GET", f"/v1/runs/{run['id']}/evidence/files/9")[0] == 404
    assert op.call("GET", f"/v1/runs/{run['id']}/evidence/files/..%2f..")[0] == 404
    assert op.call("GET", f"/v1/runs/{run['id']}/verify")[1]["exit_code"] == 0


# ------------------------------------------------------------------------------------------------ the interface
def test_the_interface_is_served_with_a_strict_csp_and_a_spa_fallback_and_carries_no_data(make_server):
    srv, c = make_server()
    for path in ("/ui/", "/ui/runs", "/ui/runs/r20260101T000000Z-abcdef", "/ui"):
        status, body, headers = c.call("GET", path, token=None)
        assert status == 200 and b"<script" in body and headers["Content-Type"].startswith("text/html"), path
        assert headers["Content-Security-Policy"] == ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
        assert headers["X-Frame-Options"] == "DENY" and headers["X-Content-Type-Options"] == "nosniff"
    assert c.call("GET", "/ui/app.js", token=None)[2]["Content-Type"].startswith("text/javascript")
    assert c.call("GET", "/ui/missing.js", token=None)[0] == 404
    assert c.call("GET", "/ui/../v1/info", token=None)[0] in (401, 404)
    assert c.call("GET", "/", token=None)[0] in (200, 302)


import re  # noqa: E402  (used by a test above)


def test_the_first_admin_is_created_from_the_bootstrap_password_once_and_the_password_is_not_logged(tmp_path, capsys):
    from qa_service.__main__ import bootstrap_admin
    from qa_service.users import UserStore
    import qa_service.users as users_mod
    users_mod.SCRYPT = {"n": 2 ** 10, "r": 8, "p": 1, "dklen": 32}
    assert "no bootstrap password" in bootstrap_admin(tmp_path, {})
    msg = bootstrap_admin(tmp_path, {"QA_SERVICE_BOOTSTRAP_ADMIN_PASSWORD": "a long bootstrap password"})
    assert "created the first admin 'admin'" in msg and "a long bootstrap password" not in msg
    assert UserStore(tmp_path).authenticate("admin", "a long bootstrap password")["role"] == "admin"
    assert bootstrap_admin(tmp_path, {"QA_SERVICE_BOOTSTRAP_ADMIN_PASSWORD": "another bootstrap password"}) == "users exist"
    pwfile = tmp_path / "pw"
    pwfile.write_text("file based password!\n")
    other = tmp_path / "other"
    other.mkdir()
    assert "created" in bootstrap_admin(other, {"QA_SERVICE_BOOTSTRAP_ADMIN_PASSWORD_FILE": str(pwfile), "QA_SERVICE_BOOTSTRAP_ADMIN_NAME": "root-admin"})


def test_the_users_command_adds_and_lists_without_a_running_service(tmp_path, monkeypatch, capsys):
    from qa_service.__main__ import users_command
    import qa_service.users as users_mod
    monkeypatch.setattr(users_mod, "SCRYPT", {"n": 2 ** 10, "r": 8, "p": 1, "dklen": 32})
    monkeypatch.setenv("QA_SERVICE_DATA_DIR", str(tmp_path))
    pw = tmp_path / "pw"
    pw.write_text("a good long password\n")
    assert users_command(["add", "dana-admin", "--role", "admin", "--password-file", str(pw)]) == 0
    assert users_command(["add", "dana-admin", "--role", "admin", "--password-file", str(pw)]) == 1
    assert users_command(["list"]) == 0
    out = capsys.readouterr().out
    assert "dana-admin\tadmin\tenabled" in out and "a good long password" not in out


# ------------------------------------------------------------------------------------------------ signed approvals from another product
def mint(secret, *, run_id, approved, estimate_digest, by="projects:local-owner", via="projects", operator="redevops-qa", capability="qa.approve_run", ttl=120, now=None, inputs=None, mission_id=None):
    """The platform's token (agentic_os.mission.approval.mint_approval_token), reproduced with the standard library: the tests of this service do not import agentic_os."""
    import base64, hashlib, hmac, secrets as sec
    canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"), default=str).encode()   # noqa: E731
    payload = canon({"operator": operator, "capability": capability, "mission_id": mission_id, "node_id": None,
                     "inputs_sha256": hashlib.sha256(canon(inputs if inputs is not None else {"run_id": run_id, "approved": approved, "estimate_digest": estimate_digest})).hexdigest(),
                     "marker": {"approved": approved, "by": by, "via": via}, "exp": (time.time() if now is None else now) + ttl, "nonce": sec.token_hex(16)})
    b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()   # noqa: E731
    return b(payload) + "." + b(hmac.new(secret, payload, hashlib.sha256).digest())


SECRET = b"shared-approval-secret-for-tests-0001"


@pytest.fixture
def projects(make_server, tmp_path):
    srv, c = make_server(QA_SERVICE_APPROVAL_SECRET=SECRET.decode())
    for name, role in (("alice-admin", "admin"), ("olivia-op", "operator"), ("vince-view", "viewer")):
        srv.users.add(name, role, "correct horse battery staple")
    users = {}
    for name in ("alice-admin", "olivia-op", "vince-view"):
        s_, d, ck, _ = login(c, name, "correct horse battery staple")
        users[name] = User(c, ck, d["csrf"])
    t = users["alice-admin"].call("POST", "/v1/targets", {"name": "approval", "run_approval": "required"})[1]
    est = users["olivia-op"].call("POST", "/v1/estimates", {"target_id": t["id"], "profile": "fixture-browser"})[1]
    run = c.json("POST", "/v1/runs", {"target_id": t["id"], "profile": "fixture-browser", "estimate_digest": est["digest"]})[1]
    assert run["state"] == "awaiting_approval" and run["requested_by"]["user"] == "service"
    return srv, c, users, run, est["digest"]


def approve_with(c, run, digest, token, approved=True):
    req = urllib.request.Request(c.base + f"/v1/runs/{run['id']}/approval", data=json.dumps({"approved": approved, "estimate_digest": digest}).encode(), method="POST",
                                 headers={"Authorization": "Bearer " + TOKEN, "X-Approval-Token": token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        with e:
            return e.code, json.loads(e.read())


def test_a_signed_approval_for_a_linked_actor_is_recorded_as_that_local_user_via_projects(projects):
    srv, c, u, run, digest = projects
    op = u["olivia-op"]
    me = srv.users.get_by_name("olivia-op")["user_id"]
    assert op.call("POST", "/v1/actor-links", {"external_actor": "projects:local-owner"})[0] == 201
    status, doc = approve_with(c, run, digest, mint(SECRET, run_id=run["id"], approved=True, estimate_digest=digest))
    assert status == 200 and doc["state"] == "running"
    assert doc["approval"]["actor_user"] == "olivia-op" and doc["approval"]["actor_role"] == "operator" and doc["approval"]["via"] == "projects" and doc["approval"]["external_actor"] == "projects:local-owner"
    assert wait_idle(srv.store, 20)
    assert [e["type"] for e in op.call("GET", f"/v1/runs/{run['id']}/events")[1]["items"]][2] == "run.approved"


@pytest.mark.parametrize("what", ["no_secret_match", "other_run", "other_decision", "other_digest", "expired", "other_operator", "other_capability", "bound_mission", "other_marker", "not_projects", "not_via_projects", "tampered"])
def test_a_token_that_is_not_exactly_for_this_run_decision_and_estimate_is_refused(projects, what):
    srv, c, u, run, digest = projects
    u["olivia-op"].call("POST", "/v1/actor-links", {"external_actor": "projects:local-owner"})
    kw = dict(run_id=run["id"], approved=True, estimate_digest=digest)
    token = {"no_secret_match": lambda: mint(b"another-secret-of-sufficient-length", **kw), "other_run": lambda: mint(SECRET, **{**kw, "run_id": "r20260101T000000Z-abcdef"}),
             "other_decision": lambda: mint(SECRET, **{**kw, "approved": False}), "other_digest": lambda: mint(SECRET, **{**kw, "estimate_digest": "sha256:" + "0" * 64}),
             "expired": lambda: mint(SECRET, **kw, now=time.time() - 1000), "other_operator": lambda: mint(SECRET, **kw, operator="edge-sentinel"),
             "other_capability": lambda: mint(SECRET, **kw, capability="sentinel.decide"), "bound_mission": lambda: mint(SECRET, **kw, mission_id="m1"),
             "other_marker": lambda: mint(SECRET, **kw, via="runtime"), "not_projects": lambda: mint(SECRET, **kw, by="admin"), "not_via_projects": lambda: mint(SECRET, **kw, via="session"),
             "tampered": lambda: mint(SECRET, **kw)[:-4] + "AAAA"}[what]()
    status, doc = approve_with(c, run, digest, token)
    assert status == 403 and doc["error"] == "approval_token_invalid", (what, doc)
    assert u["olivia-op"].call("GET", f"/v1/runs/{run['id']}")[1]["state"] == "awaiting_approval"


def test_a_token_works_once_and_a_restart_does_not_forget_it(projects):
    srv, c, u, run, digest = projects
    u["olivia-op"].call("POST", "/v1/actor-links", {"external_actor": "projects:local-owner"})
    token = mint(SECRET, run_id=run["id"], approved=True, estimate_digest=digest)
    assert approve_with(c, run, digest, token)[0] == 200
    assert wait_idle(srv.store, 20)
    from qa_service.approvals import NonceStore
    assert NonceStore(srv.cfg.data_dir / "approval-nonces.txt").consume("x", time.time() + 5, time.time()) is True
    status, doc = approve_with(c, run, digest, token)
    assert status in (403, 409), "the replay of a token is refused (the run is no longer waiting, and the nonce is spent)"
    fresh = NonceStore(srv.cfg.data_dir / "approval-nonces.txt")
    nonce = json.loads(__import__("base64").urlsafe_b64decode(token.split(".")[0] + "==="))["nonce"]
    assert fresh.consume(nonce, time.time() + 100, time.time()) is False, "the nonce was written to the data volume"


def test_an_actor_that_is_not_linked_or_linked_to_a_viewer_cannot_decide_and_the_run_keeps_waiting(projects):
    srv, c, u, run, digest = projects
    status, doc = approve_with(c, run, digest, mint(SECRET, run_id=run["id"], approved=True, estimate_digest=digest))
    assert status == 403 and doc["error"] == "actor_not_linked" and doc["actor"] == "projects:local-owner"
    assert u["vince-view"].call("POST", "/v1/actor-links", {"external_actor": "projects:local-owner"})[0] == 201
    status, doc = approve_with(c, run, digest, mint(SECRET, run_id=run["id"], approved=True, estimate_digest=digest))
    assert status == 403 and doc["error"] == "actor_not_linked", "the linked user's ROLE decides, not anything Projects asserts"
    assert u["olivia-op"].call("GET", f"/v1/runs/{run['id']}")[1]["state"] == "awaiting_approval"


def test_removing_a_link_removes_the_ability_at_once_and_only_an_admin_manages_links(projects):
    srv, c, u, run, digest = projects
    assert u["olivia-op"].call("POST", "/v1/actor-links", {"external_actor": "projects:local-owner"})[0] == 201
    assert u["olivia-op"].call("GET", "/v1/actor-links")[0] == 403
    assert u["olivia-op"].call("POST", "/v1/actor-links", {"external_actor": "projects:other", "user_id": srv.users.get_by_name("vince-view")["user_id"]})[0] == 403
    assert u["vince-view"].call("POST", "/v1/actor-links", {"external_actor": "projects:local-owner"})[0] == 409
    assert u["olivia-op"].call("POST", "/v1/actor-links", {"external_actor": "admin"})[0] == 422
    assert [x["external_actor"] for x in u["alice-admin"].call("GET", "/v1/actor-links")[1]["items"]] == ["projects:local-owner"]
    assert u["alice-admin"].call("DELETE", "/v1/actor-links/projects%3Alocal-owner")[0] == 204
    status, doc = approve_with(c, run, digest, mint(SECRET, run_id=run["id"], approved=True, estimate_digest=digest))
    assert status == 403 and doc["error"] == "actor_not_linked"


def test_the_token_is_for_the_service_credential_only_and_without_a_secret_it_is_never_accepted(make_server):
    srv, c = make_server()                                                  # no approval secret configured
    srv.users.add("olivia-op", "operator", "correct horse battery staple")
    s_, d, ck, _ = login(c, "olivia-op", "correct horse battery staple")
    u = User(c, ck, d["csrf"])
    t = srv.store.targets.register({"name": "needs approval", "run_approval": "required"}, user="x", estimate=srv.store.estimator)
    est = u.call("POST", "/v1/estimates", {"target_id": t["id"], "profile": "fixture-browser"})[1]
    run = u.call("POST", "/v1/runs", {"target_id": t["id"], "profile": "fixture-browser", "estimate_digest": est["digest"]})[1]
    u.call("POST", "/v1/actor-links", {"external_actor": "projects:local-owner"})
    status, doc = approve_with(c, run, est["digest"], mint(SECRET, run_id=run["id"], approved=True, estimate_digest=est["digest"]))
    assert status == 403 and doc["error"] == "approval_token_invalid"
    status, doc, _ = u.call("POST", f"/v1/runs/{run['id']}/approval", {"approved": True, "estimate_digest": est["digest"]}, headers={"X-Approval-Token": "x"})
    assert status == 403 and doc["error"] == "forbidden", "a user decides in their own name, not with a token"
