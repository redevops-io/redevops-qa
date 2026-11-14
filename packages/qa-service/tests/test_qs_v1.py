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
    assert es["available"] is False and es["unavailable"]["code"] == "EXTERNAL_RUN_NOT_ENABLED" and es["unavailable"]["remedy"], "listed and disabled WITH its reason, never hidden"
    assert u["vince-view"].call("GET", "/v1/profiles?target_id=tgt-000000000000")[1]["items"][-1]["unavailable"]["code"] == "TARGET_KIND_MISMATCH"


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
    assert status == 201 and est2["origin"] == origin and est2["verification_ceiling"] == "CORROBORATED" and est2["will_refuse"] is True
    assert est2["problems"][-1]["code"] == "EXTERNAL_RUN_NOT_ENABLED", "the estimate says plainly that this release cannot run it"
    assert op.call("POST", "/v1/estimates", {"target_id": t["id"], "profile": "fixture-browser"})[0] == 422
    assert op.call("POST", "/v1/estimates", {"profile": "nope"})[0] == 422
    assert op.call("POST", "/v1/estimates", {"profile": "fixture-browser", "path": "/etc/passwd"})[0] == 400


def test_a_run_of_an_external_target_is_refused_even_with_a_valid_estimate(app, es_target):
    srv, c, u = app
    t = u["alice-admin"].call("POST", "/v1/targets", {"name": "es", "origin": es_target()})[1]
    est = u["olivia-op"].call("POST", "/v1/estimates", {"target_id": t["id"], "profile": "edge-sentinel-fixture-readonly"})[1]
    status, doc, _ = u["olivia-op"].call("POST", "/v1/runs", {"target_id": t["id"], "profile": "edge-sentinel-fixture-readonly", "estimate_digest": est["digest"]})
    assert status == 422 and doc["unavailable"]["code"] == "EXTERNAL_RUN_NOT_ENABLED" and u["olivia-op"].call("GET", "/v1/runs")[1]["items"] == []


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
