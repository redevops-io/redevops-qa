# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The HTTP surface: authentication on every path but the two probes, the run lifecycle, one run at a time, the limits, and what a restart does to a run that was going."""
import json
import socket
import time

import pytest

from qa_service.config import load_config
from qa_service.runs import RunStore, wait_idle
from qa_service.server import QAServer

from qs_support import TOKEN, make_env


def finish(srv):
    assert wait_idle(srv.store, 20)


def test_probes_need_no_token_and_say_nothing_else(make_server):
    srv, c = make_server()
    assert c.json("GET", "/healthz", token=None)[:2] == (200, {"status": "ok"})
    status, doc, _ = c.json("GET", "/readyz", token=None)
    assert (status, doc) == (200, {"status": "ready"})


def test_not_ready_when_the_data_directory_is_not_writable(make_server, tmp_path):
    srv, c = make_server()
    (srv.cfg.data_dir / "runs").chmod(0o500)
    try:
        import os
        if os.geteuid() == 0:
            pytest.skip("root ignores directory modes")           # pragma: no cover
        status, doc, _ = c.json("GET", "/readyz", token=None)
        assert status == 503 and doc["failing"] == ["data_dir"]
    finally:
        (srv.cfg.data_dir / "runs").chmod(0o700)


@pytest.mark.parametrize("method,path", [("GET", "/v1/info"), ("GET", "/v1/runs"), ("POST", "/v1/runs"), ("GET", "/v1/runs/r20260101T000000Z-abcdef"), ("DELETE", "/v1/runs/r20260101T000000Z-abcdef"),
                                          ("GET", "/anything"), ("PUT", "/v1/runs")])
def test_every_other_path_answers_401_without_a_token_and_with_a_wrong_one(make_server, method, path):
    srv, c = make_server()
    for token in (None, "wrong-" + TOKEN, TOKEN[:-1], ""):
        status, doc, headers = c.json(method, path, body={} if method == "POST" else None, token=token)
        assert status == 401 and doc["error"] == "unauthenticated" and headers["WWW-Authenticate"].startswith("Bearer")


def test_a_basic_scheme_or_a_token_in_the_query_is_not_accepted(make_server):
    srv, c = make_server()
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
    try:
        conn.request("GET", "/v1/info", headers={"Authorization": "Basic " + TOKEN})
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 401
    finally:
        conn.close()
    assert c.json("GET", "/v1/info?token=" + TOKEN, token=None)[0] == 401


def test_info_lists_plans_and_the_target(make_server):
    srv, c = make_server()
    status, doc, headers = c.json("GET", "/v1/info")
    assert status == 200 and set(doc["plans"]) == {"demo", "browser", "robot", "robot-not-enforced"} and "fixture app" in doc["target"] and "CORROBORATED" in doc["target"]
    assert headers["Cache-Control"] == "no-store" and "Server" in headers and "Python" not in headers["Server"]


def test_a_run_goes_through_its_lifecycle_and_leaves_evidence_and_output(make_server):
    srv, c = make_server()
    status, rec, headers = c.json("POST", "/v1/runs", {"plan": "demo", "defect": "none"})
    assert status == 202 and headers["Location"] == "/v1/runs/" + rec["id"]
    finish(srv)
    status, rec, _ = c.json("GET", "/v1/runs/" + rec["id"])
    assert rec["state"] == "finished" and rec["exit_code"] == 0 and rec["outcome"] == "VERIFIED" and rec["bundle"] == rec["id"]
    assert b"VERIFIED" in c.call("GET", f"/v1/runs/{rec['id']}/output")[1]
    assert (srv.cfg.data_dir / "runs" / rec["id"] / "evidence" / rec["id"] / "bundle-manifest.json").is_file()
    assert [r["id"] for r in c.json("GET", "/v1/runs")[1]["runs"]] == [rec["id"]]


def test_the_command_gets_the_plan_the_defect_and_no_variable_of_the_service(make_server):
    srv, c = make_server()
    rec = c.json("POST", "/v1/runs", {"plan": "browser", "defect": "settings"})[1]
    finish(srv)
    manifest = json.loads(next((srv.cfg.data_dir / "runs" / rec["id"] / "evidence").glob("*/bundle-manifest.json")).read_text())
    argv, env = manifest["argv"], manifest["env"]
    assert argv[0] == "run" and argv[1].endswith("golden-plan.json") and argv[argv.index("--defect") + 1] == "settings"
    assert not [k for k in env if k.startswith("QA_SERVICE")] and "QA_SERVICE_TOKEN" not in env
    assert c.json("GET", "/v1/runs/" + rec["id"])[1]["outcome"] == "FAILED"


def test_report_verify_and_bundle_download(make_server):
    srv, c = make_server()
    rec = c.json("POST", "/v1/runs", {})[1]
    finish(srv)
    base = "/v1/runs/" + rec["id"]
    status, body, headers = c.call("GET", base + "/report?format=html")
    assert status == 200 and headers["Content-Type"].startswith("text/html") and "default-src 'none'" in headers["Content-Security-Policy"] and b"<html>" in body
    assert c.call("GET", base + "/report")[1] == b"report text\n"
    assert set(c.json("GET", base + "/report?format=json")[1]) == {"summary", "recomputation", "files"}
    assert c.json("GET", base + "/report?format=pdf")[0] == 400
    status, doc, _ = c.json("GET", base + "/verify")
    assert status == 200 and doc["exit_code"] == 0 and doc["result"]["ok"] is True
    status, body, headers = c.call("GET", base + "/bundle.tar")
    assert status == 200 and headers["Content-Type"] == "application/x-tar"
    import io, tarfile
    names = tarfile.open(fileobj=io.BytesIO(body)).getnames()
    assert f"{rec['id']}/bundle-manifest.json" in names


def test_one_run_at_a_time(make_server):
    srv, c = make_server(control={"sleep": 1.5})
    first = c.json("POST", "/v1/runs", {"plan": "demo"})
    assert first[0] == 202
    status, doc, _ = c.json("POST", "/v1/runs", {"plan": "demo"})
    assert status == 409 and doc["error"] == "busy"
    assert c.json("DELETE", "/v1/runs/" + first[1]["id"])[0] == 409
    assert c.call("GET", f"/v1/runs/{first[1]['id']}/report")[0] == 409           # no evidence yet
    finish(srv)
    assert c.json("POST", "/v1/runs", {"plan": "demo"})[0] == 202
    finish(srv)


def test_bad_requests_are_refused_before_anything_starts(make_server):
    srv, c = make_server()
    for body in ({"plan": "../../etc/passwd"}, {"plan": "nope"}, {"defect": "x"}, {"plan": 3}, {"target": "http://example.org"}, {"plan": "demo", "extra": 1}):
        assert c.json("POST", "/v1/runs", body)[0] == 400, body
    assert c.json("POST", "/v1/runs", raw=b"not json")[0] == 400
    assert c.json("POST", "/v1/runs", raw=b"[1]")[0] == 400
    assert c.json("POST", "/v1/runs", raw=b"{" + b" " * 5000 + b"}")[0] == 413
    assert c.json("GET", "/v1/runs")[1]["runs"] == []


def test_run_ids_cannot_escape_the_data_directory(make_server):
    srv, c = make_server()
    for path in ("/v1/runs/..", "/v1/runs/../../etc", "/v1/runs/r20260101T000000Z-abcdef/../../x", "/v1/runs/%2e%2e%2f", "/v1/runs/r20260101T000000Z-abcdef/bundle"):
        assert c.json("GET", path)[0] == 404, path
    with pytest.raises(KeyError):
        srv.store.get("../x")


@pytest.mark.parametrize("facts,plans,code", [
    (dict(machine="aarch64"), ["demo", "browser", "robot", "robot-not-enforced"], "ARCHITECTURE_UNSUPPORTED"),
    (dict(system="darwin"), ["demo", "browser"], "ARCHITECTURE_UNSUPPORTED"),
    (dict(missing_packages=("playwright", "robot")), ["demo", "browser", "robot", "robot-not-enforced"], "LANE_ENGINE_MISSING"),
    (dict(browser={"status": "FAIL", "message": "the browser is not the pinned build"}), ["demo", "browser"], "BROWSER_UNAVAILABLE"),
    (dict(robot_layers={"ok": False, "reason": "landlock-network-rules-unavailable", "message": "this host reports 0"}), ["demo", "robot"], "ROBOT_EGRESS_LAYERS_UNAVAILABLE"),
])
def test_a_plan_that_cannot_run_here_is_unavailable_with_a_code_a_reason_and_a_remedy_in_info_and_refused_at_start(make_server, facts, plans, code):
    from qa_service.capabilities import Facts
    srv, c = make_server(facts=Facts(**facts))
    info = c.json("GET", "/v1/info")[1]
    for plan in plans:
        entry = info["plans"][plan]
        assert entry["available"] is False and entry["unavailable"]["code"] == code and entry["unavailable"]["reason"] and entry["unavailable"]["remedy"], entry
        status, doc, _ = c.json("POST", "/v1/runs", {"plan": plan})
        assert status == 422 and doc["error"] == "plan_unavailable" and doc["unavailable"]["code"] == code and doc["message"] == doc["unavailable"]["reason"]
    assert c.json("GET", "/v1/runs")[1]["runs"] == [], "a refused run leaves no record and starts nothing"
    assert info["capabilities"]["machine"] == facts.get("machine", "x86_64")


def test_only_the_plans_that_need_a_missing_capability_are_unavailable(make_server):
    from qa_service.capabilities import Facts
    srv, c = make_server(facts=Facts(robot_layers={"ok": False, "reason": "landlock-network-rules-unavailable", "message": "ABI 0"}))
    plans = c.json("GET", "/v1/info")[1]["plans"]
    assert {k: v["available"] for k, v in plans.items()} == {"demo": False, "robot": False, "browser": True, "robot-not-enforced": True}
    assert plans["browser"]["unavailable"] is None
    rec = c.json("POST", "/v1/runs", {"plan": "robot-not-enforced"})
    assert rec[0] == 202
    assert wait_idle(srv.store, 20)


def test_a_missing_plan_file_is_unavailable_not_a_crash(make_server, tmp_path):
    srv, c = make_server()
    (tmp_path / "plans" / "golden-plan.json").unlink()
    assert c.json("GET", "/v1/info")[1]["plans"]["browser"]["unavailable"]["code"] == "PLAN_FILE_MISSING"
    assert c.json("POST", "/v1/runs", {"plan": "browser"})[1]["unavailable"]["code"] == "PLAN_FILE_MISSING"


def test_the_facts_are_collected_from_the_machine_and_the_runners_own_probe_decides_the_layers(monkeypatch):
    from qa_service import capabilities as caps
    monkeypatch.setattr(caps.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(caps.platform, "system", lambda: "Linux")
    monkeypatch.setattr(caps, "_have", lambda name: True)
    ok = caps.collect(lambda: {"browser": {"status": "OK", "message": ""}, "robot_layers": {"ok": True}})
    assert (ok.system, ok.machine, ok.missing_packages) == ("linux", "x86_64", ()) and caps.unavailable("demo", ok, None) is None
    nolayers = caps.collect(lambda: {"robot_layers": {"ok": False, "reason": "x", "message": "y"}})
    assert caps.unavailable("demo", nolayers, None)["code"] == "ROBOT_EGRESS_LAYERS_UNAVAILABLE"
    unmeasured = caps.collect(lambda: {})
    assert caps.unavailable("robot", unmeasured, None)["code"] == "ROBOT_EGRESS_LAYERS_UNAVAILABLE" and "not-measured" in caps.unavailable("robot", unmeasured, None)["reason"]
    monkeypatch.setattr(caps.platform, "machine", lambda: "arm64")
    assert caps.collect(lambda: {"robot_layers": {"ok": True}}).machine == "arm64"


def test_a_run_that_exceeds_the_timeout_is_killed_and_said_so(make_server, tmp_path):
    srv, c = make_server(control={"sleep": 60}, QA_SERVICE_RUN_TIMEOUT="10")
    rec = c.json("POST", "/v1/runs", {})[1]
    assert wait_idle(srv.store, 30)
    doc = c.json("GET", "/v1/runs/" + rec["id"])[1]
    assert doc["state"] == "timed_out" and doc["exit_code"] is None and "QA_SERVICE_RUN_TIMEOUT" in doc["note"]


def test_delete_removes_a_finished_run(make_server):
    srv, c = make_server()
    rec = c.json("POST", "/v1/runs", {})[1]
    finish(srv)
    assert c.call("DELETE", "/v1/runs/" + rec["id"])[0] == 204
    assert c.json("GET", "/v1/runs/" + rec["id"])[0] == 404
    assert not (srv.cfg.data_dir / "runs" / rec["id"]).exists()


def test_a_restart_marks_a_run_that_was_going_as_interrupted_and_keeps_finished_ones(make_server, tmp_path):
    srv, c = make_server()
    done = c.json("POST", "/v1/runs", {})[1]
    finish(srv)
    ghost = srv.cfg.data_dir / "runs" / "r20260101T000000Z-abcdef"
    ghost.mkdir()
    (ghost / "status.json").write_text(json.dumps({"id": ghost.name, "state": "running", "plan": "demo", "defect": "none"}))
    store = RunStore(srv.cfg)
    assert store.get(ghost.name)["state"] == "interrupted" and "stopped" in store.get(ghost.name)["note"]
    assert store.get(done["id"])["state"] == "finished"


def test_the_token_is_never_logged(make_server, capfd):
    srv, c = make_server()
    c.json("GET", "/v1/info")
    c.json("GET", "/v1/info", token="wrong-" + TOKEN)
    time.sleep(0.2)
    err = capfd.readouterr().err
    assert '"status": 200' in err and '"status": 401' in err and TOKEN not in err


def test_a_slow_client_does_not_hold_the_server(make_server):
    srv, c = make_server()
    s = socket.create_connection(("127.0.0.1", srv.server_address[1]))
    s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")            # never finished
    assert c.json("GET", "/healthz", token=None)[0] == 200
    s.close()


def test_the_probe_code_reports_the_runners_own_checks_as_json(tmp_path):
    """PROBE_CODE is what the image runs; here against a stand-in `qa_runner` so the shape of what it prints is pinned without a browser or a kernel."""
    import subprocess, sys, textwrap
    from qa_service import capabilities as caps
    pkg = tmp_path / "qa_runner"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "doctor.py").write_text(textwrap.dedent("""
        class _C:
            status = "OK"
            detail = "pinned"
        def check_browser_pin():
            return _C()
    """))
    (pkg / "netfence.py").write_text("def probe():\n    return {'ok': False, 'reason': 'landlock-network-rules-unavailable', 'message': 'ABI 0'}\n")
    done = subprocess.run([sys.executable, "-c", caps.PROBE_CODE], capture_output=True, text=True, cwd=str(tmp_path), env={"PYTHONPATH": str(tmp_path), "PATH": "/usr/bin:/bin"}, timeout=30)
    assert json.loads(done.stdout) == {"browser": {"status": "OK", "message": "pinned"}, "robot_layers": {"ok": False, "reason": "landlock-network-rules-unavailable", "message": "ABI 0"}}


def test_the_probe_does_not_receive_the_services_environment(monkeypatch, tmp_path):
    import subprocess
    from qa_service import capabilities as caps
    seen = {}
    monkeypatch.setattr(caps, "_have", lambda name: True)
    monkeypatch.setenv("QA_SERVICE_TOKEN", "must-not-travel-" + "x" * 30)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw")

    class Done:
        stdout = "{}"

    def fake_run(argv, **kw):
        seen.update(kw["env"])
        return Done()

    monkeypatch.setattr(subprocess, "run", fake_run)
    caps.run_probe()
    assert "QA_SERVICE_TOKEN" not in seen and seen["PLAYWRIGHT_BROWSERS_PATH"] == "/opt/pw"
