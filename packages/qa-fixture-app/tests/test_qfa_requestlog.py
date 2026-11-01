# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Request log content: what was asked is recorded exactly, secrets are not, and nothing in a record depends on the run."""
import http.client
import json

import pytest
import qfa_support as s

from qa_fixture_app import Request, Response, create_server


def _raw(url, method, target, headers=None, body=None):
    host, _, port = url[len("http://"):].partition(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=10)
    try:
        conn.request(method, target, body=body, headers=headers or {})
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


def _lines(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]


def test_the_log_of_the_scenario_equals_the_committed_golden_log(tmp_path):
    log = tmp_path / "requests.jsonl"
    with create_server("none", request_log=str(log)) as server:
        s.run_scenario(server.url)
    assert log.read_bytes() == (s.GOLDEN / "request-log-none.jsonl").read_bytes()


def test_one_record_per_request_in_order_with_the_documented_fields(tmp_path):
    log = tmp_path / "requests.jsonl"
    with create_server("none", request_log=str(log)) as server:
        s.run_scenario(server.url)
        assert server.request_count == len(s.SCENARIO)
    records = _lines(log)
    assert [r["seq"] for r in records] == list(range(1, len(s.SCENARIO) + 1))
    assert [(r["method"], r["target"]) for r in records] == [(m, t) for _, m, t, _ in s.SCENARIO]
    assert all(set(r) == {"seq", "method", "target", "host", "status", "has_cookie", "form_keys", "body_bytes"} for r in records)
    by_step = dict(zip(s.STEP_IDS, records))
    assert by_step["login-ok"]["status"] == 303 and by_step["login-ok"]["form_keys"] == ["email", "password"] and not by_step["login-ok"]["has_cookie"]
    assert by_step["account"]["has_cookie"] is True and by_step["account"]["status"] == 200
    assert by_step["settings-save"]["form_keys"] == ["notifications", "theme"]
    assert by_step["api-order-missing"]["status"] == 404 and by_step["head-health"]["method"] == "HEAD"


def test_no_secret_reaches_the_log(tmp_path):
    log = tmp_path / "requests.jsonl"
    with create_server("none", request_log=str(log)) as server:
        s.run_scenario(server.url)
    text = log.read_text(encoding="utf-8")
    for secret in ("correct horse", "correct+horse", "wrong", "sess-0001", "alice%40example.test", "purple"):
        assert secret not in text, secret


def test_the_host_header_is_recorded_so_a_request_for_another_name_is_visible(tmp_path):
    log = tmp_path / "requests.jsonl"
    with create_server("none", request_log=str(log)) as server:
        own = server.port
        # The connection goes to loopback; only the Host header names another host. Nothing leaves this machine.
        _raw(server.url, "GET", "/health", {"Host": "127.0.0.1:%d" % own})
        _raw(server.url, "GET", "/health", {"Host": "localhost:%d" % own})
        _raw(server.url, "GET", "/health", {"Host": "other.test"})
        _raw(server.url, "GET", "/health", {"Host": "other.test:%d" % (own + 1)})
        _raw(server.url, "GET", "/health", {"Host": "127.0.0.1:%d" % (own + 1)})
    assert [r["host"] for r in _lines(log)] == ["127.0.0.1", "localhost", "other.test", "other.test:%d" % (own + 1), "127.0.0.1:%d" % (own + 1)]


def test_a_proxy_style_request_and_connect_and_odd_methods_are_logged_as_asked(tmp_path):
    log = tmp_path / "requests.jsonl"
    with create_server("none", request_log=str(log)) as server:
        assert _raw(server.url, "GET", "http://other.test/health", {"Host": "other.test"}) == 404
        assert _raw(server.url, "CONNECT", "other.test:443") == 404
        assert _raw(server.url, "DELETE", "/orders/101") == 405
        assert _raw(server.url, "OPTIONS", "/") == 405
    got = [(r["method"], r["target"], r["status"]) for r in _lines(log)]
    assert got == [("GET", "http://other.test/health", 404), ("CONNECT", "other.test:443", 404), ("DELETE", "/orders/101", 405),
                   ("OPTIONS", "/", 405)]


def test_the_log_is_truncated_at_start_and_no_log_means_no_file(tmp_path):
    log = tmp_path / "requests.jsonl"
    log.write_text("old content\n")
    with create_server("none", request_log=str(log)) as server:
        assert log.read_text() == ""
        _raw(server.url, "GET", "/health")
    assert len(_lines(log)) == 1
    quiet = tmp_path / "quiet"
    quiet.mkdir()
    with create_server("none") as server:
        _raw(server.url, "GET", "/health")
        assert server.request_count == 1
    assert list(quiet.iterdir()) == []


def test_the_cli_writes_the_named_log_as_lines_flushed_per_request(tmp_path):
    log = tmp_path / "sub.jsonl"
    with s.spawn(tmp_path, "--request-log", str(log)) as run:
        _raw(run.url, "GET", "/api/orders/101")
        assert _lines(log)[0]["target"] == "/api/orders/101"       # visible while the process is still running
        run.proc.terminate()
        run.proc.wait(timeout=30)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["sub.jsonl"]       # the log is the only file the process ever wrote


def test_the_log_has_unix_line_ends_and_sorted_compact_keys(tmp_path):
    log = tmp_path / "requests.jsonl"
    with create_server("none", request_log=str(log)) as server:
        _raw(server.url, "GET", "/health")
    raw = log.read_bytes()
    assert raw == b'{"body_bytes":0,"form_keys":[],"has_cookie":false,"host":"127.0.0.1","method":"GET","seq":1,"status":200,"target":"/health"}\n'


def test_the_extension_point_serves_an_extra_route_and_logs_it(tmp_path):
    seen = []

    def page(request: Request) -> Response:
        seen.append(request.target)
        return Response.html(200, "Extra", "<h1>Extra</h1>")
    log = tmp_path / "requests.jsonl"
    with create_server("none", request_log=str(log), extra_routes={("GET", "/extra"): page}) as server:
        assert _raw(server.url, "GET", "/extra?x=1") == 200
        assert _raw(server.url, "GET", "/health") == 200
        assert _raw(server.url, "POST", "/extra", body=b"a=1") == 404         # only the (method, path) pair that was registered
    assert seen == ["/extra?x=1"]
    assert [(r["target"], r["status"]) for r in _lines(log)] == [("/extra?x=1", 200), ("/health", 200), ("/extra", 404)]


def test_a_request_is_in_the_log_file_by_the_time_its_response_has_arrived(tmp_path):
    # Regression: the record used to be written after the response, so a reader of the log could miss the latest request.
    log = tmp_path / "requests.jsonl"
    with create_server("none", request_log=str(log)) as server:
        for i in range(1, 101):
            _raw(server.url, "GET", "/health")
            assert server.request_count == i
            assert len(log.read_text(encoding="utf-8").splitlines()) == i
