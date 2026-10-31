# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Stand-in workload images: the server (run in process on loopback) and the deterministic build-context generator."""
import ast
import http.client
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from redevops_qa_checks.standin import builder as B
from redevops_qa_checks.standin import server as S

PKG = Path(__file__).resolve().parents[1]
ENTRY = {"name": "registry.example.test/team/web", "tag": "1.0.0", "port": 8080, "health_path": "/health"}


@pytest.fixture
def serve():
    started = []

    def _serve(health="/health"):
        srv = S.make_server(0, health, host="127.0.0.1")
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        started.append((srv, t))
        return srv.server_address[1]
    yield _serve
    for srv, t in started:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)


def call(port, method="GET", path="/", headers=None, body=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, dict(r.getheaders()), data


def test_the_health_path_answers_ok(serve):
    port = serve("/healthz")
    status, hdr, body = call(port, path="/healthz")
    assert (status, body) == (200, b"ok")
    status, hdr, body = call(port, path="/healthz?probe=1")
    assert (status, body) == (200, b"ok")


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_every_other_request_is_echoed_with_method_path_and_headers(serve, method):
    port = serve()
    status, hdr, body = call(port, method, "/api/v1/items?x=1", headers={"X-Forwarded-Prefix": "/app", "X-Custom": "a"}, body=b"hello" if method in ("POST", "PUT", "PATCH") else None)
    doc = json.loads(body)
    assert status == 200 and doc["method"] == method and doc["path"] == "/api/v1/items?x=1"
    assert doc["headers"]["x-forwarded-prefix"] == "/app" and doc["headers"]["x-custom"] == "a" and "host" in doc["headers"]
    assert doc["body_length"] == (5 if method in ("POST", "PUT", "PATCH") else 0)


def test_a_rewritten_path_is_visible_in_what_the_server_echoes(serve):
    port = serve()
    assert json.loads(call(port, "GET", "/internal/v2/resource")[2])["path"] == "/internal/v2/resource"


def test_head_returns_no_body_and_a_zero_content_length(serve):
    port = serve()
    status, hdr, body = call(port, "HEAD", "/x")
    assert status == 200 and body == b"" and hdr["Content-Length"] == "0"


def test_repeated_headers_are_joined_and_names_are_lower_cased(serve):
    port = serve()
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.putrequest("GET", "/x")
    c.putheader("X-A", "1")
    c.putheader("x-a", "2")
    c.endheaders()
    doc = json.loads(c.getresponse().read())
    c.close()
    assert doc["headers"]["x-a"] == "1, 2"


def test_a_large_body_is_bounded(serve):
    port = serve()
    status, hdr, body = call(port, "POST", "/x", body=b"x" * (S.MAX_BODY + 10))
    assert status == 200 and json.loads(body)["body_length"] == S.MAX_BODY


def test_the_server_module_imports_only_the_standard_library_and_makes_no_outgoing_connection():
    tree = ast.parse((PKG / "src/redevops_qa_checks/standin/server.py").read_text(encoding="utf-8"))
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            mods.add((n.module or "").split(".")[0])
    assert mods == {"json", "os", "sys", "http"}
    text = (PKG / "src/redevops_qa_checks/standin/server.py").read_text(encoding="utf-8")
    assert "create_connection" not in text and "urlopen" not in text and ".connect(" not in text


def test_the_server_script_refuses_a_bad_configuration():
    env = {"PATH": "/usr/bin:/bin", "STANDIN_PORT": "99999", "STANDIN_HEALTH_PATH": "/h"}
    r = subprocess.run([sys.executable, "-B", str(PKG / "src/redevops_qa_checks/standin/server.py")], env=env, capture_output=True, timeout=30)
    assert r.returncode == 2
    env = {"PATH": "/usr/bin:/bin", "STANDIN_PORT": "8080", "STANDIN_HEALTH_PATH": "health"}
    assert subprocess.run([sys.executable, "-B", str(PKG / "src/redevops_qa_checks/standin/server.py")], env=env, capture_output=True, timeout=30).returncode == 2


# -- the builder ----------------------------------------------------------------------------------------------------------------------

def test_a_context_has_a_pinned_base_a_non_root_user_and_the_server_verbatim():
    ctx = B.build_contexts([ENTRY])[0]
    df = ctx["files"]["Dockerfile"].decode()
    assert df.splitlines()[0] == "FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"
    assert "USER 10001" in df and "ENV STANDIN_PORT=8080" in df and "ENV STANDIN_HEALTH_PATH=/health" in df and "latest" not in df
    assert ctx["files"]["server.py"] == (PKG / "src/redevops_qa_checks/standin/server.py").read_bytes()
    assert ctx["image"] == "registry.example.test/team/web:1.0.0" and ctx["image_digest"] is None and "never pushed" in ctx["image_digest_note"]
    assert json.loads(ctx["files"]["config.json"]) == {"health_path": "/health", "name": ENTRY["name"], "port": 8080, "tag": "1.0.0"}


def test_the_context_hash_is_deterministic_and_depends_on_every_field():
    a = B.build_contexts([ENTRY])[0]["context_sha256"]
    assert B.build_contexts([dict(ENTRY)])[0]["context_sha256"] == a
    for change in ({"port": 8081}, {"tag": "1.0.1"}, {"health_path": "/healthz"}, {"name": "registry.example.test/team/api"}):
        assert B.build_contexts([{**ENTRY, **change}])[0]["context_sha256"] != a


def test_the_context_hash_is_identical_across_hash_seeds():
    code = ("from redevops_qa_checks.standin.builder import build_contexts; "
            "print(build_contexts([{'name': 'a/b', 'tag': '1', 'port': 80, 'health_path': '/h'}, {'name': 'c', 'tag': '2', 'port': 81, 'health_path': '/g'}])[1]['context_sha256'])")
    outs = set()
    for seed in ("0", "1", "random"):
        r = subprocess.run([sys.executable, "-B", "-c", code], env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": seed, "PYTHONPATH": str(PKG / "src")},
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr
        outs.add(r.stdout.strip())
    assert len(outs) == 1


def test_the_order_of_the_entries_is_kept_and_each_has_its_own_context():
    entries = [{**ENTRY, "name": f"app-{i}", "port": 8000 + i} for i in range(3)]
    out = B.build_contexts(entries)
    assert [c["image"] for c in out] == ["app-0:1.0.0", "app-1:1.0.0", "app-2:1.0.0"] and len({c["context_sha256"] for c in out}) == 3


@pytest.mark.parametrize("bad", [
    {"tag": "latest"}, {"tag": ""}, {"tag": "a b"}, {"tag": "x" * 200}, {"port": 0}, {"port": 65536}, {"port": "80"}, {"port": True}, {"port": 80.0},
    {"health_path": "health"}, {"health_path": "/a b"}, {"health_path": "/x\n"}, {"health_path": "/" + "a" * 101}, {"health_path": ""},
    {"name": ""}, {"name": "UPPER"}, {"name": "a b"}, {"name": "../x"}, {"name": "-x"}, {"name": "a" * 129}, {"name": 5},
])
def test_a_malformed_entry_is_refused(bad):
    with pytest.raises(B.StandInRefused):
        B.build_contexts([{**ENTRY, **bad}])


@pytest.mark.parametrize("entries", [[], None, "x", [ENTRY, ENTRY], [{**ENTRY, "extra": 1}], [{"name": "a"}], [dict(ENTRY)] * 33,
                                     [{k: v for k, v in ENTRY.items() if k != "port"}]])
def test_a_malformed_entry_list_is_refused(entries):
    with pytest.raises(B.StandInRefused):
        B.build_contexts(entries)


def test_writing_contexts_needs_an_existing_empty_directory_and_never_touches_anything_else(tmp_path):
    dest = tmp_path / "out"
    with pytest.raises(B.StandInRefused):
        B.write_contexts([ENTRY], dest)
    dest.mkdir()
    (dest / "keep.txt").write_text("x", encoding="utf-8")
    with pytest.raises(B.StandInRefused):
        B.write_contexts([ENTRY], dest)
    assert sorted(p.name for p in dest.iterdir()) == ["keep.txt"]
    dest2 = tmp_path / "out2"
    dest2.mkdir()
    paths = B.write_contexts([ENTRY, {**ENTRY, "name": "api", "port": 9090}], dest2)
    assert [p.name for p in paths] == ["00-registry.example.test_team_web_1.0.0", "01-api_1.0.0"]
    assert sorted(f.name for f in paths[0].iterdir()) == ["Dockerfile", "config.json", "server.py"]


def test_the_builder_has_no_registry_or_network_or_process_code():
    tree = ast.parse((PKG / "src/redevops_qa_checks/standin/builder.py").read_text(encoding="utf-8"))
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.level == 0:
            mods.add((n.module or "").split(".")[0])
    assert mods <= {"__future__", "json", "re", "pathlib", "typing"}
    text = (PKG / "src/redevops_qa_checks/standin/builder.py").read_text(encoding="utf-8")
    for word in ("subprocess", "socket", "urllib", "requests", "docker push", "skopeo", "crane", "os.system"):
        assert word not in text
