# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Determinism: no clock, no randomness, stable order and ids, so output is byte-identical across runs (and, with the committed golden
files, across operating systems), and the app contains nothing that could reach another host."""
import ast
import hashlib
from pathlib import Path

import pytest
import qfa_support as s

from qa_fixture_app import create_server

SRC_FILES = sorted((s.SRC / "qa_fixture_app").glob("*.py"))


def _digest(transcript):
    h = hashlib.sha256()
    for sid in s.STEP_IDS:
        h.update(transcript[sid])
    return h.hexdigest()


@pytest.mark.parametrize("mode", s.MODES)
def test_two_fresh_servers_on_different_ports_give_byte_identical_transcripts(mode):
    with create_server(mode) as a, create_server(mode) as b:
        assert a.port != b.port
        ta, tb = s.run_scenario(a.url), s.run_scenario(b.url)
    assert ta == tb and _digest(ta) == _digest(tb)


@pytest.mark.parametrize("mode", s.MODES)
def test_thirty_consecutive_starts_give_one_digest(mode):
    digests = set()
    for _ in range(30):
        with create_server(mode) as server:
            digests.add(_digest(s.run_scenario(server.url)))
    assert len(digests) == 1


@pytest.mark.parametrize("mode", s.MODES)
def test_two_separate_processes_give_identical_transcripts_and_request_logs(mode, tmp_path):
    results = []
    for n in (1, 2):
        log = tmp_path / ("log%d.jsonl" % n)
        with s.spawn(tmp_path, "--request-log", str(log), defect=mode) as run:
            transcript = s.run_scenario(run.url)
            run.proc.terminate()
            run.proc.wait(timeout=30)
        results.append((transcript, log.read_bytes()))
    assert results[0][0] == results[1][0]
    assert results[0][1] == results[1][1] and results[0][1]
    assert results[0][0] == {sid: s.read_golden(mode)[sid] for sid in s.STEP_IDS}      # and equal to the files committed on another machine


def test_the_session_ids_and_every_response_header_are_stable():
    with create_server("none") as server:
        t = s.run_scenario(server.url)
    assert b"Set-Cookie: sid=sess-0001;" in t["login-ok"]
    for raw in t.values():
        assert b"\nDate:" not in raw and b"\nLast-Modified:" not in raw and b"\nETag:" not in raw and b"\nExpires:" not in raw


def test_ordered_collections_are_sorted():
    with create_server("none") as server:
        t = s.run_scenario(server.url)
    body = t["api-orders"].partition(b"\n\n")[2].decode()
    ids = [int(x) for x in __import__("re").findall(r'"order_id": "(\d+)"', body)]
    assert ids == sorted(ids) == [101, 102, 103, 104]


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
    return names


@pytest.mark.parametrize("path", SRC_FILES, ids=lambda p: p.name)
def test_no_module_imports_a_clock_randomness_or_a_third_party_package(path):
    stdlib = set(__import__("sys").stdlib_module_names)
    imports = {n.split(".")[0] for n in _imports(path)}
    banned = {"time", "datetime", "random", "secrets", "uuid", "tempfile", "sched", "calendar"}
    if path.name == "reference_check.py":
        # the reference check, a client, bounds its own run with a monotonic deadline (nothing it prints depends on the clock); it may import ``time`` and use nothing but ``time.monotonic``
        banned -= {"time"}
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assert {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "time"} == {"monotonic"}
    assert not imports & banned, path
    assert all(n in stdlib or n == "qa_fixture_app" for n in imports), (path, imports)


@pytest.mark.parametrize("path", SRC_FILES, ids=lambda p: p.name)
def test_no_module_opens_an_outbound_connection_or_resolves_a_name(path):
    imports = _imports(path)
    assert not imports & {"ssl", "urllib.request", "smtplib", "ftplib", "telnetlib", "xmlrpc.client", "asyncio", "subprocess"}, path
    tree = ast.parse(path.read_text(encoding="utf-8"))
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not attrs & {"create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex", "urlopen", "connect", "connect_ex", "sendto"}, path
    if path.name != "reference_check.py":
        assert "http.client" not in imports and "HTTPConnection" not in attrs, path


def test_the_only_module_that_is_a_client_talks_loopback_only():
    from qa_fixture_app import reference_check
    for url in ("http://example.com:80", "http://10.0.0.1:80", "https://127.0.0.1:1", "http://127.0.0.1", "http://0.0.0.0:80"):
        with pytest.raises(ValueError):
            reference_check.run_checks(url)
