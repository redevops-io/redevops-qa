# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The process: readiness line, clean shutdown (no orphan, no leftover file), loopback-only binding, refused addresses."""
import json
import os
import signal
import socket
import subprocess
import sys

import pytest
import qfa_support as s

from qa_fixture_app import create_server
from qa_fixture_app.server import NotLoopback, check_loopback


def _port_refuses(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(5)
        return probe.connect_ex(("127.0.0.1", port)) != 0


def test_the_ready_line_is_one_json_line_naming_a_loopback_url_and_the_defect(tmp_path):
    with s.spawn(tmp_path, defect="discount") as run:
        ready = run.ready
        assert ready == {"defect": "discount", "event": "ready", "host": "127.0.0.1", "port": ready["port"],
                         "url": "http://127.0.0.1:%d" % ready["port"]}
        assert ready["port"] > 0
        status = s.run_scenario(run.url, [("h", "GET", "/health", None)])["h"]
        assert b'"status": "ok"' in status and b"discount" not in status
        run.proc.terminate()
        assert run.proc.wait(timeout=30) == 0


@pytest.mark.parametrize("sig", ["SIGTERM", "SIGINT"] + (["SIGHUP"] if hasattr(signal, "SIGHUP") else []))
def test_a_signal_ends_the_process_cleanly_and_leaves_nothing_behind(tmp_path, sig):
    with s.spawn(tmp_path) as run:
        port = run.port
        s.run_scenario(run.url, [("h", "GET", "/health", None), ("o", "GET", "/api/orders", None)])
        run.proc.send_signal(getattr(signal, sig))
        assert run.proc.wait(timeout=30) == 0
        tail = run.proc.stdout.read().splitlines()
        assert [json.loads(x) for x in tail] == [{"event": "stopped", "requests": 2}]
        assert run.proc.stderr.read() == ""
    assert _port_refuses(port)                    # the socket is closed, no process still listens
    assert list(tmp_path.iterdir()) == []         # and nothing was written anywhere (cwd was the temp directory)


def test_closing_standard_input_ends_the_process_when_asked_to(tmp_path):
    with s.spawn(tmp_path, "--shutdown-on-stdin-eof") as run:
        port = run.port
        assert run.proc.poll() is None
        run.proc.stdin.close()
        assert run.proc.wait(timeout=30) == 0
        assert json.loads(run.proc.stdout.read().splitlines()[-1]) == {"event": "stopped", "requests": 0}
    assert _port_refuses(port)


def test_without_the_stdin_option_a_closed_stdin_does_not_end_the_process(tmp_path):
    with s.spawn(tmp_path) as run:
        run.proc.stdin.close()
        with pytest.raises(subprocess.TimeoutExpired):
            run.proc.wait(timeout=1)
        assert s.run_scenario(run.url, [("h", "GET", "/health", None)])["h"]
        run.proc.terminate()
        assert run.proc.wait(timeout=30) == 0


def test_the_app_starts_no_child_process(tmp_path):
    # Linux only has a cheap, exact way to list children; elsewhere the static test (no subprocess import) is the guard.
    if not os.path.exists("/proc/self/task"):
        assert "subprocess" not in "".join(p.read_text() for p in (s.SRC / "qa_fixture_app").glob("*.py"))
        return
    with s.spawn(tmp_path) as run:
        s.run_scenario(run.url, [("h", "GET", "/health", None)])
        children = [t for t in os.listdir("/proc/%d/task" % run.proc.pid)]
        kids = []
        for t in children:
            with open("/proc/%d/task/%s/children" % (run.proc.pid, t)) as f:
                kids += f.read().split()
        assert kids == []
        run.proc.terminate()
        run.proc.wait(timeout=30)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.1", "10.0.0.1", "8.8.8.8", "localhost", "example.com", "", "128.0.0.1",
                                  "169.254.1.1", "::ffff:8.8.8.8", "2001:db8::1", "*"])
def test_an_address_that_is_not_loopback_is_refused_before_anything_is_bound(tmp_path, host):
    out = s.run_cli(["--port", "0", "--host", host], tmp_path)
    assert out.returncode == 2 and out.stdout == "" and "loopback" in out.stderr, (host, out.stderr)
    with pytest.raises(NotLoopback):
        create_server(host=host)


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "127.255.255.254", "::1"])
def test_loopback_literals_pass_the_check(host):
    assert check_loopback(host) == host


def test_the_default_is_ipv4_loopback_on_an_ephemeral_port_choice():
    with create_server() as server:
        assert server.host == "127.0.0.1" and server.port > 0 and server.url == "http://127.0.0.1:%d" % server.port
        assert server._httpd.socket.getsockname() == ("127.0.0.1", server.port)


def test_two_servers_with_port_zero_get_two_different_ports():
    with create_server() as a, create_server() as b:
        assert a.port != b.port


def test_a_port_in_use_is_a_clean_error_not_a_traceback(tmp_path):
    with create_server() as taken:
        out = s.run_cli(["--port", str(taken.port)], tmp_path)
    assert out.returncode == 1 and out.stdout == "" and out.stderr.startswith("error: cannot start") and "Traceback" not in out.stderr


@pytest.mark.parametrize("args", [["--port", "70000"], ["--port", "-1"], ["--defect", "both"], ["--defect", "discount,settings"], ["--bogus"]])
def test_unusable_options_exit_2_without_binding(tmp_path, args):
    out = s.run_cli(args, tmp_path)
    assert out.returncode == 2 and out.stdout == ""


def test_the_process_does_not_listen_on_any_non_loopback_address(tmp_path):
    probe = (
        "import json, socket, sys\n"
        "port = int(sys.argv[1]); cands = set()\n"
        "try:\n    cands.update(socket.gethostbyname_ex(socket.gethostname())[2])\nexcept OSError:\n    pass\n"
        "try:\n    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.connect(('192.0.2.1', 9)); cands.add(u.getsockname()[0]); u.close()\nexcept OSError:\n    pass\n"
        "cands = sorted(c for c in cands if not c.startswith('127.') and c != '0.0.0.0'); connected = []\n"
        "for c in cands:\n"
        "    k = socket.socket(); k.settimeout(3)\n"
        "    if k.connect_ex((c, port)) == 0: connected.append(c)\n"
        "    k.close()\n"
        "print(json.dumps({'candidates': cands, 'connected': connected}))\n")
    with s.spawn(tmp_path) as run:
        out = subprocess.run([sys.executable, "-c", probe, str(run.port)], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        assert out.returncode == 0, out.stderr
        result = json.loads(out.stdout)
        assert result["connected"] == [], result          # every non-loopback address of this host refused the connection
        run.proc.terminate()
        run.proc.wait(timeout=30)


def test_a_failed_start_leaves_no_log_file(tmp_path):
    out = s.run_cli(["--host", "0.0.0.0", "--request-log", str(tmp_path / "x.jsonl")], tmp_path)
    assert out.returncode == 2 and list(tmp_path.iterdir()) == []


def test_list_defects_prints_the_documented_descriptions(tmp_path):
    from qa_fixture_app import DEFECT_DESCRIPTIONS
    out = s.run_cli(["--list-defects"], tmp_path)
    assert out.returncode == 0 and json.loads(out.stdout) == DEFECT_DESCRIPTIONS


def test_the_console_script_and_module_entry_point_are_the_same_function():
    from qa_fixture_app import cli
    text = (s.PKG / "pyproject.toml").read_text()
    assert 'redevops-qa-fixture-app = "qa_fixture_app.cli:main"' in text and callable(cli.main)
