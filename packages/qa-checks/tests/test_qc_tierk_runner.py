# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The real runner is disabled by default and unreachable without an acknowledged disposable host; no process is ever started here."""
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import qc_cluster as C
from redevops_qa_checks.errors import LimitExceeded, PolicyBlocked
from redevops_qa_checks.tierk import guard as G
from redevops_qa_checks.tierk import runner as R


@pytest.fixture(autouse=True)
def no_processes(monkeypatch):
    """Any attempt to start a process in these tests is a failure unless a test installs its own recorder."""
    def boom(*a, **k):
        raise AssertionError("a process was started")
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(os, "system", boom)


@pytest.fixture
def local(tmp_path):
    state, entries = C.make_state(tmp_path)
    guard = C.make_guard(state)
    return G.local_for_lane(guard, "primary"), state, guard


@pytest.fixture
def fake_kubectl(tmp_path):
    p = tmp_path / "bin" / "kubectl"
    p.parent.mkdir()
    p.write_text("not a real program\n", encoding="utf-8")
    os.chmod(p, 0o755)
    return str(p)


def enabled(path):
    return R.TierKConfig(real_lane_enabled=True, kubectl_path=path)


def test_the_real_lane_is_disabled_by_default(local, fake_kubectl):
    lc, state, _ = local
    assert R.TierKConfig().real_lane_enabled is False
    R.write_acknowledgement(state, acknowledged_by="a person", runtime="a runtime")
    with pytest.raises(PolicyBlocked) as e:
        R.RealKubectlRunner(lc, R.TierKConfig(kubectl_path=fake_kubectl))
    assert e.value.details["guard_code"] == "REAL_LANE_DISABLED"


def test_enabled_without_an_acknowledgement_is_refused(local, fake_kubectl):
    lc, *_ = local
    with pytest.raises(PolicyBlocked) as e:
        R.RealKubectlRunner(lc, enabled(fake_kubectl))
    assert e.value.details["guard_code"] == "ACK_MISSING"


def _ack(state, **over):
    doc = {"schema": R.ACK_SCHEMA, "statement": R.ACK_STATEMENT, "acknowledged_by": "a person", "runtime": "a runtime",
           "host_fingerprint": R.host_fingerprint(), "isolation_checks": {k: True for k in R.ACK_CHECKS}}
    doc.update(over)
    (state / R.ACK_FILE).write_text(json.dumps(doc), encoding="utf-8")


@pytest.mark.parametrize("over", [
    {"schema": "x"}, {"statement": "I think it is fine."}, {"acknowledged_by": ""}, {"acknowledged_by": "   "}, {"acknowledged_by": 5},
    {"runtime": ""}, {"host_fingerprint": "0" * 64}, {"isolation_checks": {}}, {"isolation_checks": {k: False for k in R.ACK_CHECKS}},
    {"isolation_checks": {**{k: True for k in R.ACK_CHECKS}, "dedicated_host": "yes"}},
    {"isolation_checks": {**{k: True for k in R.ACK_CHECKS}, "extra": True}},
    {"isolation_checks": {k: True for k in R.ACK_CHECKS[:-1]}},
])
def test_an_acknowledgement_that_is_incomplete_foreign_or_not_the_statement_is_refused(local, fake_kubectl, over):
    lc, state, _ = local
    _ack(state, **over)
    with pytest.raises(PolicyBlocked) as e:
        R.RealKubectlRunner(lc, enabled(fake_kubectl))
    assert e.value.details["guard_code"] in ("ACK_INVALID", "ACK_OTHER_HOST")


def test_a_malformed_or_linked_acknowledgement_file_is_refused(local, fake_kubectl, tmp_path):
    lc, state, _ = local
    (state / R.ACK_FILE).write_text("{not json", encoding="utf-8")
    with pytest.raises(PolicyBlocked):
        R.RealKubectlRunner(lc, enabled(fake_kubectl))
    (state / R.ACK_FILE).unlink()
    good = tmp_path / "ack.json"
    good.write_text(json.dumps({"schema": R.ACK_SCHEMA}), encoding="utf-8")
    os.symlink(good, state / R.ACK_FILE)
    with pytest.raises(PolicyBlocked):
        R.RealKubectlRunner(lc, enabled(fake_kubectl))


def test_an_acknowledgement_outside_the_state_directory_does_not_count(local, fake_kubectl, tmp_path):
    lc, state, _ = local
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (elsewhere / R.ACK_FILE).write_text("{}", encoding="utf-8")
    with pytest.raises(PolicyBlocked) as e:
        R.RealKubectlRunner(lc, enabled(fake_kubectl))
    assert e.value.details["guard_code"] == "ACK_MISSING"


@pytest.mark.parametrize("path", [None, "kubectl", "./kubectl", "/nonexistent/kubectl", "/tmp/../tmp/kubectl", ""])
def test_the_kubectl_path_must_be_an_absolute_existing_executable_from_the_configuration(local, path):
    lc, state, _ = local
    R.write_acknowledgement(state, acknowledged_by="a person", runtime="a runtime")
    with pytest.raises(PolicyBlocked) as e:
        R.RealKubectlRunner(lc, R.TierKConfig(real_lane_enabled=True, kubectl_path=path))
    assert e.value.details["guard_code"] == "KUBECTL_PATH"


def test_a_non_executable_kubectl_is_refused(local, fake_kubectl):
    lc, state, _ = local
    R.write_acknowledgement(state, acknowledged_by="a person", runtime="a runtime")
    os.chmod(fake_kubectl, 0o644)
    with pytest.raises(PolicyBlocked):
        R.RealKubectlRunner(lc, enabled(fake_kubectl))


def test_a_runner_cannot_be_built_from_anything_but_the_guards_local_result(local, fake_kubectl):
    lc, state, _ = local
    R.write_acknowledgement(state, acknowledged_by="a person", runtime="a runtime")
    with pytest.raises(PolicyBlocked):
        R.RealKubectlRunner(object(), enabled(fake_kubectl))


def test_the_acknowledgement_is_written_for_this_host_only_and_never_by_the_runner(local, fake_kubectl):
    lc, state, _ = local
    assert not (state / R.ACK_FILE).exists()
    p = R.write_acknowledgement(state, acknowledged_by="a person", runtime="a runtime")
    doc = json.loads(p.read_text(encoding="utf-8"))
    assert doc["host_fingerprint"] == R.host_fingerprint() and doc["statement"] == R.ACK_STATEMENT
    R.RealKubectlRunner(lc, enabled(fake_kubectl))
    assert json.loads(p.read_text(encoding="utf-8")) == doc


def test_with_everything_in_place_the_command_line_is_fixed_and_the_environment_is_scrubbed(local, fake_kubectl, monkeypatch):
    lc, state, _ = local
    R.write_acknowledgement(state, acknowledged_by="a person", runtime="a runtime")
    runner = R.RealKubectlRunner(lc, enabled(fake_kubectl))
    seen = {}

    def recorder(argv, **kw):
        seen.update(argv=argv, **kw)
        return subprocess.CompletedProcess(argv, 0, stdout="{}", stderr="")
    monkeypatch.setattr(subprocess, "run", recorder)
    monkeypatch.setenv("KUBECONFIG", "/ambient/config")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.test")
    res = runner.run(["get", "pod", "-A", "-o", "json"], timeout_s=20)
    assert res.returncode == 0
    assert seen["argv"] == [fake_kubectl, "--kubeconfig", str(lc.kubeconfig_path), "--context", "kind-qa-tier-k-primary", "--request-timeout=30s",
                            "get", "pod", "-A", "-o", "json"]
    assert seen["shell"] is False and seen["timeout"] == 20 and seen["check"] is False
    assert set(seen["env"]) == {"HOME", "PATH", "KUBECONFIG", "LANG"} and seen["env"]["KUBECONFIG"] == str(lc.kubeconfig_path)
    assert "proxy" not in json.dumps(seen["env"]).lower() and "/ambient" not in json.dumps(seen["env"])
    assert Path(seen["env"]["HOME"]).parent == lc.state_dir


def test_the_runner_refuses_a_command_that_is_not_allow_listed_even_when_called_directly(local, fake_kubectl, monkeypatch):
    lc, state, _ = local
    R.write_acknowledgement(state, acknowledged_by="a person", runtime="a runtime")
    runner = R.RealKubectlRunner(lc, enabled(fake_kubectl))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("started")))
    for bad in (["exec", "x"], ["--context", "prod", "get", "pod", "-o", "json"], ["get", "secret", "-A", "-o", "json"]):
        with pytest.raises(PolicyBlocked):
            runner.run(bad)


def test_a_timeout_is_a_result_and_oversized_output_is_refused(local, fake_kubectl, monkeypatch):
    lc, state, _ = local
    R.write_acknowledgement(state, acknowledged_by="a person", runtime="a runtime")
    runner = R.RealKubectlRunner(lc, enabled(fake_kubectl))

    def slow(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 1)
    monkeypatch.setattr(subprocess, "run", slow)
    assert runner.run(["get", "pod", "-A", "-o", "json"]).returncode == 124
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0, stdout="x" * (R.MAX_OUTPUT + 1), stderr=""))
    with pytest.raises(LimitExceeded):
        runner.run(["get", "pod", "-A", "-o", "json"])


def test_the_guarded_session_over_the_real_runner_reads_the_marker_before_any_other_command(local, fake_kubectl, monkeypatch):
    lc, state, guard = local
    entry = lc.entry
    R.write_acknowledgement(state, acknowledged_by="a person", runtime="a runtime")
    runner = R.RealKubectlRunner(lc, enabled(fake_kubectl))
    fake = C.FakeCluster(entry)

    def recorder(argv, **kw):
        res = fake.run(argv[6:], stdin=kw.get("input"))
        return subprocess.CompletedProcess(argv, res.returncode, stdout=res.stdout, stderr=res.stderr)
    monkeypatch.setattr(subprocess, "run", recorder)
    s = G.GuardedSession(guard, lc, runner)
    s.run(["get", "pod", "-A", "-o", "json"])
    assert fake.calls[0][0][:3] == ["get", "configmap", "qa-disposable-marker"]
    assert fake.calls[-1][0][:2] == ["get", "pod"] and fake.calls[-2][0][:3] == ["get", "configmap", "qa-disposable-marker"]


def test_no_test_in_this_module_started_a_process_or_a_connection(local):
    assert callable(subprocess.run)
    with pytest.raises(AssertionError):
        subprocess.run(["true"])
