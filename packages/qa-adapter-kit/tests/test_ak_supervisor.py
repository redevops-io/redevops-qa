# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import os
import signal
import sys
import threading
import time

import pytest

from ak_support import dirs, pid_gone, wait_for_file
from qa_adapter_kit import CancelToken, CommandSpec, ErrorCode, Limits, PathPolicy, PolicyRefused
from qa_adapter_kit.supervisor import build_env, check_command, run_supervised, sha256_file, verify_pins
from qa_adapter_kit.models import PinnedFile
from qa_adapter_kit.testing.fakes import CHILD, suite_manifest

PY = sys.executable
FAST = Limits(deadline_s=20, output_limit_bytes=65536, kill_grace_s=0.5)
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


def sleep_cmd(seconds=600):
    return [PY, "-I", "-c", f"import time; time.sleep({seconds})"]


# ---------------------------------------------------------------------------------------------- running
def test_a_normal_exit_reports_its_code_and_output(tmp_path):
    out = run_supervised([PY, "-I", "-c", "import sys; print('hi'); sys.stderr.write('err'); sys.exit(3)"], cwd=str(tmp_path), env=ENV, limits=FAST)
    assert (out.exit_code, out.stdout.strip(), out.stderr, out.error_code) == (3, b"hi", b"err", None)


def test_a_signal_death_is_reported_as_a_signal_not_an_exit_code(tmp_path):
    out = run_supervised([PY, "-I", "-c", "import os,signal; os.kill(os.getpid(), signal.SIGABRT)"], cwd=str(tmp_path), env=ENV, limits=FAST)
    assert out.exit_code is None and out.signal == signal.SIGABRT


def test_the_deadline_ends_the_run_and_the_whole_process_group(tmp_path):
    ws, out_dir = dirs(tmp_path)
    t0 = time.monotonic()
    out = run_supervised([PY, "-I", CHILD, "child_tree", str(out_dir)], cwd=str(ws), env=ENV, limits=Limits(deadline_s=1.0, kill_grace_s=0.5, output_limit_bytes=65536))
    assert out.error_code is ErrorCode.TIMEOUT and out.group_terminated and time.monotonic() - t0 < 8
    pid_file = out_dir / "grandchild.pid"
    assert wait_for_file(pid_file) and pid_gone(int(pid_file.read_text()))


def test_cancellation_ends_the_run_and_the_whole_process_group(tmp_path):
    ws, out_dir = dirs(tmp_path)
    token = CancelToken()
    box = {}
    thread = threading.Thread(target=lambda: box.setdefault("o", run_supervised([PY, "-I", CHILD, "child_tree", str(out_dir)], cwd=str(ws), env=ENV,
                                                                               limits=FAST, cancel=token)))
    thread.start()
    pid_file = out_dir / "grandchild.pid"
    assert wait_for_file(pid_file)
    token.cancel()
    thread.join(10)
    assert not thread.is_alive() and box["o"].error_code is ErrorCode.CANCELLED
    assert pid_gone(int(pid_file.read_text()))


def test_a_cancel_set_before_the_start_still_ends_the_run(tmp_path):
    token = CancelToken()
    token.cancel()
    out = run_supervised(sleep_cmd(), cwd=str(tmp_path), env=ENV, limits=FAST, cancel=token)
    assert out.error_code is ErrorCode.CANCELLED


def test_a_process_that_ignores_the_terminate_signal_is_killed_after_the_grace_period(tmp_path):
    ws, out_dir = dirs(tmp_path)
    t0 = time.monotonic()
    out = run_supervised([PY, "-I", CHILD, "ignore_term", str(out_dir)], cwd=str(ws), env=ENV,
                         limits=Limits(deadline_s=1.0, kill_grace_s=0.5, output_limit_bytes=65536))
    assert out.error_code is ErrorCode.TIMEOUT and out.signal == signal.SIGKILL and time.monotonic() - t0 < 8


@pytest.mark.parametrize("scenario", ["spam", "spam_stderr"])
def test_output_over_the_limit_ends_the_run_and_is_cut_at_the_limit(tmp_path, scenario):
    ws, out_dir = dirs(tmp_path)
    out = run_supervised([PY, "-I", CHILD, scenario, str(out_dir)], cwd=str(ws), env=ENV,
                         limits=Limits(deadline_s=20, output_limit_bytes=1000, kill_grace_s=0.5))
    assert out.error_code is ErrorCode.OUTPUT_LIMIT
    assert len(out.stdout) <= 1000 and len(out.stderr) <= 1000


def test_a_group_member_that_outlives_the_leader_is_killed(tmp_path):
    ws, out_dir = dirs(tmp_path)
    out = run_supervised([PY, "-I", CHILD, "orphan_after_exit", str(out_dir)], cwd=str(ws), env=ENV, limits=FAST)
    assert out.exit_code == 0 and out.error_code is None
    pid_file = out_dir / "grandchild.pid"
    assert wait_for_file(pid_file) and pid_gone(int(pid_file.read_text()))


def test_a_missing_executable_is_a_spawn_failure_not_an_exception(tmp_path):
    out = run_supervised([str(tmp_path / "nope")], cwd=str(tmp_path), env=ENV, limits=FAST)
    assert out.error_code is ErrorCode.SPAWN_FAILED and out.exit_code is None


def test_the_child_has_no_stdin(tmp_path):
    out = run_supervised([PY, "-I", "-c", "import sys; print(repr(sys.stdin.read()))"], cwd=str(tmp_path), env=ENV, limits=FAST)
    assert out.stdout.strip() == b"''"


def test_the_child_leads_its_own_session(tmp_path):
    out = run_supervised([PY, "-I", "-c", "import os; print(os.getpgrp() == os.getpid(), os.getsid(0) == os.getpid())"], cwd=str(tmp_path), env=ENV, limits=FAST)
    assert out.stdout.split() == [b"True", b"True"]


# ---------------------------------------------------------------------------------------------- command checks
@pytest.fixture
def ctx(tmp_path):
    ws, out = dirs(tmp_path)
    return suite_manifest(), PathPolicy([ws, out]), ws


def spec(ws, *argv):
    return CommandSpec(argv=tuple(argv), cwd=str(ws))


def refused(code, manifest, policy, command, sealed=True):
    with pytest.raises(PolicyRefused) as info:
        check_command(manifest, command, policy, sealed=sealed)
    assert info.value.code is code


def test_a_command_inside_the_allowlist_passes(ctx):
    m, p, ws = ctx
    check_command(m, spec(ws, PY, "-I", "-c", "pass"), p, sealed=True)


def test_an_executable_outside_the_allowlist_is_refused(ctx):
    m, p, ws = ctx
    refused(ErrorCode.EXECUTABLE_NOT_ALLOWED, m, p, spec(ws, "/bin/ls"))
    refused(ErrorCode.EXECUTABLE_NOT_ALLOWED, m, p, spec(ws, "python3"))      # relative: resolved through PATH, so not accepted
    refused(ErrorCode.INVALID_REQUEST, m, p, spec(ws))


@pytest.mark.parametrize("exe", ["/usr/bin/docker", "/usr/local/bin/podman", "/opt/x/nerdctl", "/usr/bin/runc", "/x/DOCKER"])
def test_a_container_engine_is_refused_even_when_the_manifest_lists_it(tmp_path, exe):
    ws, out = dirs(tmp_path)
    m = suite_manifest(executables=[exe])
    refused(ErrorCode.DOCKER_REFUSED, m, PathPolicy([ws, out]), spec(ws, exe, "run", "x"), sealed=False)


def test_a_symlink_to_a_container_engine_is_refused(tmp_path):
    ws, out = dirs(tmp_path)
    link = tmp_path / "harmless"
    os.symlink("/usr/bin/docker", link)
    m = suite_manifest(executables=[str(link)])
    refused(ErrorCode.DOCKER_REFUSED, m, PathPolicy([ws, out]), spec(ws, str(link)), sealed=False)


@pytest.mark.parametrize("arg", ["/var/run/docker.sock", "--host=unix:///var/run/docker.sock", "-v=/run/docker.sock:/s", "/x/containerd.sock", "/x/podman.sock"])
def test_the_docker_socket_is_never_handed_to_an_adapter(ctx, arg):
    m, p, ws = ctx
    refused(ErrorCode.DOCKER_REFUSED, m, p, spec(ws, PY, "-I", "-c", "pass", arg), sealed=False)


@pytest.mark.parametrize("arg", ["/etc/passwd", "--config=/home/u/.aws/credentials", "/home/u/.ssh/id_rsa"])
def test_an_argument_naming_a_prohibited_path_is_refused(ctx, arg):
    m, p, ws = ctx
    refused(ErrorCode.PROHIBITED_PATH, m, p, spec(ws, PY, "-I", "-c", "pass", arg), sealed=False)


@pytest.mark.parametrize("exe", ["/usr/bin/pip", "/usr/bin/pip3.12", "/usr/bin/npm", "/usr/bin/npx", "/usr/bin/curl", "/usr/bin/wget",
                                 "/usr/bin/apt-get", "/usr/bin/git", "/usr/bin/uv", "/usr/bin/yarn"])
def test_a_sealed_run_cannot_start_an_installer_or_downloader(tmp_path, exe):
    ws, out = dirs(tmp_path)
    m = suite_manifest(executables=[exe])
    p = PathPolicy([ws, out])
    refused(ErrorCode.DOWNLOAD_REFUSED, m, p, spec(ws, exe, "install", "x"), sealed=True)
    check_command(m, spec(ws, exe, "install", "x"), p, sealed=False)       # outside a sealed run the manifest decides


@pytest.mark.parametrize("module", ["pip", "ensurepip", "venv", "pip._internal"])
def test_a_sealed_run_cannot_run_python_dash_m_an_installer(ctx, module):
    m, p, ws = ctx
    refused(ErrorCode.DOWNLOAD_REFUSED, m, p, spec(ws, PY, "-m", module, "install", "x"))
    check_command(m, spec(ws, PY, "-I", "-m", "json.tool"), p, sealed=True)


def test_an_adapter_that_downloads_cannot_run_sealed(tmp_path):
    ws, out = dirs(tmp_path)
    m = suite_manifest(downloads=True)
    refused(ErrorCode.DOWNLOAD_REFUSED, m, PathPolicy([ws, out]), spec(ws, PY, "-c", "pass"))


def test_a_working_directory_outside_the_allowlist_is_refused(ctx, tmp_path):
    m, p, ws = ctx
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(Exception):
        check_command(m, CommandSpec(argv=(PY,), cwd=str(other)), p, sealed=True)


def test_oversized_and_nul_arguments_are_refused(ctx):
    m, p, ws = ctx
    refused(ErrorCode.INVALID_REQUEST, m, p, spec(ws, PY, "x" * 5000))
    refused(ErrorCode.INVALID_REQUEST, m, p, spec(ws, PY, "a\x00b"))
    refused(ErrorCode.INVALID_REQUEST, m, p, spec(ws, PY, *["a"] * 300))


# ---------------------------------------------------------------------------------------------- pins
def test_pinned_files_are_verified_before_a_sealed_start(tmp_path):
    ws, out = dirs(tmp_path)
    tool = tmp_path / "tool"
    tool.write_text("#!/bin/sh\n")
    pin = PinnedFile(path=str(tool), sha256=sha256_file(str(tool)))
    m = suite_manifest(pinned_files=[pin])
    p = PathPolicy([ws, out])
    check_command(m, spec(ws, PY, "-c", "pass"), p, sealed=True)
    tool.write_text("#!/bin/sh\necho changed\n")
    refused(ErrorCode.PIN_MISMATCH, m, p, spec(ws, PY, "-c", "pass"))
    check_command(m, spec(ws, PY, "-c", "pass"), p, sealed=False)           # pins gate sealed runs
    tool.unlink()
    refused(ErrorCode.PIN_MISMATCH, m, p, spec(ws, PY, "-c", "pass"))


def test_verify_pins_reports_the_file(tmp_path):
    with pytest.raises(PolicyRefused, match="cannot be read"):
        verify_pins(suite_manifest(pinned_files=[PinnedFile(path=str(tmp_path / "gone"), sha256="0" * 64)]))


# ---------------------------------------------------------------------------------------------- environment
def env_for(manifest=None, **kw):
    base = dict(env={}, secret_env={}, extra={}, home="/tmp/h", sealed=True)
    base.update(kw)
    return build_env(manifest or suite_manifest(), **base)


def test_nothing_is_inherited_from_the_parent_environment(monkeypatch):
    monkeypatch.setenv("QA_KIT_PARENT_VALUE", "visible-in-parent")
    monkeypatch.setenv("SOME_API_TOKEN", "parent-credential")
    env = env_for()
    assert "QA_KIT_PARENT_VALUE" not in env and "SOME_API_TOKEN" not in env
    assert env["HOME"] == "/tmp/h" and env["PATH"] == "/usr/bin:/bin"


def test_a_sealed_run_is_told_to_stay_offline():
    assert env_for(sealed=True)["PIP_NO_INDEX"] == "1" and "PIP_NO_INDEX" not in env_for(sealed=False)


def test_only_names_the_manifest_allows_pass():
    m = suite_manifest(env_allowlist=("APP_URL",))
    assert env_for(m, env={"APP_URL": "http://localhost:3000"})["APP_URL"] == "http://localhost:3000"
    with pytest.raises(PolicyRefused) as info:
        env_for(m, env={"OTHER": "x"})
    assert info.value.code is ErrorCode.ENV_REFUSED


@pytest.mark.parametrize("name", ["GH_TOKEN", "GITHUB_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS",
                                  "DOCKER_HOST", "DOCKER_CONFIG", "SSH_AUTH_SOCK", "KUBECONFIG", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES",
                                  "PYTHONPATH", "PATH", "HOME", "PIP_INDEX_URL", "NPM_CONFIG_REGISTRY", "BASH_ENV", "APP_PASSWORD", "MY_API_KEY"])
def test_dangerous_names_are_refused_even_when_the_manifest_allows_them(name):
    m = suite_manifest(env_allowlist=(name,))
    with pytest.raises(PolicyRefused) as info:
        env_for(m, env={name: "x"})
    assert info.value.code is ErrorCode.ENV_REFUSED
    with pytest.raises(PolicyRefused):
        env_for(m, extra={name: "x"})


def test_a_secret_passes_only_as_a_secret_and_only_if_named():
    m = suite_manifest(secret_env_allowlist=("APP_PASSWORD",))
    assert env_for(m, secret_env={"APP_PASSWORD": "abc12345"})["APP_PASSWORD"] == "abc12345"
    with pytest.raises(PolicyRefused):
        env_for(suite_manifest(), secret_env={"APP_PASSWORD": "abc12345"})
    with pytest.raises(PolicyRefused):
        env_for(suite_manifest(env_allowlist=("APP_PASSWORD",)), env={"APP_PASSWORD": "abc12345"})


@pytest.mark.parametrize("name", ["GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "DOCKER_HOST", "LD_PRELOAD"])
def test_cloud_and_loader_variables_are_refused_as_secrets_too(name):
    m = suite_manifest(secret_env_allowlist=(name,))
    with pytest.raises(PolicyRefused):
        env_for(m, secret_env={name: "x12345"})
