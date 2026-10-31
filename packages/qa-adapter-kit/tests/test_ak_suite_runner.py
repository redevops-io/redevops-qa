# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The shared runner against the fake suite adapter: every status, cancel, timeout, malformed result, missing artifact and
prohibited path, plus redaction and environment scrubbing."""
import hashlib
import json
import os
import sys
import threading
import time

import pytest

from ak_support import dirs, fresh_secret, pid_gone, request, run, wait_for_file
from qa_adapter_kit import (AdapterClass, AdapterResult, CancelToken, ErrorCode, Limits, Status, SuiteRunner, REDACTED)
from qa_adapter_kit.testing.fakes import FakeSuiteAdapter, interactive_manifest, suite_manifest


# ---------------------------------------------------------------------------------------------- statuses
def test_pass(tmp_path):
    r, _ = run(tmp_path, "pass")
    assert r.status is Status.PASS and r.exit_code == 0 and r.error_code is None and r.authority == "native"
    assert [a.status for a in r.native_assertions] == [Status.PASS] and r.native_assertions[0].declared_assertion_ids == ("A-1",)
    assert r.stdout_tail.strip() == "all good" and r.attempts == 1


def test_fail_with_a_passing_and_a_failing_test(tmp_path):
    r, _ = run(tmp_path, "fail")
    assert r.status is Status.FAIL and r.exit_code == 1 and r.error_code is None
    assert {a.native_id: a.status for a in r.native_assertions} == {"T1": Status.PASS, "T2": Status.FAIL}


def test_a_native_error_is_an_error_with_a_code(tmp_path):
    r, _ = run(tmp_path, "error")
    assert r.status is Status.ERROR and r.error_code is ErrorCode.NATIVE_ERROR and r.native_assertions[0].status is Status.ERROR


def test_skip(tmp_path):
    r, _ = run(tmp_path, "skip")
    assert r.status is Status.SKIP and r.error_code is None


def test_unknown(tmp_path):
    r, _ = run(tmp_path, "unknown")
    assert r.status is Status.UNKNOWN


def test_an_empty_report_is_unknown_never_a_pass(tmp_path):
    r, _ = run(tmp_path, "empty")
    assert r.status is Status.UNKNOWN and r.native_assertions == ()


def test_a_zero_test_zero_exit_run_is_not_a_pass(tmp_path):
    r, _ = run(tmp_path, "empty")
    assert r.status is not Status.PASS


def test_all_passing_but_a_nonzero_exit_is_an_error_not_a_pass(tmp_path):
    r, _ = run(tmp_path, "pass_nonzero_exit")
    assert r.status is Status.ERROR and r.error_code is ErrorCode.NATIVE_ERROR and r.exit_code == 3


def test_a_framework_cannot_report_unverified(tmp_path):
    r, _ = run(tmp_path, "framework_unverified")
    assert r.status is Status.ERROR and r.error_code is ErrorCode.MALFORMED_RESULT


def test_the_result_is_a_valid_model_that_round_trips(tmp_path):
    r, _ = run(tmp_path, "fail")
    assert AdapterResult.from_dict(json.loads(json.dumps(r.to_dict()))) == r


# ---------------------------------------------------------------------------------------------- limits and lifecycle
def test_timeout_is_an_error_and_kills_the_group(tmp_path):
    ws, out = dirs(tmp_path)
    m = suite_manifest(limits=Limits(deadline_s=1.0, kill_grace_s=0.5, output_limit_bytes=65536))
    t0 = time.monotonic()
    r, _ = run(tmp_path, "child_tree", manifest=m)
    assert r.status is Status.ERROR and r.error_code is ErrorCode.TIMEOUT and time.monotonic() - t0 < 10
    pid_file = out / "grandchild.pid"
    assert wait_for_file(pid_file) and pid_gone(int(pid_file.read_text()))


def test_a_request_cannot_raise_its_deadline_above_the_manifests(tmp_path):
    m = suite_manifest(limits=Limits(deadline_s=1.0, kill_grace_s=0.5, output_limit_bytes=65536))
    t0 = time.monotonic()
    r, _ = run(tmp_path, "hang", manifest=m, limits=Limits(deadline_s=600))
    assert r.error_code is ErrorCode.TIMEOUT and time.monotonic() - t0 < 10


def test_a_request_may_lower_its_deadline(tmp_path):
    t0 = time.monotonic()
    r, _ = run(tmp_path, "hang", limits=Limits(deadline_s=0.5, kill_grace_s=0.5))
    assert r.error_code is ErrorCode.TIMEOUT and time.monotonic() - t0 < 10


def test_cancel_is_an_error_and_kills_the_group(tmp_path):
    ws, out = dirs(tmp_path)
    token = CancelToken()
    box = {}
    adapter = FakeSuiteAdapter("child_tree")
    thread = threading.Thread(target=lambda: box.setdefault("r", SuiteRunner(adapter).run(request(tmp_path), token)))
    thread.start()
    pid_file = out / "grandchild.pid"
    assert wait_for_file(pid_file)
    token.cancel()
    thread.join(10)
    assert not thread.is_alive()
    assert box["r"].status is Status.ERROR and box["r"].error_code is ErrorCode.CANCELLED and pid_gone(int(pid_file.read_text()))


@pytest.mark.parametrize("scenario", ["spam", "spam_stderr"])
def test_output_over_the_limit_is_an_error_and_the_tail_is_bounded(tmp_path, scenario):
    r, _ = run(tmp_path, scenario)
    assert r.status is Status.ERROR and r.error_code is ErrorCode.OUTPUT_LIMIT
    assert len(r.stdout_tail) <= 4096 and len(r.stderr_tail) <= 4096


def test_a_start_failure_is_retried_up_to_the_limit_and_then_reported(tmp_path):
    ws, out = dirs(tmp_path)
    ghost = str(tmp_path / "ghost")
    m = suite_manifest(executables=[ghost], limits=Limits(deadline_s=10, max_retries=2, output_limit_bytes=65536))
    r, adapter = run(tmp_path, "pass", manifest=m, adapter_kw=dict(argv_override=[ghost]))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.SPAWN_FAILED and r.attempts == 3


def test_a_failing_run_is_never_retried(tmp_path):
    m = suite_manifest(limits=Limits(deadline_s=10, max_retries=3, output_limit_bytes=65536))
    r, adapter = run(tmp_path, "fail", manifest=m)
    assert r.status is Status.FAIL and r.attempts == 1


def test_a_timeout_is_never_retried(tmp_path):
    m = suite_manifest(limits=Limits(deadline_s=0.5, max_retries=3, kill_grace_s=0.5, output_limit_bytes=65536))
    r, _ = run(tmp_path, "hang", manifest=m)
    assert r.error_code is ErrorCode.TIMEOUT and r.attempts == 1


def test_the_home_directory_is_removed_after_the_run(tmp_path):
    r, _ = run(tmp_path, "env_dump")
    values = json.loads((tmp_path / "output" / "env-values.json").read_text())
    assert r.status is Status.PASS and not os.path.exists(values["HOME"])


# ---------------------------------------------------------------------------------------------- malformed results
@pytest.mark.parametrize("scenario,code", [("malformed", ErrorCode.MALFORMED_RESULT), ("bad_shape", ErrorCode.MALFORMED_RESULT),
                                           ("bad_status", ErrorCode.MALFORMED_RESULT)])
def test_a_malformed_native_report_is_an_error_never_a_pass(tmp_path, scenario, code):
    r, _ = run(tmp_path, scenario)
    assert r.status is Status.ERROR and r.error_code is code and r.native_assertions == ()


def test_a_missing_report_is_an_error(tmp_path):
    r, _ = run(tmp_path, "no_such_scenario")        # the child exits 97 and writes no native report
    assert r.status is Status.ERROR and r.error_code is ErrorCode.MALFORMED_RESULT and r.exit_code == 97


def test_an_adapter_returning_the_wrong_type_is_malformed(tmp_path):
    r, _ = run(tmp_path, "pass", adapter_kw=dict(wrong_return=True))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.MALFORMED_RESULT


def test_an_adapter_bug_is_an_adapter_crash_with_the_class_name_only(tmp_path):
    r, _ = run(tmp_path, "pass", adapter_kw=dict(raise_in_import=True))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.ADAPTER_CRASH
    assert "RuntimeError" in r.error_message and "hunter2" not in r.error_message and "boom" not in r.error_message


# ---------------------------------------------------------------------------------------------- artifacts
def test_a_produced_artifact_is_hashed_and_listed(tmp_path):
    r, _ = run(tmp_path, "good_artifact")
    assert r.status is Status.PASS and len(r.artifacts) == 1
    art = r.artifacts[0]
    assert art.path == "screens/a.txt" and art.size_bytes == 8 and art.sha256 == hashlib.sha256(b"evidence").hexdigest()


def test_a_declared_artifact_that_was_not_produced_is_an_error(tmp_path):
    r, _ = run(tmp_path, "missing_artifact")
    assert r.status is Status.ERROR and r.error_code is ErrorCode.MISSING_ARTIFACT and "missing.png" in r.error_message


@pytest.mark.parametrize("scenario", ["traversal_artifact", "absolute_artifact", "prohibited_artifact"])
def test_an_artifact_on_a_prohibited_path_is_refused(tmp_path, scenario):
    (tmp_path / "escape.txt").write_text("outside")
    r, _ = run(tmp_path, scenario)
    assert r.status is Status.ERROR and r.error_code is ErrorCode.PROHIBITED_PATH and r.artifacts == ()


def test_a_symlink_artifact_that_leaves_the_output_directory_is_refused(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("private")
    r, _ = run(tmp_path, "symlink_artifact", adapter_kw=dict(extra_env={}), env={})
    # the child links to /etc/hosts by default: outside the output directory, and /etc is prohibited
    assert r.status is Status.ERROR and r.error_code is ErrorCode.PROHIBITED_PATH


def test_an_artifact_larger_than_the_limit_is_refused(tmp_path):
    m = suite_manifest(limits=Limits(deadline_s=20, output_limit_bytes=65536, max_artifact_bytes=4, kill_grace_s=0.5))
    r, _ = run(tmp_path, "good_artifact", manifest=m)
    assert r.status is Status.ERROR and r.error_code is ErrorCode.ARTIFACT_REFUSED


# ---------------------------------------------------------------------------------------------- request paths
@pytest.mark.parametrize("kw", [dict(suite_path="nothing/here"), dict(workspace="/etc"), dict(output_dir="/etc"), dict(workspace="/var/run")])
def test_request_paths_outside_the_allowlist_or_missing_are_errors(tmp_path, kw):
    r, adapter = run(tmp_path, "pass", **kw)
    assert r.status is Status.ERROR and r.error_code in (ErrorCode.PROHIBITED_PATH, ErrorCode.INVALID_REQUEST) and adapter.builds == 0


def test_a_suite_path_that_leaves_the_workspace_through_a_symlink_is_refused(tmp_path):
    ws, out = dirs(tmp_path)
    secret_dir = tmp_path / "elsewhere"
    secret_dir.mkdir()
    (secret_dir / "t.fake").write_text("x")
    os.symlink(secret_dir, ws / "linked")
    r, adapter = run(tmp_path, "pass", suite_path="linked/t.fake")
    assert r.status is Status.ERROR and r.error_code is ErrorCode.PROHIBITED_PATH and adapter.builds == 0


def test_a_credential_directory_as_the_output_directory_is_refused(tmp_path):
    ws, out = dirs(tmp_path)
    bad = tmp_path / ".ssh"
    bad.mkdir()
    r, adapter = run(tmp_path, "pass", output_dir=str(bad))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.PROHIBITED_PATH and adapter.builds == 0


# ---------------------------------------------------------------------------------------------- manifest and class
def test_a_request_for_another_adapter_is_refused(tmp_path):
    r, adapter = run(tmp_path, "pass", adapter_id="other-adapter")
    assert r.status is Status.ERROR and r.error_code is ErrorCode.INVALID_REQUEST and adapter.builds == 0


def test_the_suite_runner_refuses_an_interactive_manifest(tmp_path):
    r, _ = run(tmp_path, "pass", manifest=interactive_manifest(adapter_id="fake-suite"))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.INVALID_REQUEST and r.adapter_class is AdapterClass.INTERACTIVE


def test_a_command_the_manifest_does_not_allow_is_never_started(tmp_path):
    ws, out = dirs(tmp_path)
    marker = tmp_path / "ran"
    r, _ = run(tmp_path, "pass", adapter_kw=dict(argv_override=["/bin/sh", "-c", f"touch {marker}"]))
    assert r.error_code is ErrorCode.EXECUTABLE_NOT_ALLOWED and not marker.exists()


def test_a_container_engine_command_is_never_started(tmp_path):
    m = suite_manifest(executables=["/usr/bin/docker"])
    r, _ = run(tmp_path, "pass", manifest=m, adapter_kw=dict(argv_override=["/usr/bin/docker", "ps"]))
    assert r.error_code is ErrorCode.DOCKER_REFUSED


def test_a_sealed_run_that_would_install_is_refused_and_an_unsealed_one_is_not_special_cased(tmp_path):
    m = suite_manifest(executables=["/usr/bin/pip"])
    r, _ = run(tmp_path, "pass", manifest=m, adapter_kw=dict(argv_override=["/usr/bin/pip", "install", "x"]))
    assert r.error_code is ErrorCode.DOWNLOAD_REFUSED


# ---------------------------------------------------------------------------------------------- environment and secrets
def test_the_child_sees_only_the_scrubbed_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("QA_KIT_PARENT_VALUE", "from-the-parent")
    monkeypatch.setenv("GH_TOKEN", fresh_secret())
    m = suite_manifest(env_allowlist=("APP_URL",))
    r, _ = run(tmp_path, "env_dump", manifest=m, env={"APP_URL": "http://localhost:3000"})
    names = json.loads((tmp_path / "output" / "env.json").read_text())
    assert r.status is Status.PASS
    assert "QA_KIT_PARENT_VALUE" not in names and "GH_TOKEN" not in names
    assert set(names) >= {"APP_URL", "PATH", "HOME", "PIP_NO_INDEX"}
    assert set(names) - {"APP_URL", "PATH", "HOME", "TMPDIR", "LANG", "PYTHONDONTWRITEBYTECODE", "NO_COLOR", "PIP_NO_INDEX", "NPM_CONFIG_OFFLINE",
                         "LC_CTYPE", "__CF_USER_TEXT_ENCODING"} == set()


def test_a_dangerous_environment_request_is_refused_before_the_start(tmp_path):
    m = suite_manifest(env_allowlist=("DOCKER_HOST",))
    r, adapter = run(tmp_path, "pass", manifest=m, env={"DOCKER_HOST": "unix:///var/run/docker.sock"})
    assert r.error_code is ErrorCode.ENV_REFUSED


def test_a_secret_never_appears_in_the_result(tmp_path):
    secret = fresh_secret("pw-")
    m = suite_manifest(secret_env_allowlist=("QA_APP_PASSWORD",))
    r, _ = run(tmp_path, "secret_print", manifest=m, secret_env={"QA_APP_PASSWORD": secret})
    blob = json.dumps(r.to_dict())
    assert r.status is Status.FAIL and secret not in blob and REDACTED in blob
    assert "abcdef0123456789" not in blob                   # the bearer value the child printed


def test_a_secret_in_a_text_artifact_makes_the_artifact_unusable_as_evidence(tmp_path):
    secret = fresh_secret("pw-")
    m = suite_manifest(secret_env_allowlist=("QA_APP_PASSWORD",))
    r, _ = run(tmp_path, "secret_in_artifact", manifest=m, secret_env={"QA_APP_PASSWORD": secret})
    assert r.status is Status.ERROR and r.error_code is ErrorCode.ARTIFACT_REFUSED and r.artifacts == () and secret not in json.dumps(r.to_dict())


def test_a_secret_in_the_error_message_is_redacted(tmp_path):
    secret = fresh_secret("pw-")
    m = suite_manifest(secret_env_allowlist=("QA_APP_PASSWORD",))
    r, _ = run(tmp_path, "secret_in_artifact", manifest=m, secret_env={"QA_APP_PASSWORD": secret})
    assert secret not in r.error_message
