# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The Robot suite adapter through the shared runner, with a stand-in for ``python -m robot`` that writes a recorded output.xml."""
import json
import sys

import pytest

from rb_support import FIXTURES, FAKE, SIMPLE, run_fake, workspace
from qa_adapter_kit import (ErrorCode, ModelError, PolicyRefused, RunLayout, Status, SuiteRunRequest, SuiteRunner, canonical_status, map_to_canonical)
from qa_robot import RobotConfig, RobotSuiteAdapter, suite_manifest


def test_the_manifest_is_a_suite_manifest_with_no_steering():
    m = suite_manifest(sys.executable)
    assert m.adapter_class.value == "suite" and set(m.capabilities) == {"run_suite", "import_native_report"} and m.report_formats == ("robot-output-xml",)
    assert m.framework.pinned_release == "7.5" and m.env_allowlist == ("QA_BASE_URL",)


def layout(tmp_path):
    ws, out = workspace(tmp_path)
    (tmp_path / "home").mkdir()
    return RunLayout(workspace=ws, suite=ws / "suite", output_dir=out, home=tmp_path / "home")


def request(tmp_path, **kw):
    ws, out = tmp_path / "workspace", tmp_path / "output"
    return SuiteRunRequest(run_id="r1", adapter_id="robot-suite", workspace=str(ws), suite_path="suite", output_dir=str(out), **kw)


def test_the_command_is_isolated_python_dash_m_robot_with_no_log_or_report_and_no_shell(tmp_path):
    lay = layout(tmp_path)
    spec = RobotSuiteAdapter(sys.executable).build_command(request(tmp_path, selectors=("Login Works", "tag:smoke")), lay)
    argv = list(spec.argv)
    assert argv[:4] == [sys.executable, "-I", "-m", "robot"] and argv[-1] == str(lay.suite) and spec.cwd == str(lay.workspace)
    assert argv[argv.index("--outputdir") + 1] == str(lay.home / "robot") and argv[argv.index("--log") + 1] == "NONE" and argv[argv.index("--report") + 1] == "NONE"
    assert argv[argv.index("--test") + 1] == "Login Works" and argv[argv.index("--include") + 1] == "smoke"
    assert not any(a in ("pip", "install", "-c", "sh", "bash") for a in argv)


@pytest.mark.parametrize("selector", ["--exec", "a;b", "$(x)", "tag:", "tag:a b;c", "a\nb"])
def test_a_selector_that_is_not_a_test_or_tag_name_is_refused(tmp_path, selector):
    with pytest.raises(ModelError):
        lay = layout(tmp_path)
        RobotSuiteAdapter(sys.executable).build_command(request(tmp_path, selectors=(selector,)), lay)


def test_a_suite_that_imports_a_library_outside_the_allowlist_is_refused_before_anything_starts(tmp_path):
    r, ws, out = run_fake(tmp_path, "robot75-pass.xml", text="*** Settings ***\nLibrary    OperatingSystem\n\n*** Test Cases ***\nT\n    Log    x\n")
    assert r.status is Status.ERROR and r.error_code is ErrorCode.LIBRARY_REFUSED and "OperatingSystem" in r.error_message
    assert r.exit_code is None and not (out / "robot-summary.json").exists()


# ---------------------------------------------------------------------------------------------- statuses from recorded runs
def test_a_recorded_mixed_run_is_a_fail_with_every_native_outcome(tmp_path):
    r, _, out = run_fake(tmp_path, "robot75-mixed.xml", exit_code=3)
    assert r.status is Status.FAIL and r.error_code is None and r.exit_code == 3
    got = {a.name: a.status for a in r.native_assertions}
    assert got["Banner Text Is Wrong"] is Status.FAIL and got["Skipped On Purpose"] is Status.SKIP and got["Login Works"] is Status.PASS and len(got) == 8


def test_a_recorded_passing_run_is_a_native_pass(tmp_path):
    r, _, _ = run_fake(tmp_path, "robot75-pass.xml", exit_code=0)
    assert r.status is Status.PASS and r.exit_code == 0 and len(r.native_assertions) == 2 and r.authority == "native"


def test_a_passing_report_with_a_nonzero_exit_is_an_error_not_a_pass(tmp_path):
    r, _, _ = run_fake(tmp_path, "robot75-pass.xml", exit_code=7)
    assert r.status is Status.ERROR and r.error_code is ErrorCode.NATIVE_ERROR


@pytest.mark.parametrize("code", [251, 252, 253, 255])
def test_exit_codes_for_an_invalid_call_a_stop_or_an_internal_error_make_the_report_untrusted(tmp_path, code):
    r, _, _ = run_fake(tmp_path, "robot75-pass.xml", exit_code=code)
    assert r.status is Status.ERROR and r.error_code is ErrorCode.MALFORMED_RESULT and r.native_assertions == ()


def test_no_output_file_is_an_error(tmp_path):
    r, _, _ = run_fake(tmp_path, "robot75-pass.xml", exit_code=0, write=False)
    assert r.status is Status.ERROR and r.error_code is ErrorCode.MALFORMED_RESULT and "not written" in r.error_message


def test_a_truncated_output_file_is_an_error(tmp_path, monkeypatch):
    cut = tmp_path / "cut.xml"
    cut.write_bytes((FIXTURES / "robot75-mixed.xml").read_bytes()[:900])
    r, _, _ = run_fake(tmp_path, str(cut), exit_code=3)
    assert r.status is Status.ERROR and r.error_code is ErrorCode.MALFORMED_RESULT


def test_robot_framework_not_installed_is_an_error_never_a_pass(tmp_path):
    ws, out = workspace(tmp_path)
    adapter = RobotSuiteAdapter(sys.executable, launcher=("-m", "qa_definitely_missing_robot_module"))
    r = SuiteRunner(adapter).run(request(tmp_path))
    assert r.status is Status.ERROR and r.native_assertions == ()


# ---------------------------------------------------------------------------------------------- allowlist after the run
def test_a_report_with_keywords_of_a_library_that_was_not_allowed_is_refused(tmp_path):
    bad = (FIXTURES / "robot75-pass.xml").read_text().replace('owner="BuiltIn"', 'owner="OperatingSystem"', 1)
    tmp = tmp_path / "owner.xml"
    tmp.write_text(bad)
    r, _, out = run_fake(tmp_path, str(tmp), exit_code=0)
    assert r.status is Status.ERROR and r.error_code is ErrorCode.LIBRARY_REFUSED and r.native_assertions == () and not (out / "robot-summary.json").exists()


def test_a_report_that_called_evaluate_is_refused_even_though_it_is_a_builtin_keyword(tmp_path):
    bad = (FIXTURES / "robot75-pass.xml").read_text().replace('name="Log"', 'name="Evaluate"', 1)
    tmp = tmp_path / "eval.xml"
    tmp.write_text(bad)
    r, _, _ = run_fake(tmp_path, str(tmp), exit_code=0)
    ok, _, _ = run_fake(tmp_path / "b", str(tmp), exit_code=0, config=RobotConfig(allow_dynamic_python=True))
    assert r.error_code is ErrorCode.LIBRARY_REFUSED and ok.status is Status.PASS


# ---------------------------------------------------------------------------------------------- evidence artifacts
def test_the_summary_artifact_has_no_messages_or_arguments_and_records_the_raw_digest(tmp_path):
    r, _, out = run_fake(tmp_path, "robot75-mixed.xml", exit_code=3)
    summary = json.loads((out / "robot-summary.json").read_text())
    assert [a.path for a in r.artifacts] == ["robot-summary.json"] and summary["schema"] == "redevops-qa/robot-summary/1"
    assert len(summary["raw_output_sha256"]) == 64 and len(summary["tests"]) == 8 and "BuiltIn" in summary["libraries_used"]
    assert all(set(t) == {"native_id", "name", "status", "declared_assertion_ids", "duration_s"} for t in summary["tests"])
    text = (out / "robot-summary.json").read_text()
    assert "Banner differs" not in text and "PASSWORD" not in text and not (out / "output.xml").exists()


def test_the_raw_output_is_kept_only_when_asked_for(tmp_path):
    r, _, out = run_fake(tmp_path, "robot75-pass.xml", exit_code=0, config=RobotConfig(keep_raw_output=True))
    assert sorted(a.path for a in r.artifacts) == ["output.xml", "robot-summary.json"] and (out / "output.xml").exists()


def test_a_kept_raw_output_that_holds_a_known_secret_is_refused_as_evidence(tmp_path):
    secret = "kept-raw-" + "0123456789abcdef"
    tmp = tmp_path / "secret.xml"
    tmp.write_text((FIXTURES / "robot75-pass.xml").read_text().replace("<arg>one</arg>", f"<arg>{secret}</arg>"))
    r, _, _ = run_fake(tmp_path, str(tmp), exit_code=0, config=RobotConfig(keep_raw_output=True), secret_names=("QA_APP_PASSWORD",),
                       secret_env={"QA_APP_PASSWORD": secret})
    ok, _, out = run_fake(tmp_path / "b", str(tmp), exit_code=0, secret_names=("QA_APP_PASSWORD",), secret_env={"QA_APP_PASSWORD": secret})
    assert r.status is Status.ERROR and r.error_code is ErrorCode.ARTIFACT_REFUSED and secret not in json.dumps(r.to_dict())
    assert ok.status is Status.PASS and secret not in (out / "robot-summary.json").read_text()      # the default keeps only the summary


def test_the_raw_output_directory_is_removed_with_the_run(tmp_path):
    r, _, out = run_fake(tmp_path, "robot75-pass.xml", exit_code=0)
    assert not any(p.name == "output.xml" for p in out.rglob("*"))


# ---------------------------------------------------------------------------------------------- native PASS is not an oracle PASS
def test_a_tagged_native_pass_with_an_explicit_mapping_stays_unverified_for_the_oracle(tmp_path):
    r, _, _ = run_fake(tmp_path, "robot75-pass.xml", exit_code=0, required=("A-1",), mapping={"Suite.First": "A-1"})
    ids = {a.name: a.native_id for a in r.native_assertions}
    [ev] = map_to_canonical(r, ("A-1",), {ids["First"]: "A-1"}).evidence
    assert r.status is Status.PASS and ev.native_status is Status.PASS and canonical_status(ev) is Status.UNVERIFIED


def test_a_passing_untagged_test_and_a_test_tagged_for_another_assertion_support_nothing(tmp_path):
    r, _, _ = run_fake(tmp_path, "robot75-mixed.xml", exit_code=3)
    ids = {a.name: a.native_id for a in r.native_assertions}
    assert map_to_canonical(r, ("A-1",), {ids["Untagged Pass"]: "A-1"}).evidence[0].native_status is Status.UNVERIFIED
    assert map_to_canonical(r, ("A-1",), {ids["Total Is Correct"]: "A-1"}).evidence[0].native_status is Status.UNVERIFIED


def test_a_failing_parent_setup_test_declares_its_assertion_but_is_native_fail(tmp_path):
    r, _, _ = run_fake(tmp_path, "robot75-mixed.xml", exit_code=3)
    ids = {a.name: a.native_id for a in r.native_assertions}
    [ev] = map_to_canonical(r, ("A-6",), {ids["Never Runs"]: "A-6"}).evidence
    assert ev.native_status is Status.FAIL and canonical_status(ev) is Status.UNVERIFIED


def test_a_skipped_test_that_declares_an_assertion_is_native_skip_never_pass(tmp_path):
    r, _, _ = run_fake(tmp_path, "robot75-mixed.xml", exit_code=3)
    ids = {a.name: a.native_id for a in r.native_assertions}
    [ev] = map_to_canonical(r, ("A-5",), {ids["Skipped On Purpose"]: "A-5"}).evidence
    assert ev.native_status is Status.SKIP


def test_the_result_serialises_without_any_oracle_field(tmp_path):
    r, _, _ = run_fake(tmp_path, "robot75-pass.xml", exit_code=0)
    d = json.loads(json.dumps(r.to_dict()))
    assert d["authority"] == "native" and not any("oracle" in k for k in d)


# ---------------------------------------------------------------------------------------------- supervisor interplay
def test_a_variable_outside_the_allowlist_is_refused(tmp_path):
    r, _, _ = run_fake(tmp_path, "robot75-pass.xml", exit_code=0, env={"QA_OTHER": "x"})
    assert r.error_code is ErrorCode.ENV_REFUSED


def test_pip_cannot_be_started_by_this_adapter_in_a_sealed_run(tmp_path):
    ws, out = workspace(tmp_path)
    adapter = RobotSuiteAdapter("/usr/bin/pip", manifest=suite_manifest("/usr/bin/pip"), launcher=("install", "robotframework"))
    assert SuiteRunner(adapter).run(request(tmp_path)).error_code is ErrorCode.DOWNLOAD_REFUSED


def test_a_python_that_is_not_in_the_manifest_is_never_started(tmp_path):
    ws, out = workspace(tmp_path)
    # An executable that is not the manifest's: a file of our own. "/usr/bin/python3" is not one on Debian and Ubuntu, where it is the
    # very interpreter a system-Python virtual environment links to, so the manifest rightly accepts it.
    other_python = tmp_path / "other-python"
    other_python.write_text("#!/bin/sh\nexit 0\n")
    other_python.chmod(0o755)
    adapter = RobotSuiteAdapter(str(other_python), manifest=suite_manifest(sys.executable))
    assert SuiteRunner(adapter).run(request(tmp_path)).error_code is ErrorCode.EXECUTABLE_NOT_ALLOWED
