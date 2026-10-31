# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The real lane: Robot Framework 7.5 started by the shared supervisor through the adapter. Every test is marked ``robot_real`` and runs only
in the ``robot-real`` CI job. It shows that the adapter works with the real framework's real output.xml; it says nothing about other
versions."""
import dataclasses
import json
import secrets
import sys
import textwrap

import pytest

from qa_adapter_kit import ErrorCode, Limits, Status, SuiteRunRequest, SuiteRunner, canonical_status, map_to_canonical
from qa_robot import RobotConfig, RobotSuiteAdapter, suite_manifest

pytestmark = pytest.mark.robot_real

MIXED = textwrap.dedent('''\
    *** Settings ***
    Library           Collections

    *** Test Cases ***
    Login Works
        [Tags]    qa-assert:A-1
        Should Be Equal    1    1

    Banner Is Wrong
        [Tags]    qa-assert:A-4
        Should Be Equal    Welcome    Welcome back

    Skipped On Purpose
        [Tags]    qa-assert:A-5
        Skip    not on this platform

    Untagged Pass
        No Operation
    ''')


def setup(tmp_path, files):
    ws, out = tmp_path / "workspace", tmp_path / "output"
    (ws / "suite").mkdir(parents=True)
    out.mkdir()
    for name, text in files.items():
        p = ws / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return ws, out


def run(tmp_path, files, *, config=None, limits=None, secret_names=(), **kw):
    ws, out = setup(tmp_path, files)
    manifest = dataclasses.replace(suite_manifest(sys.executable, limits=limits or Limits(deadline_s=120, output_limit_bytes=500_000, kill_grace_s=3)),
                                   secret_env_allowlist=tuple(secret_names))
    adapter = RobotSuiteAdapter(sys.executable, config=config, manifest=manifest)
    req = SuiteRunRequest(run_id="real-1", adapter_id="robot-suite", workspace=str(ws), suite_path="suite", output_dir=str(out), **kw)
    return SuiteRunner(adapter).run(req), ws, out


def test_a_real_mixed_suite_reports_every_native_status(robot_installed, tmp_path):
    r, _, out = run(tmp_path, {"suite/mixed.robot": MIXED})
    got = {a.name: a.status for a in r.native_assertions}
    assert got == {"Login Works": Status.PASS, "Banner Is Wrong": Status.FAIL, "Skipped On Purpose": Status.SKIP, "Untagged Pass": Status.PASS}, (r.error_code, r.error_message)
    assert r.status is Status.FAIL and r.exit_code == 1 and (out / "robot-summary.json").exists() and not (out / "output.xml").exists()
    assert {a.name: a.declared_assertion_ids for a in r.native_assertions}["Login Works"] == ("A-1",)


def test_a_real_passing_suite_is_a_native_pass_and_stays_unverified_for_the_oracle(robot_installed, tmp_path):
    r, _, _ = run(tmp_path, {"suite/ok.robot": MIXED.split("Banner Is Wrong")[0] + "Untagged Pass\n    No Operation\n"})
    assert r.status is Status.PASS and r.exit_code == 0
    ids = {a.name: a.native_id for a in r.native_assertions}
    [ev] = map_to_canonical(r, ("A-1",), {ids["Login Works"]: "A-1"}).evidence
    [other] = map_to_canonical(r, ("A-1",), {ids["Untagged Pass"]: "A-1"}).evidence
    assert ev.native_status is Status.PASS and canonical_status(ev) is Status.UNVERIFIED and other.native_status is Status.UNVERIFIED


def test_a_real_suite_setup_failure_marks_its_tests_failed(robot_installed, tmp_path):
    text = "*** Settings ***\nSuite Setup    Fail    setup exploded\n\n*** Test Cases ***\nNever Runs\n    [Tags]    qa-assert:A-6\n    Log    unreachable\n"
    r, _, _ = run(tmp_path, {"suite/s.robot": text})
    assert r.status is Status.FAIL and r.native_assertions[0].status is Status.FAIL and r.native_assertions[0].message.startswith("Parent suite setup failed")


def test_selectors_run_only_the_named_tests_and_tags(robot_installed, tmp_path):
    r, _, _ = run(tmp_path, {"suite/mixed.robot": MIXED}, selectors=("Login Works",))
    assert [a.name for a in r.native_assertions] == ["Login Works"] and r.status is Status.PASS
    r2, _, _ = run(tmp_path / "b", {"suite/mixed.robot": MIXED.replace("[Tags]    qa-assert:A-1", "[Tags]    qa-assert:A-1    smoke")}, selectors=("tag:smoke",))
    assert [a.name for a in r2.native_assertions] == ["Login Works"]


def test_a_library_that_is_not_allowed_is_refused_before_the_run(robot_installed, tmp_path):
    r, _, out = run(tmp_path, {"suite/a.robot": "*** Settings ***\nLibrary    OperatingSystem\n\n*** Test Cases ***\nT\n    Log    x\n"})
    assert r.status is Status.ERROR and r.error_code is ErrorCode.LIBRARY_REFUSED and r.exit_code is None and not (out / "robot-summary.json").exists()


def test_a_keyword_that_builds_the_name_of_evaluate_at_run_time_is_caught_after_the_run(robot_installed, tmp_path):
    text = ("*** Test Cases ***\nSneaky\n    ${name}=    Set Variable    Eval${EMPTY}uate\n    ${v}=    Run Keyword    ${name}    1 + 1\n")
    r, _, out = run(tmp_path, {"suite/a.robot": text})
    assert r.status is Status.ERROR and r.error_code is ErrorCode.LIBRARY_REFUSED and r.native_assertions == () and not (out / "robot-summary.json").exists()


def test_a_workspace_file_named_like_an_allowed_library_does_not_replace_it(robot_installed, tmp_path):
    # Observed with Robot Framework 7.5: a standard library name is resolved from Robot Framework itself, so a same-named module in the
    # workspace is not loaded even without isolation. The adapter also runs `python -I`, which keeps the workspace and PYTHON* variables off
    # the import path for anything else; a library that is not a standard one is refused by name before the run.
    shadow = "def get_from_list(items, index):\n    return 'SHADOW'\n"
    suite = ("*** Settings ***\nLibrary    Collections\n\n*** Test Cases ***\nReal Library\n"
             "    ${items}=    Create List    a    b\n    ${v}=    Get From List    ${items}    1\n    Should Be Equal    ${v}    b\n")
    r, _, _ = run(tmp_path, {"suite/t.robot": suite, "Collections.py": shadow, "suite/Collections.py": shadow})
    assert r.status is Status.PASS, (r.error_code, r.error_message, r.stdout_tail[-300:])


def test_a_secret_logged_by_the_suite_never_reaches_the_result_or_the_summary(robot_installed, tmp_path):
    secret = "pw-" + secrets.token_hex(12)
    text = ("*** Test Cases ***\nLeaky\n    [Tags]    qa-assert:A-1\n    Log    value is %{QA_APP_PASSWORD}    WARN\n"
            "    Fail    login failed for %{QA_APP_PASSWORD}\n")
    r, _, out = run(tmp_path, {"suite/a.robot": text}, secret_names=("QA_APP_PASSWORD",), secret_env={"QA_APP_PASSWORD": secret})
    assert r.status is Status.FAIL
    blob = json.dumps(r.to_dict()) + (out / "robot-summary.json").read_text()
    assert secret not in blob and "[REDACTED]" in r.native_assertions[0].message


def test_a_suite_that_never_ends_times_out_and_is_an_error(robot_installed, tmp_path):
    text = "*** Test Cases ***\nHang\n    Sleep    600\n"
    r, _, _ = run(tmp_path, {"suite/a.robot": text}, limits=Limits(deadline_s=3, kill_grace_s=2, output_limit_bytes=100_000))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.TIMEOUT


def test_the_suite_sees_only_the_scrubbed_environment(robot_installed, tmp_path, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "x" * 20)
    text = ("*** Test Cases ***\nEnv\n    ${v}=    Get Environment Variable    GH_TOKEN    absent\n")
    cfg = RobotConfig(allowed_libraries=frozenset({"BuiltIn", "OperatingSystem"}))
    r, _, _ = run(tmp_path, {"suite/a.robot": "*** Settings ***\nLibrary    OperatingSystem\n\n" + text + "    Should Be Equal    ${v}    absent\n"}, config=cfg)
    assert r.status is Status.PASS, (r.error_code, r.error_message)
