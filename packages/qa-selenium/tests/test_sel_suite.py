# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The suite adapter end to end: real pytest started by the shared supervisor over a small suite, its JUnit XML imported."""
import json
import sys

import pytest

from sel_support import mini_workspace, run_suite
from qa_adapter_kit import (CommandSpec, ErrorCode, Limits, ModelError, RunLayout, Status, SuiteRunRequest, SuiteRunner, canonical_status,
                            map_to_canonical)
from qa_selenium import SeleniumSuiteAdapter, suite_manifest


def test_the_manifest_is_a_suite_manifest_with_no_steering():
    m = suite_manifest(sys.executable)
    assert m.adapter_class.value == "suite" and set(m.capabilities) == {"run_suite", "import_native_report"} and m.report_formats == ("junit-xml",)
    assert m.framework.pinned_release == "4.52.0" and m.allowed_executables == (sys.executable,)


def test_the_command_is_python_dash_m_pytest_with_a_junit_report_and_no_shell(tmp_path):
    ws, out = mini_workspace(tmp_path)
    adapter = SeleniumSuiteAdapter(sys.executable)
    req = SuiteRunRequest(run_id="r1", adapter_id="selenium-suite", workspace=str(ws), suite_path="suite/test_mini.py", output_dir=str(out),
                          selectors=("test_login_ok", "smoke"))
    spec = adapter.build_command(req, RunLayout(workspace=ws, suite=ws / "suite" / "test_mini.py", output_dir=out, home=tmp_path))
    assert spec.argv[:3] == (sys.executable, "-m", "pytest") and f"--junitxml={out}/junit.xml" in spec.argv
    assert spec.argv[spec.argv.index("-k") + 1] == "test_login_ok or smoke" and "junit_family=xunit1" in spec.argv and spec.cwd == str(ws)


def _layout(ws, out, tmp_path):
    return RunLayout(workspace=ws, suite=ws / "suite" / "test_mini.py", output_dir=out, home=tmp_path)


@pytest.mark.parametrize("selector", ["a b", "not x", "a or b", "1abc", "a-b", "x" * 65, "a:b", "a/b", "a*"])
def test_a_selector_that_is_not_a_plain_name_is_refused_by_the_adapter(tmp_path, selector):
    ws, out = mini_workspace(tmp_path)
    req = SuiteRunRequest(run_id="r1", adapter_id="selenium-suite", workspace=str(ws), suite_path="suite/test_mini.py", output_dir=str(out),
                          selectors=(selector,))
    with pytest.raises(ModelError):
        SeleniumSuiteAdapter(sys.executable).build_command(req, _layout(ws, out, tmp_path))


@pytest.mark.parametrize("selector", ["a;b", "-k", "--exec=x", "a\nb", "$(x)"])
def test_a_selector_with_shell_or_option_characters_is_refused_by_the_request_model(tmp_path, selector):
    ws, out = mini_workspace(tmp_path)
    with pytest.raises(ModelError):
        SuiteRunRequest(run_id="r1", adapter_id="selenium-suite", workspace=str(ws), suite_path="suite/test_mini.py", output_dir=str(out),
                        selectors=(selector,))


def test_a_mixed_suite_reports_fail_with_every_native_outcome(tmp_path):
    r, _, out = run_suite(tmp_path)
    assert r.status is Status.ERROR and r.error_code is ErrorCode.NATIVE_ERROR          # a fixture error is a native ERROR
    got = {a.name: a.status for a in r.native_assertions}
    assert got["test_banner_text"] is Status.FAIL and got["test_error_in_fixture"] is Status.ERROR and got["test_login_ok"] is Status.PASS
    assert got["test_skipped"] is Status.SKIP and got["test_expected_failure"] is Status.SKIP and r.exit_code == 1
    assert [a.path for a in r.artifacts] == ["junit.xml"] and (out / "junit.xml").exists()


def test_a_selected_passing_subset_is_a_native_pass(tmp_path):
    r, _, _ = run_suite(tmp_path, selectors=("test_login_ok", "test_untagged_pass"))
    assert r.status is Status.PASS and r.exit_code == 0 and len(r.native_assertions) == 2


def test_a_failing_subset_is_a_fail(tmp_path):
    r, _, _ = run_suite(tmp_path, selectors=("test_banner_text", "test_login_ok"))
    assert r.status is Status.FAIL and r.error_code is None


def test_an_error_free_run_with_a_skip_is_a_skip_not_a_pass(tmp_path):
    r, _, _ = run_suite(tmp_path, selectors=("test_skipped",))
    assert r.status is Status.SKIP


def test_nothing_collected_is_an_error_never_a_pass(tmp_path):
    r, _, _ = run_suite(tmp_path, selectors=("test_that_does_not_exist",))
    assert r.status is Status.ERROR and r.native_assertions == ()


def test_a_suite_with_a_collection_error_is_an_error(tmp_path):
    r, _, _ = run_suite(tmp_path, text="import definitely_not_installed_module\n\ndef test_x():\n    pass\n")
    assert r.status is Status.ERROR


def test_a_usage_error_exit_code_means_the_report_is_not_trusted(tmp_path):
    ws, out = mini_workspace(tmp_path)
    adapter = SeleniumSuiteAdapter(sys.executable)
    req = SuiteRunRequest(run_id="r1", adapter_id="selenium-suite", workspace=str(ws), suite_path="suite/test_mini.py", output_dir=str(out))
    (out / "junit.xml").write_bytes((tmp_path.parent / "x").name.encode() and b"<testsuites/>")
    from qa_adapter_kit import MalformedReport, ProcessOutcome
    with pytest.raises(MalformedReport):
        adapter.import_report(req, RunLayout(workspace=ws, suite=ws, output_dir=out, home=tmp_path),
                              ProcessOutcome(exit_code=4, signal=None, stdout=b"", stderr=b"", duration_s=0.1))


def test_a_hanging_suite_times_out_and_is_an_error(tmp_path):
    r, _, _ = run_suite(tmp_path, text="import time\n\ndef test_hang():\n    time.sleep(600)\n",
                        limits=Limits(deadline_s=2, kill_grace_s=1, output_limit_bytes=100_000))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.TIMEOUT


def test_the_suite_does_not_see_the_parents_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "x" * 20)
    monkeypatch.setenv("QA_KIT_PARENT_VALUE", "from-the-parent")
    text = ("import os\n\ndef test_env():\n    names = sorted(os.environ)\n    open(os.path.join(os.path.dirname(__file__), 'seen.json'), 'w').write(repr(names))\n")
    r, ws, _ = run_suite(tmp_path, text=text)
    seen = (ws / "suite" / "seen.json").read_text()
    assert r.status is Status.PASS and "GH_TOKEN" not in seen and "QA_KIT_PARENT_VALUE" not in seen and "PIP_NO_INDEX" in seen


def test_the_suite_gets_the_allowlisted_variables_and_nothing_else(tmp_path):
    text = ("import os\n\ndef test_env():\n    assert os.environ['QA_BASE_URL'] == 'http://127.0.0.1:1/'\n    assert 'QA_OTHER' not in os.environ\n")
    r, _, _ = run_suite(tmp_path, text=text, env={"QA_BASE_URL": "http://127.0.0.1:1/"})
    assert r.status is Status.PASS


def test_a_variable_outside_the_allowlist_is_refused(tmp_path):
    r, _, _ = run_suite(tmp_path, env={"QA_OTHER": "x"})
    assert r.status is Status.ERROR and r.error_code is ErrorCode.ENV_REFUSED


def test_a_sealed_run_is_what_this_adapter_runs_by_default_and_pip_cannot_be_started(tmp_path):
    ws, out = mini_workspace(tmp_path)
    m = suite_manifest("/usr/bin/pip")
    adapter = SeleniumSuiteAdapter("/usr/bin/pip", m)
    req = SuiteRunRequest(run_id="r1", adapter_id="selenium-suite", workspace=str(ws), suite_path="suite/test_mini.py", output_dir=str(out))
    assert SuiteRunner(adapter).run(req).error_code is ErrorCode.DOWNLOAD_REFUSED


def test_a_python_that_is_not_in_the_manifest_is_never_started(tmp_path):
    ws, out = mini_workspace(tmp_path)
    adapter = SeleniumSuiteAdapter("/usr/bin/python3", suite_manifest(sys.executable))
    req = SuiteRunRequest(run_id="r1", adapter_id="selenium-suite", workspace=str(ws), suite_path="suite/test_mini.py", output_dir=str(out))
    assert SuiteRunner(adapter).run(req).error_code is ErrorCode.EXECUTABLE_NOT_ALLOWED


# ---------------------------------------------------------------------------------------------- native PASS is not an oracle PASS
def test_a_native_pass_with_an_explicit_matching_mapping_stays_unverified_for_the_oracle(tmp_path):
    r, _, _ = run_suite(tmp_path, selectors=("test_login_ok",), required=("A-1",), mapping={"suite.test_mini::test_login_ok": "A-1"})
    # the recorded mini suite tags test_login_ok with A-1 through record_property
    [ev] = map_to_canonical(r, ("A-1",), {"suite.test_mini::test_login_ok": "A-1"}).evidence
    assert r.status is Status.PASS and ev.native_status is Status.PASS and canonical_status(ev) is Status.UNVERIFIED


def test_a_passing_untagged_test_cannot_support_an_assertion(tmp_path):
    r, _, _ = run_suite(tmp_path, selectors=("test_untagged_pass",))
    rep = map_to_canonical(r, ("A-1",), {"suite.test_mini::test_untagged_pass": "A-1"})
    assert r.status is Status.PASS and rep.evidence[0].native_status is Status.UNVERIFIED and rep.refused


def test_a_passing_test_tagged_for_another_assertion_cannot_support_this_one(tmp_path):
    r, _, _ = run_suite(tmp_path, selectors=("test_inside_class",))
    assert map_to_canonical(r, ("A-1",), {"suite.test_mini.TestGroup::test_inside_class": "A-1"}).evidence[0].native_status is Status.UNVERIFIED


def test_a_skipped_test_never_reaches_its_tag_so_it_supports_nothing(tmp_path):
    r, _, _ = run_suite(tmp_path, selectors=("test_skipped",))
    [ev] = map_to_canonical(r, ("A-5",), {"suite.test_mini::test_skipped": "A-5"}).evidence
    assert r.status is Status.SKIP and ev.native_status is Status.UNVERIFIED and canonical_status(ev) is Status.UNVERIFIED


def test_a_tagged_test_that_is_skipped_at_run_time_is_native_skip_evidence(tmp_path):
    text = ("import pytest\n\ndef test_late_skip(record_property):\n    record_property('qa-assert', 'A-7')\n    pytest.skip('no browser')\n")
    r, _, _ = run_suite(tmp_path, text=text)
    [ev] = map_to_canonical(r, ("A-7",), {"suite.test_mini::test_late_skip": "A-7"}).evidence
    assert r.status is Status.SKIP and ev.native_status is Status.SKIP and canonical_status(ev) is Status.UNVERIFIED


def test_a_failing_test_tagged_for_an_assertion_is_native_fail_and_still_not_a_verdict(tmp_path):
    r, _, _ = run_suite(tmp_path, selectors=("test_banner_text",))
    [ev] = map_to_canonical(r, ("A-4",), {"suite.test_mini::test_banner_text": "A-4"}).evidence
    assert ev.native_status is Status.FAIL and canonical_status(ev) is Status.UNVERIFIED


def test_the_result_serialises_without_any_oracle_field(tmp_path):
    r, _, _ = run_suite(tmp_path, selectors=("test_login_ok",))
    d = json.loads(json.dumps(r.to_dict()))
    assert d["authority"] == "native" and not any("oracle" in k for k in d)
