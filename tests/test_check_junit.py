# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("check_junit", Path(__file__).resolve().parents[1] / "tools" / "check_junit.py")
check_junit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_junit)


def _report(tmp_path, suite_attrs, cases):
    attrs = " ".join(f'{k}="{v}"' for k, v in suite_attrs.items())
    body = "".join(cases)
    path = tmp_path / "r.xml"
    path.write_text(f'<?xml version="1.0"?><testsuites><testsuite name="x" {attrs}>{body}</testsuite></testsuites>')
    return str(path)


OK = '<testcase classname="a" name="t"/>'


def test_a_clean_report_passes(tmp_path, capsys):
    path = _report(tmp_path, dict(tests=1, skipped=0, failures=0, errors=0), [OK])
    assert check_junit.main(["x", path]) == 0
    assert "OK 1 tests" in capsys.readouterr().out


def test_zero_collected_tests_fails(tmp_path, capsys):
    path = _report(tmp_path, dict(tests=0, skipped=0, failures=0, errors=0), [])
    assert check_junit.main(["x", path]) == 1
    assert "NO_TESTS_COLLECTED" in capsys.readouterr().out


def test_any_skip_fails_even_if_the_suite_counter_is_wrong(tmp_path, capsys):
    skip = '<testcase classname="a" name="s"><skipped message="why"/></testcase>'
    path = _report(tmp_path, dict(tests=2, skipped=0, failures=0, errors=0), [OK, skip])
    assert check_junit.main(["x", path]) == 1
    assert "SKIPPED_TESTS" in capsys.readouterr().out


@pytest.mark.parametrize("attrs,code", [(dict(failures=1), "FAILED_TESTS"), (dict(errors=1), "ERRORED_TESTS")])
def test_failures_and_errors_fail(tmp_path, capsys, attrs, code):
    base = dict(tests=1, skipped=0, failures=0, errors=0)
    base.update(attrs)
    assert check_junit.main(["x", _report(tmp_path, base, [OK])]) == 1
    assert code in capsys.readouterr().out


def test_an_unreadable_report_fails(tmp_path, capsys):
    assert check_junit.main(["x", str(tmp_path / "missing.xml")]) == 1
    (tmp_path / "bad.xml").write_text("<not xml")
    assert check_junit.main(["x", str(tmp_path / "bad.xml")]) == 1
    assert check_junit.main(["x"]) == 2
