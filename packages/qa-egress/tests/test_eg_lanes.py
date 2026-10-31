# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The offline suite never collects the egress browser lane; the lane is marked and fails (never skips) without Playwright; and
the SSRF vector set has at least one hundred cases that run against the real gateway."""
import ast
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PKG = ROOT / "packages" / "qa-egress"
TEXT = (ROOT / ".github" / "workflows" / "tests.yml").read_text()


def _env():
    return {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/tmp"), "PYTHONDONTWRITEBYTECODE": "1",
            **{k: v for k, v in os.environ.items() if k.startswith(("QA_PIN", "REDEVOPS_QA"))}}


def _pytest(*args):
    return subprocess.run([sys.executable, "-m", "pytest", "-q", *args], cwd=str(ROOT), env=_env(), capture_output=True, text=True)


def test_the_offline_runs_collect_no_egress_browser_test():
    for args in ((), ("packages/qa-egress/tests",)):
        done = _pytest("--collect-only", *args)
        assert done.returncode == 0 and "qa-egress/tests/browser" not in done.stdout


def test_the_egress_lane_collects_only_when_named_and_marked():
    done = _pytest("--collect-only", "-m", "browser", "packages/qa-egress/tests/browser")
    assert done.returncode == 0 and "tests/browser/test_eg_browser_loopback.py" in done.stdout


def test_every_egress_browser_module_is_marked():
    modules = sorted((PKG / "tests" / "browser").glob("test_*.py"))
    assert modules
    for path in modules:
        tree = ast.parse(path.read_text())
        assert any(isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "pytestmark" for t in n.targets) for n in tree.body), path.name


def test_the_egress_lane_fails_and_does_not_skip_without_playwright():
    try:
        import playwright  # noqa: F401
        raise AssertionError("playwright is installed here: this test describes the environment without it")
    except ImportError:
        pass
    done = _pytest("-m", "browser", "packages/qa-egress/tests/browser", "-x")
    out = done.stdout + done.stderr
    assert done.returncode != 0 and "skipped" not in out and "needs the Playwright package" in out


def test_the_browser_job_runs_the_egress_lane_as_well():
    import yaml
    steps = yaml.safe_load(TEXT)["jobs"]["browser"]["steps"]
    runs = "\n".join(str(s.get("run", "")) for s in steps)
    assert "packages/qa-egress/tests/browser" in runs and "packages/qa-playwright/tests/browser" in runs and "-m browser" in runs


def test_the_ssrf_vector_set_has_at_least_one_hundred_cases_and_each_runs_against_the_real_gateway():
    done = _pytest("--collect-only", "packages/qa-egress/tests/test_eg_ssrf_vectors.py")
    cases = [line for line in done.stdout.splitlines() if "::test_" in line]
    assert len(cases) >= 100, len(cases)
    source = (PKG / "tests" / "test_eg_ssrf_vectors.py").read_text()
    assert "make_gateway" in source and "Upstream()" in source and "monkeypatch" not in source      # real sockets, nothing mocked
