# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The offline suite and the real-browser lane are separate: the offline run never collects ``tests/browser``, every browser
test is marked ``browser``, the lane fails (never skips) without Playwright, and the CI job that runs it is pinned,
read-only and secret-free."""
import ast
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
PKG = ROOT / "packages" / "qa-playwright"
TEXT = (ROOT / ".github" / "workflows" / "tests.yml").read_text()


def _collect(*args, env_extra=None):
    import os
    env = {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/tmp"), "PYTHONDONTWRITEBYTECODE": "1",
           **{k: v for k, v in os.environ.items() if k.startswith(("QA_PIN", "REDEVOPS_QA"))}}
    return subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", *args], cwd=str(ROOT), env=env,
                          capture_output=True, text=True)


def test_the_offline_default_run_collects_no_browser_test():
    done = _collect()
    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-2000:]
    assert "tests/browser" not in done.stdout


def test_the_offline_package_run_collects_no_browser_test_even_when_the_package_is_named():
    done = _collect("packages/qa-playwright/tests")
    assert done.returncode == 0 and "tests/browser" not in done.stdout


def test_the_browser_lane_collects_only_when_named_and_selected_by_its_marker():
    done = _collect("packages/qa-playwright/tests/browser", "-m", "browser")
    assert done.returncode == 0 and "tests/browser/test_pw_browser_driver.py" in done.stdout


def test_every_browser_test_module_is_marked_and_every_test_in_it_is_a_test_function():
    modules = sorted((PKG / "tests" / "browser").glob("test_*.py"))
    assert modules
    for path in modules:
        tree = ast.parse(path.read_text())
        marked = any(isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "pytestmark" for t in n.targets) for n in tree.body)
        assert marked, f"{path.name} does not set pytestmark = pytest.mark.browser"
        assert any(isinstance(n, ast.FunctionDef) and n.name.startswith("test_") for n in tree.body)


def test_the_lane_fails_and_does_not_skip_without_playwright():
    done = subprocess.run([sys.executable, "-m", "pytest", "-q", "-m", "browser", "packages/qa-playwright/tests/browser", "-x",
                           "-p", "no:randomly"], cwd=str(ROOT), capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1",
                               **{k: v for k, v in __import__("os").environ.items() if k.startswith(("QA_PIN", "REDEVOPS_QA"))}})
    out = done.stdout + done.stderr
    try:
        import playwright  # noqa: F401
        pytest.fail("playwright is installed here: this test describes the environment without it")
    except ImportError:
        pass
    assert done.returncode != 0 and "skipped" not in out and "needs the Playwright package" in out


def test_the_marker_is_registered_strictly_and_the_browser_directory_is_not_recursed_into():
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["pytest"]["ini_options"]
    assert any(m.startswith("browser:") for m in cfg["markers"]) and "--strict-markers" in cfg["addopts"]
    assert "browser" in cfg["norecursedirs"]
    assert not any("browser" in p for p in cfg["testpaths"])


# -- the CI job -----------------------------------------------------------------------------------------------

def _job():
    import yaml
    return yaml.safe_load(TEXT)["jobs"]["browser"]


def test_the_browser_job_is_read_only_secret_free_and_has_no_publish_step():
    job = _job()
    assert "permissions" not in job or all(v == "read" for v in job["permissions"].values())
    body = "\n".join(f"{s.get('run', '')} {s.get('uses', '')} {s.get('with', '')} {s.get('env', '')}" for s in job["steps"])
    for word in ("secrets.", "token", "password", "release", "publish", "twine", "git push", "docker push", "contents: write"):
        assert word not in body.lower(), word
    assert "continue-on-error" not in TEXT


def test_the_browser_job_pins_playwright_installs_the_browser_and_fails_on_a_skip_or_an_empty_run():
    steps = _job()["steps"]
    runs = "\n".join(str(s.get("run", "")) for s in steps)
    assert '"playwright==1.64.1"' in runs and "playwright install --with-deps chromium" in runs
    assert "import importlib.metadata as m, playwright.sync_api" in runs
    assert "-m browser" in runs and "packages/qa-playwright/tests/browser" in runs and "--junitxml" in runs
    assert "tools/check_junit.py" in runs
    first_test = next(i for i, s in enumerate(steps) if "-m pytest" in str(s.get("run", "")))
    install = next(i for i, s in enumerate(steps) if "playwright install" in str(s.get("run", "")))
    verify = next(i for i, s in enumerate(steps) if "--verify-trees" in str(s.get("run", "")))
    assert verify < install < first_test
    assert "env -i HOME=" in runs


def test_the_offline_jobs_do_not_install_playwright():
    import yaml
    jobs = yaml.safe_load(TEXT)["jobs"]
    for name, job in jobs.items():
        if name in ("browser", "runner-browser", "runner-e2e"):          # the jobs that install the browser: the adapter's own lane and the orchestrated runner lane
            continue
        for step in job["steps"]:
            assert "playwright" not in str(step.get("run", "")).lower(), name
