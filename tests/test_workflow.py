# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The CI workflow is read-only, has no tag or publish trigger, and cannot let a skip or an empty run pass."""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
WF = yaml.safe_load(TEXT)
TRIGGERS = WF.get(True) or WF.get("on")
ANDROID_TEXT = (ROOT / ".github" / "workflows" / "appium-android.yml").read_text(encoding="utf-8")
ANDROID_WF = yaml.safe_load(ANDROID_TEXT)
ANDROID_TRIGGERS = ANDROID_WF.get(True) or ANDROID_WF.get("on")


def test_permissions_are_read_only_everywhere():
    assert WF["permissions"] == {"contents": "read"}
    for name, job in WF["jobs"].items():
        assert "permissions" not in job or all(v == "read" for v in job["permissions"].values()), name


def test_no_tag_trigger_and_no_manual_or_scheduled_publish_path():
    assert set(TRIGGERS) <= {"push", "pull_request"}
    assert "tags" not in TRIGGERS.get("push", {}) and "tags-ignore" not in TRIGGERS.get("push", {})


@pytest.mark.parametrize("word", ["release", "publish", "twine", "gh release", "git push", "docker push", "pypi", "contents: write",
                                  "id-token", "continue-on-error", "--no-verify"])
def test_no_release_publish_or_write_step(word):
    executable = "\n".join(f"{s.get('run', '')} {s.get('uses', '')} {s.get('with', '')}" for job in WF["jobs"].values()
                           for s in job["steps"])
    assert word not in (executable + str(WF["permissions"])).lower()
    assert "continue-on-error" not in TEXT and "contents: write" not in TEXT


def test_the_conformance_job_exists_runs_the_cli_and_verifies_the_receipt():
    job = WF["jobs"]["conformance"]
    steps = "\n".join(str(s.get("run", "")) + str(s.get("uses", "")) for s in job["steps"])
    assert "redevops_qa_bridge.conformance.cli run" in steps and "cli verify" in steps and "upload-artifact" in steps
    assert job["strategy"]["matrix"]["pin_set"] == ["c3", "c4"]
    assert "pins" in job["needs"]


def test_the_bridge_job_fails_on_zero_tests_or_skips():
    steps = "\n".join(str(s.get("run", "")) for s in WF["jobs"]["bridge"]["steps"])
    assert "--junitxml" in steps and "tools/check_junit.py" in steps


@pytest.mark.parametrize("word", ["secrets.", "token", "qa_pins_read_token", "pat:", "password"])
def test_the_workflow_uses_no_secret_and_no_token(word):
    assert word not in TEXT.lower().replace("no token input", "").replace("no secret and no token", "")


def test_the_pinned_trees_are_fetched_at_the_commit_named_in_pins_toml():
    for job in ("bridge", "conformance"):
        fetches = [s for s in WF["jobs"][job]["steps"] if "repository" in s.get("with", {})]
        assert len(fetches) == 2
        for s in fetches:
            assert s["with"]["ref"].startswith("${{ steps.pins.outputs.") and s["with"]["persist-credentials"] is False
            assert set(s["with"]) == {"repository", "ref", "path", "persist-credentials"}      # no token input


def test_tests_run_in_a_scrubbed_environment():
    assert TEXT.count("env -i HOME=") >= 3


@pytest.mark.parametrize("job", ["bridge", "conformance"])
def test_every_pinned_job_verifies_the_fetched_trees_before_running_anything(job):
    steps = WF["jobs"][job]["steps"]
    runs = [str(s.get("run", "")) for s in steps]
    verify = next(i for i, r in enumerate(runs) if "--verify-trees --require-git" in r)
    fetch = max(i for i, s in enumerate(steps) if "repository" in s.get("with", {}))
    first_test = next(i for i, r in enumerate(runs) if "-m pytest" in r or "conformance.cli run" in r)
    assert fetch < verify < first_test
    assert any('test -z "$(git status --porcelain)"' in r for r in runs[:first_test])


def test_a_temp_pin_is_refused_except_on_a_feature_branch():
    step = WF["jobs"]["pins"]["steps"][-1]
    run = step["run"]
    assert "qa-p1/*|qa-ea/*|feature/*" in run and "--forbid-temp-pin" in run
    assert run.index("qa-p1/*|qa-ea/*|feature/*) flag=\"\"") < run.index("*) flag=\"--forbid-temp-pin\"")


def test_the_conformance_job_fails_on_zero_tests_and_skips_a_second_time_and_the_c4_receipt_may_list_no_not_applicable_item():
    steps = "\n".join(str(s.get("run", "")) for s in WF["jobs"]["conformance"]["steps"])
    assert 'tools/check_junit.py "$OUT/junit-conformance-' in steps and '--junit "$OUT/junit-conformance-' in steps
    # outputs are written outside the checkout (the receipt requires a clean tree) and the reviewed commit is checked out
    job = WF["jobs"]["conformance"]
    assert "env" not in job                       # the runner context is not available in job-level env
    assert 'echo "OUT=$RUNNER_TEMP/out" >> "$GITHUB_ENV"' in steps
    assert job["steps"][0]["with"]["ref"] == "${{ github.event.pull_request.head.sha || github.sha }}"
    assert not any(str(x) in steps for x in ("--receipt compat-receipt", "--junit junit-conformance", "--report divergence"))
    assert "--forbid-not-applicable" in steps and '"c4"' in steps


def test_the_adapter_licence_job_runs_the_checker_and_its_tests_offline_and_fails_on_skips():
    job = WF["jobs"]["adapter-licences"]
    steps = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert "tools/check_adapter_licenses.py" in steps and "tests/test_adapter_license_matrix.py" in steps
    assert "tools/check_junit.py" in steps and "--verify-upstream" not in steps      # offline: no download
    assert not any("repository" in s.get("with", {}) for s in job["steps"])          # no pinned upstream is fetched
    assert "needs" not in job and "continue-on-error" not in job


def test_the_neutral_wording_job_scans_the_tracked_files_offline_without_pins_and_fails_on_skips():
    job = WF["jobs"]["neutral-wording"]
    steps = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert "tools/check_neutral_wording.py" in steps and "tests/test_neutral_wording.py" in steps and "env -i HOME=" in steps
    assert "tools/check_junit.py" in steps and not any("repository" in s.get("with", {}) for s in job["steps"])
    assert "needs" not in job and "continue-on-error" not in job


def test_the_adapter_kit_job_is_offline_pin_free_and_fails_on_skips():
    job = WF["jobs"]["adapter-kit"]
    steps = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert "packages/qa-adapter-kit/tests" in steps and "env -i HOME=" in steps and "tools/check_junit.py" in steps
    assert not any("repository" in s.get("with", {}) for s in job["steps"]) and "needs" not in job and "playwright" not in steps.lower()


def test_the_fixture_app_job_is_offline_pin_free_runs_both_supported_pythons_and_fails_on_skips():
    job = WF["jobs"]["fixture-app"]
    steps = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert "packages/qa-fixture-app/tests" in steps and "env -i HOME=" in steps and "tools/check_junit.py" in steps
    assert job["strategy"]["matrix"]["python"] == ["3.11", "3.12"] and job["strategy"]["fail-fast"] is False
    assert not any("repository" in s.get("with", {}) for s in job["steps"]) and "needs" not in job and "continue-on-error" not in job
    assert "playwright" not in steps.lower() and "pip install" in steps and "--junitxml" in steps
    assert steps.count('test -z "$(git status --porcelain)"') == 2         # clean before and after: the tests write nothing into the tree


def test_the_selenium_offline_job_installs_no_selenium_and_the_browser_job_never_skips_or_downloads():
    offline = "\n".join(str(s.get("run", "")) for s in WF["jobs"]["selenium-offline"]["steps"])
    assert "selenium==" not in offline and "packages/qa-selenium/tests" in offline and "tools/check_junit.py" in offline
    steps = WF["jobs"]["selenium-browser"]["steps"]
    run = "\n".join(str(s.get("run", "")) for s in steps)
    assert '"selenium==4.52.0"' in run and "exit 1" in run and "-m browser packages/qa-selenium/tests/browser" in run
    assert "tools/check_junit.py" in run and "playwright install" not in run and "chrome-for-testing" not in run.lower() and "wget" not in run and "curl" not in run
    assert "continue-on-error" not in TEXT and "needs" not in WF["jobs"]["selenium-browser"]
    assert "NOT a required check until proven" in WF["jobs"]["selenium-browser"]["name"]
    assert not any("repository" in s.get("with", {}) for s in steps)


def test_the_robot_offline_job_installs_no_robot_and_the_real_job_never_skips():
    offline = "\n".join(str(s.get("run", "")) for s in WF["jobs"]["robot-offline"]["steps"])
    assert "robotframework==" not in offline and "packages/qa-robot/tests" in offline and "tools/check_junit.py" in offline
    steps = WF["jobs"]["robot-real"]["steps"]
    run = "\n".join(str(s.get("run", "")) for s in steps)
    assert '"robotframework==7.5"' in run and "-m robot_real packages/qa-robot/tests/real" in run and "tools/check_junit.py" in run
    assert "needs" not in WF["jobs"]["robot-real"] and "NOT a required check until proven" in WF["jobs"]["robot-real"]["name"]
    assert not any("repository" in s.get("with", {}) for s in steps)


def test_the_appium_offline_job_installs_no_appium_and_the_real_jobs_never_skip_install_licences_or_emulators():
    offline = "\n".join(str(s.get("run", "")) for s in WF["jobs"]["appium-offline"]["steps"])
    assert "Appium-Python-Client" not in offline and "npm" not in offline and "packages/qa-appium/tests" in offline and "tools/check_junit.py" in offline
    for job, marker in ((WF["jobs"]["appium-server"], "appium_server"), (ANDROID_WF["jobs"]["appium-android"], "appium_android")):
        run = "\n".join(str(s.get("run", "")) for s in job["steps"])
        assert f"-m {marker} packages/qa-appium/tests/real" in run and "tools/check_junit.py" in run and "needs" not in job
        assert "NOT a required check" in job["name"] and "--ignore-scripts" in run and "appium@3.9.0" in run and "uiautomator2@8.7.3" in run
        assert not any(w in run.lower() for w in ("sdkmanager", "avdmanager", "--licenses", "system-images", "emulator -avd", "kvm"))
        assert not any("repository" in s.get("with", {}) for s in job["steps"])
    android = "\n".join(str(s.get("run", "")) for s in ANDROID_WF["jobs"]["appium-android"]["steps"])
    assert android.index("exit 1") < android.index("pip install") and "no Android emulator or device" in android and "manual" in ANDROID_WF["jobs"]["appium-android"]["name"]
    server_run = "\n".join(str(s.get("run", "")) for s in WF["jobs"]["appium-server"]["steps"])
    assert "ANDROID_HOME" not in server_run         # the server lane starts its server without any Android SDK variable


# -- the real-device Android lane is its own manual workflow ------------------------------------------------------------------------------------------------------

def test_no_job_in_the_main_workflow_is_red_by_design():
    assert "appium-android" not in WF["jobs"]
    assert not any("EXPECTED RED" in str(job.get("name", "")) for job in WF["jobs"].values())


def test_the_android_workflow_is_manual_only_and_read_only():
    assert set(ANDROID_TRIGGERS) == {"workflow_dispatch"}                       # no push, pull request, schedule or tag trigger
    assert ANDROID_WF["permissions"] == {"contents": "read"}
    assert list(ANDROID_WF["jobs"]) == ["appium-android"]
    job = ANDROID_WF["jobs"]["appium-android"]
    assert "permissions" not in job or all(v == "read" for v in job["permissions"].values())
    assert "needs" not in job and "NOT a required check" in job["name"]


def test_the_android_workflow_takes_one_runner_label_and_nothing_else():
    inputs = ANDROID_TRIGGERS["workflow_dispatch"]["inputs"]
    assert set(inputs) == {"runner"} and inputs["runner"]["type"] == "string" and inputs["runner"]["required"] is True
    assert ANDROID_WF["jobs"]["appium-android"]["runs-on"] == "${{ inputs.runner }}"
    # the input is used only as the runner label, never inside a shell command or a step
    steps = "\n".join(str(s) for s in ANDROID_WF["jobs"]["appium-android"]["steps"])
    assert "inputs." not in steps


@pytest.mark.parametrize("word", ["release", "publish", "twine", "gh release", "git push", "docker push", "pypi", "contents: write", "id-token",
                                  "continue-on-error", "--no-verify", "secrets.", "qa_pins_read_token", "pat:", "password"])
def test_the_android_workflow_has_no_publish_write_or_secret(word):
    executable = "\n".join(f"{s.get('run', '')} {s.get('uses', '')} {s.get('with', '')}" for s in ANDROID_WF["jobs"]["appium-android"]["steps"])
    assert word not in (executable + str(ANDROID_WF["permissions"])).lower()
    if word in ("secrets.", "qa_pins_read_token", "pat:", "password", "contents: write", "id-token", "continue-on-error"):
        assert word not in ANDROID_TEXT.lower()                                  # not even in a comment or a key
    assert "token" not in ANDROID_TEXT.lower().replace("no secret and no token input", "")


def test_the_evidence_job_is_offline_pin_free_scrubbed_and_fails_on_skips():
    job = WF["jobs"]["evidence"]
    steps = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert "packages/qa-evidence/tests" in steps and "env -i HOME=" in steps and "tools/check_junit.py" in steps and "--junitxml" in steps
    assert not any("repository" in s.get("with", {}) for s in job["steps"]) and "needs" not in job and "continue-on-error" not in job
    assert "playwright" not in steps.lower() and "upload-artifact" not in str(job)
    assert any('test -z "$(git status --porcelain)"' in str(s.get("run", "")) for s in job["steps"])


def test_the_runner_job_is_offline_scrubbed_pinned_and_fails_on_skips():
    job = WF["jobs"]["runner"]
    steps = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert "packages/qa-runner/tests" in steps and "env -i HOME=" in steps and "tools/check_junit.py" in steps and "--junitxml" in steps
    assert job["strategy"]["matrix"]["python"] == ["3.11", "3.12"] and job["strategy"]["fail-fast"] is False and "pins" in job["needs"]
    fetches = [s for s in job["steps"] if "repository" in s.get("with", {})]
    assert len(fetches) == 2 and all(s["with"]["ref"].startswith("${{ steps.pins.outputs.") and s["with"]["persist-credentials"] is False for s in fetches)
    assert "--verify-trees --require-git" in steps and "playwright" not in steps.lower() and "continue-on-error" not in job and "upload-artifact" not in str(job)
    assert "-m browser" not in steps


def test_the_runner_browser_job_runs_only_the_browser_tests_in_a_scrubbed_environment_and_fails_on_skips():
    job = WF["jobs"]["runner-browser"]
    steps = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert "-m browser packages/qa-runner/tests/browser" in steps and "env -i HOME=" in steps and "tools/check_junit.py" in steps and "--junitxml" in steps
    assert "playwright==1.64.1" in steps and "playwright install --with-deps chromium" in steps and "PLAYWRIGHT_BROWSERS_PATH" in steps
    assert "pins" in job["needs"] and "continue-on-error" not in job and "upload-artifact" not in str(job)
    fetches = [s for s in job["steps"] if "repository" in s.get("with", {})]
    assert len(fetches) == 2 and "--verify-trees --require-git" in steps
    assert steps.count('test -z "$(git status --porcelain)"') == 2


def test_the_runner_documentation_states_what_it_does_not_show():
    text = (ROOT / "packages" / "qa-runner" / "README.md").read_text(encoding="utf-8")
    for needle in ("unkeyed", "does not say the application is correct", "Linux x86_64", "never installs", "source-available, not open source"):
        assert needle in text
    assert "open source" not in text.replace("not open source", "")


def test_the_runner_robot_job_installs_robot_not_a_browser_runs_only_the_real_tests_and_fails_on_skips():
    job = WF["jobs"]["runner-robot"]
    steps = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert '"robotframework==7.5"' in steps and "-m robot_real packages/qa-runner/tests/real" in steps and "env -i HOME=" in steps
    assert "playwright" not in steps.lower() and "tools/check_junit.py" in steps and "--junitxml" in steps
    assert "pins" in job["needs"] and "continue-on-error" not in job and "upload-artifact" not in str(job)
    fetches = [s for s in job["steps"] if "repository" in s.get("with", {})]
    assert len(fetches) == 2 and "--verify-trees --require-git" in steps and steps.count('test -z "$(git status --porcelain)"') == 2
    offline = "\n".join(str(s.get("run", "")) for s in WF["jobs"]["runner"]["steps"])
    assert "robotframework" not in offline.lower()
