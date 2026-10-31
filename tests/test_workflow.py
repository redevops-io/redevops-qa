# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The CI workflow is read-only, has no tag or publish trigger, and cannot let a skip or an empty run pass."""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
WF = yaml.safe_load(TEXT)
TRIGGERS = WF.get(True) or WF.get("on")


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


def test_the_adapter_kit_job_is_offline_pin_free_and_fails_on_skips():
    job = WF["jobs"]["adapter-kit"]
    steps = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert "packages/qa-adapter-kit/tests" in steps and "env -i HOME=" in steps and "tools/check_junit.py" in steps
    assert not any("repository" in s.get("with", {}) for s in job["steps"]) and "needs" not in job and "playwright" not in steps.lower()
