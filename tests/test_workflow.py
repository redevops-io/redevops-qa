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


def test_the_pinned_trees_are_fetched_at_the_commit_named_in_pins_toml():
    for job in ("bridge", "conformance"):
        fetches = [s for s in WF["jobs"][job]["steps"] if "repository" in s.get("with", {})]
        assert len(fetches) == 2
        for s in fetches:
            assert s["with"]["ref"].startswith("${{ steps.pins.outputs.") and s["with"]["persist-credentials"] is False


def test_tests_run_in_a_scrubbed_environment():
    assert TEXT.count("env -i HOME=") >= 3
