# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Invariants of the workflows that build and install the bundle. The main workflow (tests.yml) must stay free of anything that publishes (tests/test_workflow.py guards that, word
by word), so the manual build lives in its own file, and its guards are here: manual only, read-only, no secret, no tag, no release, and a `publish` input that cannot do anything."""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_TEXT = (ROOT / ".github" / "workflows" / "bundle.yml").read_text(encoding="utf-8")
BUNDLE = yaml.safe_load(BUNDLE_TEXT)
TRIGGERS = BUNDLE.get(True) or BUNDLE.get("on")
MAIN_TEXT = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
MAIN = yaml.safe_load(MAIN_TEXT)
ACCEPT = (ROOT / "tools" / "bundle_acceptance.sh").read_text(encoding="utf-8")


def executable(wf):
    return "\n".join(f"{s.get('run', '')} {s.get('uses', '')} {s.get('with', '')} {s.get('env', '')}" for job in wf["jobs"].values() for s in job["steps"])


# -------------------------------------------------------------------------------------------------------------------------- the manual build
def test_the_manual_build_is_triggered_by_workflow_dispatch_and_nothing_else():
    assert set(TRIGGERS) == {"workflow_dispatch"}
    assert "push" not in TRIGGERS and "pull_request" not in TRIGGERS and "schedule" not in TRIGGERS and "workflow_run" not in TRIGGERS and "workflow_call" not in TRIGGERS


def test_the_publish_input_exists_defaults_to_false_and_is_refused_when_true():
    publish = TRIGGERS["workflow_dispatch"]["inputs"]["publish"]
    assert publish["type"] == "boolean" and publish["default"] is False
    first = BUNDLE["jobs"]["build"]["steps"][0]
    assert first["env"] == {"PUBLISH": "${{ inputs.publish }}"} and '[ "$PUBLISH" = "true" ]' in first["run"] and "exit 1" in first["run"]
    assert "inputs.publish" not in "\n".join(str(s.get("run", "")) for s in BUNDLE["jobs"]["build"]["steps"])           # an input is never interpolated into a script


def test_the_manual_build_is_read_only_and_names_no_secret_or_write_path():
    assert BUNDLE["permissions"] == {"contents": "read"}
    for job in BUNDLE["jobs"].values():
        assert "permissions" not in job and "env" not in job and "continue-on-error" not in job
    low = BUNDLE_TEXT.lower()
    for word in ("secrets.", "github_token", "id-token", "contents: write", "packages: write", "gh release", "gh api", "git tag", "git push", "twine", "docker", "ghcr", "attest", "pypi",
                 "create-release", "action-gh-release", "continue-on-error", "--no-verify", "sudo"):
        assert word not in low, word


def test_the_manual_build_uses_only_the_actions_the_repository_already_uses_and_keeps_an_artifact_only():
    uses = {s["uses"] for job in BUNDLE["jobs"].values() for s in job["steps"] if "uses" in s}
    assert {u.split("@")[0] for u in uses} == {"actions/checkout", "actions/setup-python", "actions/upload-artifact"}
    assert all(re.fullmatch(r"[0-9a-f]{40}", u.split("@")[1]) for u in uses), uses                    # pinned by commit, not by a tag that can move
    uploads = [s for job in BUNDLE["jobs"].values() for s in job["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact")]
    assert len(uploads) == 1 and uploads[0]["with"]["name"] == "qa-bundle" and uploads[0]["with"]["if-no-files-found"] == "error"
    assert all(s.get("with", {}).get("persist-credentials") is False for job in BUNDLE["jobs"].values() for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout"))


def test_the_manual_build_verifies_the_pinned_trees_refuses_a_temp_pin_and_checks_the_bundle_it_made():
    runs = [str(s.get("run", "")) for s in BUNDLE["jobs"]["build"]["steps"]]
    joined = "\n".join(runs)
    assert "--forbid-temp-pin" in joined and "--verify-trees --require-git" in joined
    assert runs.index(next(r for r in runs if "--verify-trees" in r)) < runs.index(next(r for r in runs if "build_bundle.py build" in r)) < runs.index(next(r for r in runs if "check_bundle.py" in r))
    assert 'test -z "$(git status --porcelain)"' in joined and "python -I" in joined
    assert 'env:\n          LABEL: ${{ inputs.label }}' in BUNDLE_TEXT and '--label "$LABEL"' in joined


def test_the_pinned_inputs_of_the_manual_build_are_fetched_by_commit_with_no_token():
    fetches = [s for s in BUNDLE["jobs"]["build"]["steps"] if "repository" in s.get("with", {})]
    assert len(fetches) == 2
    for s in fetches:
        assert s["with"]["ref"].startswith("${{ steps.pins.outputs.") and set(s["with"]) == {"repository", "ref", "path", "persist-credentials"}


def test_the_main_workflow_has_no_manual_trigger_so_the_build_cannot_be_started_from_it():
    assert set(MAIN.get(True) or MAIN.get("on")) <= {"push", "pull_request"}


# ------------------------------------------------------------------------------------------ the bundle jobs of the main workflow
BUNDLE_JOBS = ("bundle-tests", "bundle", "bundle-install")


@pytest.mark.parametrize("job", BUNDLE_JOBS)
def test_the_bundle_jobs_run_on_ubuntu_2404_read_only_without_a_secret_or_a_skip_escape(job):
    j = MAIN["jobs"][job]
    assert j["runs-on"] == "ubuntu-24.04" and "continue-on-error" not in j and ("permissions" not in j or all(v == "read" for v in j["permissions"].values()))
    text = "\n".join(f"{s.get('run', '')} {s.get('with', '')}" for s in j["steps"]).lower()
    for word in ("secrets.", "token", "release", "publish", "twine", "pypi", "docker", "gh api", "git push", "git tag", "id-token"):
        assert word not in text, (job, word)


def test_the_bundle_tests_job_runs_the_tests_in_a_scrubbed_environment_and_fails_on_zero_tests_or_skips():
    steps = MAIN["jobs"]["bundle-tests"]["steps"]
    run = "\n".join(str(s.get("run", "")) for s in steps)
    for f in ("tests/test_bundle_builder.py", "tests/test_bundle_install.py", "tests/test_bundle_pinned.py", "tests/test_bundle_workflow.py", "tests/test_workflow.py"):
        assert f in run
    assert "env -i HOME=" in run and "tools/check_junit.py" in run and run.count('test -z "$(git status --porcelain)"') == 2
    assert MAIN["jobs"]["bundle-tests"]["needs"] == "pins"
    assert any("--verify-trees --require-git" in str(s.get("run", "")) for s in steps)                    # test_bundle_pinned.py needs the verified trees


def test_the_bundle_job_builds_twice_compares_and_keeps_two_archives_as_artifacts_only():
    job = MAIN["jobs"]["bundle"]
    run = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert run.count("tools/build_bundle.py build") == 3 and "--download-cache \"$RUNNER_TEMP/cache-2\"" in run and "--label rollback-previous" in run
    assert "cmp \"$a\" \"$b\"" in run and "diff -u" in run and "exit 1" in run
    assert "python -I \"$GITHUB_WORKSPACE/tools/check_bundle.py\"" in run
    uploads = {s["with"]["name"] for s in job["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact")}
    assert uploads == {"qa-bundle-current", "qa-bundle-previous"}
    assert job["needs"] == "pins" and any("--verify-trees --require-git" in str(s.get("run", "")) for s in job["steps"])


def test_the_bundle_install_job_starts_from_the_kept_archives_and_runs_the_acceptance_script():
    job = MAIN["jobs"]["bundle-install"]
    assert job["needs"] == "bundle"
    downloads = {s["with"]["name"] for s in job["steps"] if str(s.get("uses", "")).startswith("actions/download-artifact")}
    assert downloads == {"qa-bundle-current", "qa-bundle-previous"}
    run = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert "tools/bundle_acceptance.sh --current" in run and "--previous" in run
    assert not any(str(s.get("uses", "")).startswith("actions/upload-artifact") for s in job["steps"])


# -------------------------------------------------------------------------------------------------------------- the acceptance script
def test_the_acceptance_script_runs_the_commands_of_the_readme_and_nothing_else_for_the_happy_path():
    assert "set -euo pipefail" in ACCEPT and "readme_block.py" in ACCEPT
    for block in ("unpack", "install", "use", "uninstall"):
        assert f"for b in unpack install use uninstall" in ACCEPT and (ROOT / "bundle" / "README.md").read_text(encoding="utf-8").count(f"<!-- bundle-commands: {block} -->") == 1
    assert "tar xOf" in ACCEPT                                     # the README comes out of the archive that is being installed


@pytest.mark.parametrize("fragment", ["tampered wheel, sums unchanged", "SHA256SUMS rewritten: pip --require-hashes", "THESE PACKAGES DO NOT MATCH THE HASHES", "a lock that names a version the wheelhouse does not hold",
                                      "another Python minor", "another platform", "rollback", "is the directory clean", "ACCEPTANCE OK", "left under HOME"])
def test_the_acceptance_script_checks_every_acceptance_item(fragment):
    assert fragment in ACCEPT


def test_the_acceptance_script_downloads_and_deletes_nothing_outside_its_work_directory():
    assert "curl" not in ACCEPT and "wget" not in ACCEPT and "pip install" not in ACCEPT
    for line in ACCEPT.splitlines():
        if re.search(r"\brm\b", line) and "#" not in line.split("rm")[0]:
            assert '"$WORK' in line, line


# ------------------------------------------------------------------------------------------------------------------------------------- the demo jobs
DEMO_JOBS = ("demo", "demo-verify")


@pytest.mark.parametrize("job", DEMO_JOBS)
def test_the_demo_jobs_are_read_only_on_ubuntu_2404_and_name_no_secret_or_publishing_step(job):
    j = MAIN["jobs"][job]
    assert j["runs-on"] == "ubuntu-24.04" and "continue-on-error" not in j and ("permissions" not in j or all(v == "read" for v in j["permissions"].values()))
    assert j["strategy"]["fail-fast"] is False
    text = "\n".join(f"{s.get('run', '')} {s.get('with', '')} {s.get('env', '')}" for s in j["steps"]).lower()
    for word in ("secrets.", "token", "release", "publish", "twine", "pypi", "docker", "gh api", "git push", "git tag", "id-token"):
        assert word not in text, (job, word)


def test_the_demo_jobs_run_the_three_defects_with_the_expected_exit_statuses():
    for job in DEMO_JOBS:
        assert MAIN["jobs"][job]["strategy"]["matrix"]["include"] == [{"defect": "none", "exit": 0}, {"defect": "discount", "exit": 1}, {"defect": "settings", "exit": 1}]


def test_the_demo_job_installs_the_kept_bundle_with_the_readme_commands_runs_the_demo_checks_it_and_keeps_the_evidence_and_the_anchor():
    job = MAIN["jobs"]["demo"]
    assert job["needs"] == "bundle"
    run = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert 'tar xOf "$RUNNER_TEMP/dl/$name.tar" "$name/README.md"' in run and run.count("tools/readme_block.py") == 2 and " unpack" in run and " install" in run
    assert '"$HOME/redevops-qa/bin/redevops-qa" demo --defect "$DEFECT" --out "$RUNNER_TEMP/evidence" > "$RUNNER_TEMP/demo.out" 2>&1 || status=$?' in run
    assert "| tee" not in run                       # the default shell of a step has no pipefail: a pipe would hide the exit status of the command in front of it
    assert "python -I \"$GITHUB_WORKSPACE/tools/check_demo_outcome.py\" run" in run and "--exit-code \"$STATUS\"" in run and "GITHUB_STEP_SUMMARY" in run
    uploads = {s["with"]["name"]: s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact")}
    assert set(uploads) == {"demo-evidence-${{ matrix.defect }}", "demo-anchor-${{ matrix.defect }}"}
    assert uploads["demo-evidence-${{ matrix.defect }}"]["if"] == "always()" and all(u["with"]["if-no-files-found"] == "error" for u in uploads.values())
    names = [s.get("name", "") for s in job["steps"]]
    assert names.index("Run the demo (the exit status is checked in the next step)") < names.index("Check the outcome against the seeded defect and print the anchor") < names.index("Keep the evidence bundle")


def test_the_verify_job_is_a_second_job_that_starts_from_the_kept_artifacts_in_a_new_directory_and_refuses_a_changed_bundle_and_a_wrong_anchor():
    job = MAIN["jobs"]["demo-verify"]
    assert job["needs"] == ["bundle", "demo"]
    downloads = {s["with"]["name"] for s in job["steps"] if str(s.get("uses", "")).startswith("actions/download-artifact")}
    assert downloads == {"qa-bundle-current", "demo-evidence-${{ matrix.defect }}", "demo-anchor-${{ matrix.defect }}"}
    run = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert './install.sh --prefix "$RUNNER_TEMP/verifier"' in run and "install-browser" not in run and "--with-deps" not in run
    assert "verify \"$bundle\" --anchor \"$anchor\" --plan-digest \"$plan\" --require-anchor --require-plan-digest --json" in run
    assert "check_demo_outcome.py\" verify" in run and run.count('test "$status" -eq 5') == 2 and "printf 'x' >> \"$RUNNER_TEMP/changed/report.json\"" in run
    # a refusal is checked by its finding codes, not only by the exit status (any crash that exits 5 would otherwise pass)
    for code in ("SIZE_MISMATCH report.json", "REPORT_UNREADABLE report.json", "ANCHOR_MISMATCH anchor", "ANCHOR_REQUIRED anchor"):
        assert f'grep -q "^  {code}:"' in run, code
    assert "--anchor \"sha256:$(printf '0%.0s' $(seq 64))\"" in run
    assert not any(str(s.get("uses", "")).startswith("actions/upload-artifact") for s in job["steps"])


def test_the_new_test_files_run_in_the_bundle_tests_job():
    run = "\n".join(str(s.get("run", "")) for s in MAIN["jobs"]["bundle-tests"]["steps"])
    assert "tests/test_demo_outcome.py" in run and "tests/test_readme_layout.py" in run


@pytest.mark.parametrize("job", DEMO_JOBS)
def test_no_step_of_the_demo_jobs_pipes_a_command_whose_exit_status_matters_through_another(job):
    """A step without an explicit shell runs `bash -e {0}`: no pipefail, so `cmd | tee file` succeeds when `cmd` fails. (The first version of the demo job lost the demo's exit status this way.)"""
    for step in MAIN["jobs"][job]["steps"]:
        for line in str(step.get("run", "")).splitlines():
            code = line.split("#")[0]
            assert not re.search(r"\)\s*\|\s*tee\b|[^|]\|\s*tee\b", code) or "pipefail" in str(step.get("run", "")) or step.get("shell"), line
