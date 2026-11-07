# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The README names what the repository holds and nothing else: every package it lists exists, every package that exists is listed, what is absent is said to be absent, and every
relative link resolves. (An earlier README named four packages and a deploy directory that did not exist.)"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
PACKAGES = sorted(p.name for p in (ROOT / "packages").iterdir() if (p / "pyproject.toml").is_file())
NOT_HERE = README.split("**Not in this repository:**", 1)[1].split("\n\n", 1)[0] if "**Not in this repository:**" in README else ""
LAYOUT = README.split("## Layout", 1)[1]


def test_every_package_the_readme_lists_exists_and_every_package_is_listed():
    listed = re.search(r"Packages \(under `packages/`\): (.*?)\.\n", LAYOUT, re.S).group(1)
    names = re.findall(r"`(qa-[a-z-]+)`", listed)
    assert sorted(names) == PACKAGES and len(set(names)) == len(names)


def test_what_the_readme_names_as_absent_is_absent_and_said_so():
    assert NOT_HERE, "the README must say what is not in the repository"
    for name in ("qa-api", "qa-ui"):
        assert f"`{name}`" in NOT_HERE and not (ROOT / "packages" / name).exists()
    for path in ("deploy", "benchmarks", "examples"):
        assert not (ROOT / path).exists()
    assert "`deploy/`" in NOT_HERE and "benchmarks" in NOT_HERE


def test_no_package_is_named_outside_the_absent_list_unless_it_exists():
    absent = set(re.findall(r"`(qa-[a-z-]+)`", NOT_HERE))
    for name in set(re.findall(r"`(qa-[a-z-]+)`", README)):
        assert name in PACKAGES or name in absent, name


def test_every_relative_link_of_the_readme_resolves():
    for target in re.findall(r"\]\((?!https?://|#)([^)#]+)(?:#[^)]*)?\)", README):
        assert (ROOT / target).exists(), target


def test_the_readme_does_not_call_the_project_open_source_and_does_not_claim_other_platforms():
    low = README.lower()
    assert not re.search(r"(?<!not )open[- ]source", low) and "soc 2" not in low and "tamper-proof" not in low
    assert "macos and windows are not claimed" in low and "linux x86_64" in low


ORCH = (ROOT / "packages" / "qa-runner" / "src" / "qa_runner" / "orchestrate.py").read_text(encoding="utf-8")
FIRST_SCREEN = README.split("## What runs in CI", 1)[0]


def test_the_first_screen_admits_the_fixture_only_scope_while_the_code_hard_wires_it():
    """Audit item P0-4, testable form: while `run` still hard-wires `target fixture-app`, the opening screen must
    say the runner runs only against the bundled fixture app, and it must list the unsupported platforms there.
    When P2-1 removes the hard-wiring the condition lifts; the sentence may then move, but it may not be dropped
    while the code still refuses an external target."""
    hard_wired = "target fixture-app" in ORCH or '"target": "fixture-app"' in ORCH
    if hard_wired:
        assert "run only against the bundled fixture app" in FIRST_SCREEN, \
            "orchestrate.py hard-wires the fixture app: the README first screen must say so"
    assert "linux x86_64" in FIRST_SCREEN.lower() and "macos and windows are not claimed" in FIRST_SCREEN.lower()


# ------------------------------------------------------------------------------------------------------------------ the demo page cites a run on main
DEMO = (ROOT / "docs" / "QA_DEMO.md").read_text(encoding="utf-8")


def test_the_demo_page_cites_a_run_on_main_with_its_jobs_and_anchors_and_no_branch_run():
    assert "actions/runs/41591460007" in DEMO and "head commit `d856bab` of `main`" in DEMO
    assert "41566638020" not in DEMO and "a93dfc3" not in DEMO and "on a branch" not in DEMO
    anchors = re.findall(r"`(sha256:[0-9a-f]{64})`", DEMO)
    assert len(set(anchors)) >= 4                                              # the three anchors and the plan digest
    for job in ("125769400806", "125769400825", "125769400895", "125769764235", "125769764661", "125769764369"):
        assert f"runs/41591460007/job/{job}" in DEMO, job


def test_the_demo_page_keeps_its_statements_about_the_anchor_and_says_what_happens_as_root():
    low = DEMO.lower()
    assert "nothing in the tool authenticates where the value came from" in low and "differ from run to run" in low and "unkeyed" in low
    assert "## Running it as root" in DEMO and "PROHIBITED_PATH" in DEMO and "/opt/redevops-qa" in DEMO and "`INCONCLUSIVE`" in DEMO
    assert "tamper-proof" not in low and not re.search(r"(?<!not )open[- ]source", low)


# ---- the developer-checkout job (audit item P1-5) ---------------------------------------------------------------
WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _dev_checkout_steps():
    import yaml
    wf = yaml.safe_load((WORKFLOWS / "tests.yml").read_text(encoding="utf-8"))
    return [str(s.get("run", "")) for s in wf["jobs"]["dev-checkout"]["steps"] if s.get("run")]


def test_the_dev_checkout_job_runs_the_readme_block_rather_than_a_retyped_copy():
    steps = "\n".join(_dev_checkout_steps())
    assert "tools/readme_block.py README.md dev-checkout" in steps, "the commands must come out of the README"
    assert 'bash "$RUNNER_TEMP/dev-checkout.sh"' in steps


def test_the_dev_checkout_job_runs_the_block_where_the_suite_expect_to_be_run():
    # Every other test job in tests.yml runs pytest under `env -i` with a temporary HOME, because the suite
    # fails on ambient user state (a HOME outside a temp directory; a USER value landing in a run-built
    # archive). The documented checkout must run the same way, or the job reports the environment as a defect.
    steps = "\n".join(_dev_checkout_steps())
    assert 'env -i HOME="$(mktemp -d)"' in steps
    assert 'bash "$RUNNER_TEMP/dev-checkout.sh"' in steps
    # the job still insists the checkout left the tree clean, and nothing in this workflow may be allowed to fail
    later = (WORKFLOWS / "tests.yml").read_text(encoding="utf-8")
    assert 'test -z "$(git status --porcelain)"' in later
    assert "continue-on-error" not in later


