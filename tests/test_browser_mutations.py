# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Mutation tests for the browser pin outside the runner package: removing a guard of ``install-browser.sh``, the builder or the checker makes the named tests fail. Each case copies the
files the tests need into a temporary tree, changes one guard there, and runs the named tests on the copy (the same tests must pass on an unmodified copy)."""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KEEP = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")

BB = "tests/test_bundle_browser.py"
BL = "tests/test_bundle_browser_lock.py"
BP = "tests/test_bundle_pinned.py"
BI = "tests/test_bundle_install.py"
BW = "tests/test_bundle_workflow.py"


def t(file, name):
    return f"{file}::{name}"


def copy_tree(tmp: Path) -> Path:
    work = tmp / "repo"
    for rel in ("tests", "tools", "bundle", "packages/qa-runner/tests", "pins.toml", "docs", ".github", "README.md"):
        src = ROOT / rel
        dst = work / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
        else:
            shutil.copyfile(src, dst)
    for src in sorted((ROOT / "packages").glob("*/src")):                       # the sources of every package (qa_runner imports the others); their tests are not needed
        shutil.copytree(src, work / "packages" / src.parent.name / "src", ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    pinned = ROOT / ".pinned"
    if pinned.exists():
        os.symlink(pinned.resolve(), work / ".pinned")
    return work


def run_tests(work: Path, tests):
    env = {k: os.environ[k] for k in KEEP if k in os.environ}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for k in ("REDEVOPS_QA_PIN_SET",):
        if k in os.environ:
            env[k] = os.environ[k]
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "--rootdir", str(work), *tests], cwd=work, env=env, capture_output=True, text=True, timeout=1500)


def mutate(work: Path, rel: str, old, new):
    target = work / rel
    text = target.read_text(encoding="utf-8")
    olds, news = ((old,), (new,)) if isinstance(old, str) else (tuple(old), tuple(new))
    for o, n in zip(olds, news):
        assert text.count(o) == 1, f"mutation anchor must occur exactly once in {rel}; found {text.count(o)}: {o!r}"
        text = text.replace(o, n)
    target.write_text(text, encoding="utf-8")


SH = "bundle/install-browser.sh"
CB = "tools/check_bundle.py"
BBUILD = "tools/build_bundle.py"
COMMIT_LINE = 'out="$(pin commit --lock "$installed_lock" --browsers "$browsers" --staging "$staging")" || fail 6 "the verified browser could not be moved into place"\n'

CASES = [
    ("script: the bundle's lock must be the installation's", SH, 'cmp -s "$bundle_lock" "$installed_lock" || fail 4', 'true || fail 4',
     [t(BB, "test_a_script_from_another_bundle_whose_lock_differs_is_refused_before_anything_is_created")]),
    ("script: an installation without the pin is refused", SH, '[ -f "$installed_lock" ] || fail 5', 'true || fail 5',
     [t(BB, "test_an_installation_without_the_pin_is_refused")]),
    ("script: a bundle directory without its lock is refused", SH, '[ -f "$bundle_lock" ] || fail 4', 'true || fail 4',
     [t(BB, "test_a_bundle_directory_without_its_lock_is_refused")]),
    ("script: a failed download-and-verify stops the step", SH, '|| fail 6 "the browser could not be downloaded and verified; nothing was installed"', '|| true',
     [t(BB, "test_a_truncated_archive_fails_with_exit_6_names_the_expected_and_the_actual_hash_and_leaves_nothing"), t(BB, "test_one_changed_byte_in_one_archive_installs_none_of_the_three")]),
    ("script: apt runs only after the archives were verified and before anything is placed", SH, [COMMIT_LINE, 'if [ "$deps" -eq 1 ]; then\n'], ["", COMMIT_LINE + 'if [ "$deps" -eq 1 ]; then\n'],
     [t(BB, "test_with_deps_runs_after_the_archives_were_verified_and_before_anything_is_placed")]),
    ("script: a failing apt step places nothing", SH, '"$py" -m playwright install-deps chromium || fail 6', '"$py" -m playwright install-deps chromium || true; echo ignored || fail 6',
     [t(BB, "test_a_failing_with_deps_places_nothing")]),
    ("script: the staging directory is removed on every exit", SH, '  rm -rf -- "$staging"\n', "  true\n",
     [t(BB, "test_an_interrupted_install_leaves_no_staging_directory"), t(BB, "test_a_failing_with_deps_places_nothing")]),
    ("script: a browsers directory this run created is removed when nothing was installed", SH, 'if [ "$created" -eq 1 ]; then rmdir "$browsers" 2>/dev/null || true; fi', "true",
     [t(BB, "test_a_truncated_archive_fails_with_exit_6_names_the_expected_and_the_actual_hash_and_leaves_nothing")]),
    ("script: the installed tree is checked after the placement", SH, 'pin verify --lock "$installed_lock" --browsers "$browsers" || fail 6', 'true || fail 6',
     [t(BB, "test_a_good_install_checks_every_archive_unpacks_checks_the_tree_and_places_it")]),
    ("script: a browsers directory that is a link is refused", SH, '[ -d "$browsers" ] && [ ! -L "$browsers" ] || fail 5', 'true || fail 5',
     [t(BB, "test_a_symbolic_link_as_the_browsers_directory_is_refused")]),
    ("script: the system libraries are installed only on request", SH, 'if [ "$deps" -eq 1 ]; then\n', 'if true; then\n',
     [t(BB, "test_without_with_deps_the_system_packages_are_not_touched")]),
    ("checker: the lock is the lock of the Playwright wheel in the bundle (version and browsers.json digest)", CB,
     'if pws[0].get("version") != pw["version"] or hashlib.sha256(raw).hexdigest() != pw["browsers_json_sha256"]:', "if False:",
     [t(BL, "test_the_checker_finds_a_lock_that_is_for_another_revision_or_wheel_than_the_one_in_the_bundle")]),
    ("checker: the revision the Playwright wheel expects is the pinned one", CB, 'if str(chromium["revision"]) != br["revision"] or chromium.get("browserVersion") != br["browser_version"]:', "if False:",
     [t(BL, "test_the_checker_finds_a_lock_that_is_for_another_revision_or_wheel_than_the_one_in_the_bundle")]),
    ("checker: the record in BUNDLE.json is made from the lock file", CB, 'if record.get("lock_sha256") != hashlib.sha256(data).hexdigest() or record.get("lock") != "browser.lock.json":', "if False:",
     [t("tests/test_bundle_builder.py", "test_a_manifest_whose_browser_record_is_not_what_the_lock_says_is_found")]),
    ("checker: the lock's tree digest is checked", CB, "              and lock.get(\"tree_sha256\") == _tree_digest(tree) and", "              and",
     [t(BL, "test_the_checker_finds_a_lock_whose_tree_was_edited_without_its_digest")]),
    ("checker: the browser record says not shipped, fetched at install and pinned", CB,
     'if browser.get("shipped_in_bundle") is not False or browser.get("fetched_at_install") is not True or browser.get("pinned_by_this_bundle") is not True:', "if False:",
     [t("tests/test_bundle_builder.py", "test_a_manifest_whose_browser_record_is_not_what_the_lock_says_is_found")]),
    ("checker: a release bundle holds the Playwright wheel the lock is checked against", CB, "    elif not allow_test_target:\n        out.append(Finding(\"BROWSER_LOCK\"", "    elif False:\n        out.append(Finding(\"BROWSER_LOCK\"",
     [t(BL, "test_a_release_bundle_needs_the_playwright_wheel_the_lock_is_checked_against")]),
    ("checker: the pinned wheel carries the bundle's lock", CB, "            if browser_lock is not None and (", "            if False and (",
     [t(BP, "test_the_wheel_carries_the_browser_lock_under_share_and_the_checker_compares_it_with_the_bundles_copy")]),
    ("checker: the lock file is required", CB, '"uninstall.sh", "browser.lock.json")', '"uninstall.sh")',
     [t(BL, "test_the_checker_passes_a_consistent_bundle_and_requires_the_lock_file")]),
    ("builder: a lock that is not for the bundled Playwright wheel is refused", BBUILD, '    if (wheel_name_version(wheel.name)[1] != lock["playwright"]["version"]', '    if False and (wheel_name_version(wheel.name)[1] != lock["playwright"]["version"]',
     [t(BL, "test_the_builder_refuses_a_lock_that_is_not_for_the_playwright_wheel_it_bundles")]),
    ("builder: the lock is carried into the bundle", BBUILD, "    (bdir / BROWSER_LOCK).write_bytes(lock_bytes)\n", "    pass\n",
     [t(BL, "test_the_builder_carries_the_lock_into_the_bundle_and_records_it"), t(BB, "test_the_bundle_and_the_installation_carry_the_same_lock_and_the_bundle_passes_the_checker")]),
    ("builder: the lock is carried into the pinned wheel (the copy doctor reads)", BBUILD, '        files[f"{data_root}/{BROWSER_LOCK}"] = browser_lock\n', "        pass\n",
     [t(BP, "test_the_wheel_carries_the_browser_lock_under_share_and_the_checker_compares_it_with_the_bundles_copy")]),
    ("builder: the release build passes the lock to the pinned wheel", BBUILD, "wheels_dir, (BUNDLE_SRC / BROWSER_LOCK).read_bytes()), \"pinned-upstreams\",", "wheels_dir), \"pinned-upstreams\",",
     [t(BW, "test_the_builder_puts_the_browser_lock_into_the_pinned_wheel_of_a_release_build")]),
    ("acceptance: the tampered browser must make doctor fail and demo refuse", "tools/bundle_acceptance.sh", '  need "[ $st -eq 3 ]" "demo must refuse to start the browser lane with exit status 3 for: $name (got $st)"\n', "",
     [t(BW, "test_the_acceptance_script_tampers_with_the_installed_browser_and_requires_the_refusals")]),
    ("acceptance: a plan with only a Robot lane must still run", "tools/bundle_acceptance.sh", "a plan with only a Robot lane must still run with a tampered browser", "REMOVED",
     [t(BW, "test_the_acceptance_script_tampers_with_the_installed_browser_and_requires_the_refusals")]),
]


@pytest.fixture(scope="module")
def baseline(tmp_path_factory):
    tests = sorted({x for c in CASES for x in c[4]})
    work = copy_tree(tmp_path_factory.mktemp("baseline"))
    return run_tests(work, tests)


def test_the_selected_tests_pass_on_an_unmodified_copy(baseline):
    assert baseline.returncode == 0, baseline.stdout[-3000:] + baseline.stderr[-1500:]


@pytest.mark.parametrize("name,rel,old,new,tests", CASES, ids=[c[0] for c in CASES])
def test_removing_the_guard_makes_the_tests_fail(tmp_path, name, rel, old, new, tests):
    work = copy_tree(tmp_path)
    mutate(work, rel, old, new)
    result = run_tests(work, tests)
    assert result.returncode == 1, f"mutant not killed by a failing test (exit {result.returncode}): {name}\n{result.stdout[-1500:]}"
    assert re.search(r"\b[1-9][0-9]* failed\b", result.stdout), result.stdout[-1500:]
