# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""install.sh, install-browser.sh and uninstall.sh against bundles of synthetic wheels built by the real builder functions: install, run, uninstall, refusal of a
wrong Python or platform, of a tampered or unlisted wheel and of a re-signed one (pip's --require-hashes), a wrong version, a prefix that is not new, and rollback by
installing the previous bundle into a new directory. Real bash, real venv, real pip, no network (the install is --no-index)."""
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from bundle_helpers import bb, clean_env, host_target, make_mini_bundle, make_wheel, resum, run_script, tree_listing


@pytest.fixture(scope="module")
def bundles(tmp_path_factory):
    base = tmp_path_factory.mktemp("bundles")
    return {"v1": make_mini_bundle(base / "v1", "1.0", label="previous"), "v2": make_mini_bundle(base / "v2", "2.0", label="current")}


@pytest.fixture()
def box(tmp_path):
    """A sandbox: an empty home and a place for installations. After a test the sandbox holds exactly what the test expects."""
    (tmp_path / "home").mkdir()
    return tmp_path


def fresh_copy(bundle, box):
    parent = Path(tempfile.mkdtemp(prefix="copy-", dir=box))
    dst = parent / bundle.name
    shutil.copytree(bundle, dst)
    return dst


def test_install_runs_the_launcher_and_writes_nothing_outside_the_prefix(bundles, box):
    prefix = box / "qa"
    done = run_script(bundles["v1"], "install.sh", ["--prefix", str(prefix)], box / "home")
    assert done.returncode == 0, done.stderr
    assert sorted(p.name for p in prefix.iterdir()) == ["INSTALL.json", "bin", "venv"]
    assert tree_listing(box / "home") == []                                 # no cache, no config, nothing under the home directory
    assert sorted(p.name for p in box.iterdir()) == ["home", "qa"]
    launched = subprocess.run([str(prefix / "bin" / "redevops-qa")], capture_output=True, text=True, env=clean_env(box / "home"), cwd=str(box / "home"))
    assert launched.returncode == 0 and launched.stdout.strip() == f"testpkg 1.0 ok {prefix}/browsers"        # the launcher sets the browser directory inside the prefix
    info = json.loads((prefix / "INSTALL.json").read_text())
    assert info["bundle"] == bundles["v1"].name and re.fullmatch(r"[0-9a-f]{64}", info["bundle_json_sha256"])
    assert f"installed {bundles['v1'].name} into {prefix}" in done.stdout


def test_the_install_used_pip_with_no_index_and_hashes(bundles):
    text = (bundles["v1"] / "install.sh").read_text(encoding="utf-8")
    command = '-m pip install --no-index --find-links "$here/wheelhouse" --require-hashes --only-binary=:all: -r "$here/requirements.lock"'
    assert command in text                                                  # the command itself, not a comment about it
    assert "PIP_CONFIG_FILE=/dev/null" in text and "PIP_NO_CACHE_DIR=1" in text            # no user configuration and no cache directory


def test_uninstall_removes_the_directory_and_leaves_the_sandbox_as_it_was(bundles, box):
    prefix = box / "qa"
    assert run_script(bundles["v1"], "install.sh", ["--prefix", str(prefix)], box / "home").returncode == 0
    done = run_script(bundles["v1"], "uninstall.sh", ["--prefix", str(prefix)], box / "home")
    assert done.returncode == 0, done.stderr
    assert not prefix.exists() and sorted(p.name for p in box.iterdir()) == ["home"] and tree_listing(box / "home") == []


def test_uninstall_of_a_prefix_that_install_prepared_as_an_empty_directory_removes_it_too(bundles, box):
    prefix = box / "qa"
    prefix.mkdir()
    assert run_script(bundles["v1"], "install.sh", ["--prefix", str(prefix)], box / "home").returncode == 0
    assert run_script(bundles["v1"], "uninstall.sh", ["--prefix", str(prefix)], box / "home").returncode == 0 and not prefix.exists()


def test_uninstall_refuses_what_install_did_not_make_and_removes_nothing(bundles, box):
    stranger = box / "mine"
    stranger.mkdir()
    (stranger / "notes.txt").write_text("keep me")
    done = run_script(bundles["v1"], "uninstall.sh", ["--prefix", str(stranger)], box / "home")
    assert done.returncode == 5 and "not an installation" in done.stderr and (stranger / "notes.txt").read_text() == "keep me"
    prefix = box / "qa"
    assert run_script(bundles["v1"], "install.sh", ["--prefix", str(prefix)], box / "home").returncode == 0
    (prefix / "my-evidence").mkdir()
    done = run_script(bundles["v1"], "uninstall.sh", ["--prefix", str(prefix)], box / "home")
    assert done.returncode == 5 and "my-evidence" in done.stderr and (prefix / "venv").is_dir() and (prefix / "my-evidence").is_dir()
    for bad in ("relative/path", "/", "//"):
        assert run_script(bundles["v1"], "uninstall.sh", ["--prefix", bad], box / "home").returncode in (2, 5)
    assert run_script(bundles["v1"], "uninstall.sh", [], box / "home").returncode == 2


def test_install_refuses_a_prefix_that_is_not_new_and_changes_nothing(bundles, box):
    taken = box / "taken"
    taken.mkdir()
    (taken / "file").write_text("x")
    done = run_script(bundles["v1"], "install.sh", ["--prefix", str(taken)], box / "home")
    assert done.returncode == 5 and "not empty" in done.stderr and tree_listing(taken) == ["file"]
    as_file = box / "afile"
    as_file.write_text("x")
    assert run_script(bundles["v1"], "install.sh", ["--prefix", str(as_file)], box / "home").returncode == 5


@pytest.mark.parametrize("prefix", ["relative/dir", "/tmp/has space/x", "/tmp/quote'x", "/", "//x"])
def test_install_refuses_a_prefix_that_is_relative_unsafe_for_the_launcher_or_the_root(bundles, box, prefix):
    done = run_script(bundles["v1"], "install.sh", ["--prefix", prefix], box / "home")
    assert done.returncode == 2 and tree_listing(box / "home") == []


def test_install_needs_a_prefix_and_refuses_unknown_arguments(bundles, box):
    assert run_script(bundles["v1"], "install.sh", [], box / "home").returncode == 2
    assert run_script(bundles["v1"], "install.sh", ["--prefix", str(box / "q"), "--force"], box / "home").returncode == 2
    assert not (box / "q").exists()


def test_a_bundle_for_another_python_minor_is_refused_before_anything_is_created(box, tmp_path_factory):
    other = make_mini_bundle(tmp_path_factory.mktemp("wrongpy"), target=host_target(python="3.99"))
    done = run_script(other, "install.sh", ["--prefix", str(box / "qa")], box / "home")
    assert done.returncode == 3 and "this bundle is for Python 3.99" in done.stderr and "Nothing was changed" in done.stderr
    assert not (box / "qa").exists()


def test_a_bundle_for_another_platform_is_refused_before_anything_is_created(box, tmp_path_factory):
    target = host_target()
    target["platform"] = "linux-s390x" if target["platform"] != "linux-s390x" else "linux-x86_64"
    other = make_mini_bundle(tmp_path_factory.mktemp("wrongplat"), target=target)
    done = run_script(other, "install.sh", ["--prefix", str(box / "qa")], box / "home")
    assert done.returncode == 3 and target["platform"] in done.stderr and not (box / "qa").exists()


def test_the_real_release_target_is_refused_on_any_host_that_is_not_that_target(box, tmp_path_factory):
    release = make_mini_bundle(tmp_path_factory.mktemp("release"), target=dict(bb.TARGET))
    done = run_script(release, "install.sh", ["--prefix", str(box / "qa")], box / "home")
    if host_target() == bb.TARGET:
        assert done.returncode == 0
    else:
        assert done.returncode == 3 and "linux-x86_64" in done.stderr and not (box / "qa").exists()


def test_a_tampered_wheel_is_refused_by_the_sums_first_and_nothing_is_created(bundles, box):
    bundle = fresh_copy(bundles["v1"], box)
    wheel = next((bundle / "wheelhouse").glob("*.whl"))
    wheel.write_bytes(wheel.read_bytes() + b"tampered")
    done = run_script(bundle, "install.sh", ["--prefix", str(box / "qa")], box / "home")
    assert done.returncode == 4 and "checksum differs" in done.stderr and not (box / "qa").exists()


def test_a_tampered_wheel_whose_sums_were_rewritten_is_refused_by_pip_require_hashes_and_the_prefix_is_removed(bundles, box):
    bundle = fresh_copy(bundles["v1"], box)
    wheel = next((bundle / "wheelhouse").glob("*.whl"))
    wheel.write_bytes(wheel.read_bytes() + b"tampered")
    resum(bundle)                                       # the first check now passes: what is left is pip's own, against requirements.lock
    done = run_script(bundle, "install.sh", ["--prefix", str(box / "qa")], box / "home")
    assert done.returncode == 6, done.stderr
    assert "THESE PACKAGES DO NOT MATCH THE HASHES" in done.stderr
    assert "nothing was installed" in done.stderr and not (box / "qa").exists() and tree_listing(box / "home") == []


def test_a_wheel_swapped_for_another_build_of_it_is_refused(bundles, box):
    bundle = fresh_copy(bundles["v1"], box)
    old = next((bundle / "wheelhouse").glob("*.whl"))
    swapped = make_wheel(box, "1.0", marker="evil")                  # same name and version, other contents
    old.write_bytes(swapped.read_bytes())
    resum(bundle)
    done = run_script(bundle, "install.sh", ["--prefix", str(box / "qa")], box / "home")
    assert done.returncode == 6 and not (box / "qa").exists()


def test_a_wheel_that_is_not_listed_is_refused(bundles, box):
    bundle = fresh_copy(bundles["v1"], box)
    make_wheel(bundle / "wheelhouse", "1.1")
    done = run_script(bundle, "install.sh", ["--prefix", str(box / "qa")], box / "home")
    assert done.returncode == 4 and "not listed in SHA256SUMS" in done.stderr and not (box / "qa").exists()
    resum(bundle)                                       # even listed, a wheel the lock does not name is never chosen: the lock pins 1.0
    done = run_script(bundle, "install.sh", ["--prefix", str(box / "qa")], box / "home")
    assert done.returncode == 0, done.stderr
    out = subprocess.run([str(box / "qa" / "bin" / "redevops-qa")], capture_output=True, text=True, env=clean_env(box / "home")).stdout
    assert out.startswith("testpkg 1.0 ")


def test_a_lock_that_names_a_version_the_wheelhouse_does_not_hold_is_refused(bundles, box):
    bundle = fresh_copy(bundles["v1"], box)
    lock = bundle / "requirements.lock"
    lock.write_text(lock.read_text(encoding="utf-8").replace("==1.0", "==3.0"), encoding="utf-8")
    resum(bundle)
    done = run_script(bundle, "install.sh", ["--prefix", str(box / "qa")], box / "home")
    assert done.returncode == 6 and not (box / "qa").exists()


def test_a_lock_hash_that_is_not_the_wheels_is_refused(bundles, box):
    bundle = fresh_copy(bundles["v1"], box)
    lock = bundle / "requirements.lock"
    text = lock.read_text(encoding="utf-8")
    lock.write_text(re.sub(r"--hash=sha256:[0-9a-f]{64}", "--hash=sha256:" + "0" * 64, text), encoding="utf-8")
    resum(bundle)
    done = run_script(bundle, "install.sh", ["--prefix", str(box / "qa")], box / "home")
    assert done.returncode == 6 and not (box / "qa").exists()


def test_a_requirement_without_a_hash_is_refused_by_pip(bundles, box):
    bundle = fresh_copy(bundles["v1"], box)
    lock = bundle / "requirements.lock"
    lock.write_text(lock.read_text(encoding="utf-8") + "redevops-qa-nothing==1\n", encoding="utf-8")
    resum(bundle)
    done = run_script(bundle, "install.sh", ["--prefix", str(box / "qa")], box / "home")
    assert done.returncode == 6 and not (box / "qa").exists()


def test_a_missing_file_of_the_bundle_is_refused(bundles, box):
    bundle = fresh_copy(bundles["v1"], box)
    (bundle / "BUNDLE.json").unlink()
    assert run_script(bundle, "install.sh", ["--prefix", str(box / "qa")], box / "home").returncode == 4
    bundle2 = fresh_copy(bundles["v2"], box)
    next((bundle2 / "wheelhouse").glob("*.whl")).unlink()
    done = run_script(bundle2, "install.sh", ["--prefix", str(box / "qa2")], box / "home")
    assert done.returncode == 4 and "listed but missing" in done.stderr and not (box / "qa2").exists()


def test_a_broken_interpreter_is_refused_and_nothing_is_created(bundles, box):
    done = run_script(bundles["v1"], "install.sh", ["--prefix", str(box / "qa"), "--python", str(box / "no-such-python")], box / "home", python=None)
    assert done.returncode == 3 and not (box / "qa").exists()


def test_rollback_installs_the_previous_bundle_into_a_new_directory_and_leaves_the_other_alone(bundles, box):
    current, previous = box / "current", box / "previous"
    assert run_script(bundles["v2"], "install.sh", ["--prefix", str(current)], box / "home").returncode == 0
    before = tree_listing(current)
    assert run_script(bundles["v1"], "install.sh", ["--prefix", str(previous)], box / "home").returncode == 0
    assert tree_listing(current) == before                          # installing the other bundle touched nothing of this one
    out = lambda p: subprocess.run([str(p / "bin" / "redevops-qa")], capture_output=True, text=True, env=clean_env(box / "home")).stdout.split()[:2]
    assert out(current) == ["testpkg", "2.0"] and out(previous) == ["testpkg", "1.0"]
    assert json.loads((previous / "INSTALL.json").read_text())["bundle"] != "" and json.loads((current / "INSTALL.json").read_text())["bundle_json_sha256"] != json.loads((previous / "INSTALL.json").read_text())["bundle_json_sha256"]
    assert run_script(bundles["v2"], "uninstall.sh", ["--prefix", str(current)], box / "home").returncode == 0
    assert not current.exists() and out(previous) == ["testpkg", "1.0"]


def test_a_failed_install_of_the_new_bundle_leaves_the_running_installation_working(bundles, box):
    running = box / "running"
    assert run_script(bundles["v1"], "install.sh", ["--prefix", str(running)], box / "home").returncode == 0
    broken = fresh_copy(bundles["v2"], box)
    wheel = next((broken / "wheelhouse").glob("*.whl"))
    wheel.write_bytes(wheel.read_bytes() + b"x")
    resum(broken)
    assert run_script(broken, "install.sh", ["--prefix", str(box / "next")], box / "home").returncode == 6
    assert not (box / "next").exists()
    out = subprocess.run([str(running / "bin" / "redevops-qa")], capture_output=True, text=True, env=clean_env(box / "home")).stdout
    assert out.startswith("testpkg 1.0 ")


def test_a_signal_during_the_install_leaves_nothing_behind(bundles, box):
    """SIGTERM while pip is running: the trap removes what was made. (SIGKILL cannot be trapped by anything; the next install refuses a non-empty prefix instead.)"""
    import os
    import signal
    import time
    bundle = fresh_copy(bundles["v1"], box)
    # a stand-in python that makes the venv step slow: wraps the real interpreter and sleeps when asked to run -m venv
    slow = box / "slowpy"
    slow.write_text(f"#!/bin/sh\nif [ \"$1\" = \"-m\" ] && [ \"$2\" = \"venv\" ]; then sleep 30; fi\nexec '{sys.executable}' \"$@\"\n")
    slow.chmod(0o755)
    proc = subprocess.Popen(["bash", str(bundle / "install.sh"), "--prefix", str(box / "qa"), "--python", str(slow)], env=clean_env(box / "home"), cwd=str(box / "home"),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    deadline = time.time() + 30
    while not (box / "qa").exists() and time.time() < deadline:
        time.sleep(0.1)
    assert (box / "qa").exists()
    time.sleep(0.5)
    os.killpg(proc.pid, signal.SIGTERM)
    proc.communicate(timeout=60)
    assert proc.returncode != 0 and not (box / "qa").exists()


def test_the_venv_is_made_with_a_home_inside_the_prefix_so_nothing_a_python_creates_under_home_lands_outside_it(bundles, box):
    """A CPython from a runner's toolcache creates a directory (.rustup) under the HOME it is started with when it makes a venv; the installer must not leave that outside the prefix."""
    log = box / "venv-home.txt"
    wrapper = box / "homepy"
    wrapper.write_text(f"#!/bin/sh\nif [ \"$1\" = \"-m\" ] && [ \"$2\" = \"venv\" ]; then echo \"$HOME\" > '{log}'; mkdir -p \"$HOME/.leftover\"; fi\nexec '{sys.executable}' \"$@\"\n")
    wrapper.chmod(0o755)
    prefix = box / "qa"
    done = run_script(bundles["v1"], "install.sh", ["--prefix", str(prefix), "--python", str(wrapper)], box / "home", python=None)
    assert done.returncode == 0, done.stderr
    assert log.read_text().strip() == f"{prefix}/venv" and (prefix / "venv" / ".leftover").is_dir()
    assert tree_listing(box / "home") == []
    assert run_script(bundles["v1"], "uninstall.sh", ["--prefix", str(prefix)], box / "home").returncode == 0 and not prefix.exists()


def test_install_browser_refuses_a_directory_that_is_not_an_installation(bundles, box):
    done = run_script(bundles["v1"], "install-browser.sh", ["--prefix", str(box / "nothing")], box / "home")
    assert done.returncode == 5 and "not an installation" in done.stderr
    assert run_script(bundles["v1"], "install-browser.sh", [], box / "home").returncode == 2


def test_install_browser_downloads_into_the_prefix_through_the_pinned_playwright(bundles):
    text = (bundles["v1"] / "install-browser.sh").read_text(encoding="utf-8")
    assert 'PLAYWRIGHT_BROWSERS_PATH="$prefix/browsers"' in text and '-m playwright install $deps chromium' in text
    assert "not part of the bundle, not hashed by it" in text


def test_the_scripts_are_executable_in_the_directory_and_in_the_archive(bundles, tmp_path):
    import os
    import tarfile
    for script in bb.SCRIPTS:
        assert os.access(bundles["v1"] / script, os.X_OK)
    bb.write_tar(bundles["v1"], tmp_path / "b.tar", 1_700_000_000)
    with tarfile.open(tmp_path / "b.tar") as tf:
        modes = {m.name.split("/", 1)[1]: m.mode for m in tf.getmembers() if m.isfile()}
    assert all(modes[s] == 0o755 for s in bb.SCRIPTS) and modes["README.md"] == 0o644


# ------------------------------------------------------------------------------------------------ the launcher does not read the caller's Python environment
def _evil_copy(box, marker="EVIL CODE RUNNING"):
    evil = box / "evil"
    (evil / "redevops_qa_testpkg").mkdir(parents=True)
    (evil / "redevops_qa_testpkg" / "__init__.py").write_text(f"def main():\n    print({marker!r})\n    return 0\n")
    return evil


def test_a_pythonpath_with_another_copy_of_a_package_is_not_loaded_by_the_launcher(bundles, box):
    prefix = box / "qa"
    assert run_script(bundles["v1"], "install.sh", ["--prefix", str(prefix)], box / "home").returncode == 0
    evil = _evil_copy(box)
    env = {**clean_env(box / "home"), "PYTHONPATH": str(evil), "PYTHONHOME": "/nonexistent", "PYTHONSTARTUP": str(evil / "x.py")}
    done = subprocess.run([str(prefix / "bin" / "redevops-qa")], capture_output=True, text=True, env=env, cwd=str(box / "home"))
    assert done.returncode == 0 and "EVIL" not in done.stdout + done.stderr and done.stdout.startswith("testpkg 1.0 ok"), done.stdout + done.stderr
    # the control: the same PYTHONPATH DOES replace the package when the console script is run directly, so the test above proves the launcher and not luck
    direct = subprocess.run([str(prefix / "venv" / "bin" / "redevops-qa")], capture_output=True, text=True, env={**clean_env(box / "home"), "PYTHONPATH": str(evil)}, cwd=str(box / "home"))
    assert "EVIL CODE RUNNING" in direct.stdout


def test_the_launcher_runs_the_entry_script_of_this_installation_with_python_e_and_s(bundles, box):
    prefix = box / "qa"
    assert run_script(bundles["v1"], "install.sh", ["--prefix", str(prefix)], box / "home").returncode == 0
    text = (prefix / "bin" / "redevops-qa").read_text()
    assert f"exec '{prefix}/venv/bin/python' -E -s '{prefix}/venv/bin/redevops-qa' \"$@\"" in text
    assert (prefix / "venv" / "bin" / "redevops-qa").is_file() and "unset PYTHONPATH PYTHONHOME" in text


# ------------------------------------------------------------------------------------------------ uninstall validates INSTALL.json
def _fake_install(box, doc):
    victim = box / "victim"
    (victim / "venv").mkdir(parents=True)
    (victim / "venv" / "important.txt").write_text("keep")
    (victim / "bin").mkdir()
    (victim / "INSTALL.json").write_text(json.dumps(doc))
    return victim


@pytest.mark.parametrize("label,doc", [
    ("an empty object", {}),
    ("a foreign schema", {"schema": "something/else", "schema_version": "1.0"}),
    ("the right schema but the wrong entries", {"schema": "redevops-qa/install", "schema_version": "1.0", "entries": ["venv"], "bundle": "redevops-qa-bundle-x", "bundle_json_sha256": "0" * 64,
                                                 "python": "3.12.3", "prefix": "x"}),
    ("a list", []),
])
def test_uninstall_refuses_a_directory_whose_install_json_is_not_what_install_writes_and_removes_nothing(bundles, box, label, doc):
    victim = _fake_install(box, doc)
    done = run_script(bundles["v1"], "uninstall.sh", ["--prefix", str(victim)], box / "home")
    assert done.returncode == 5 and "not what install.sh writes" in done.stderr, (label, done.stderr)
    assert (victim / "venv" / "important.txt").read_text() == "keep" and (victim / "INSTALL.json").is_file()


def test_uninstall_refuses_an_install_json_that_names_another_directory_and_a_directory_without_a_venv(bundles, box):
    one, two = box / "one", box / "two"
    assert run_script(bundles["v1"], "install.sh", ["--prefix", str(one)], box / "home").returncode == 0
    two.mkdir()
    for name in ("INSTALL.json", "bin", "venv"):
        subprocess.run(["cp", "-R", str(one / name), str(two / name)], check=True)
    done = run_script(bundles["v1"], "uninstall.sh", ["--prefix", str(two)], box / "home")
    assert done.returncode == 5 and "not what install.sh writes" in done.stderr and (two / "venv").is_dir()      # copied from another installation: the recorded prefix is not this one
    doc = json.loads((one / "INSTALL.json").read_text())
    assert doc["prefix"] == str(one.resolve()) and doc["schema"] == "redevops-qa/install"
    (one / "venv" / "pyvenv.cfg").unlink()
    done = run_script(bundles["v1"], "uninstall.sh", ["--prefix", str(one)], box / "home")
    assert done.returncode == 5 and "no virtual environment" in done.stderr and (one / "venv").is_dir()


@pytest.mark.parametrize("suffix", ["", "/", "//", "/.", "/./", "/.//."])
def test_a_symbolic_link_is_refused_by_install_and_by_uninstall_however_the_path_ends_and_nothing_is_left_or_removed(bundles, box, suffix):
    real = box / "real"
    assert run_script(bundles["v1"], "install.sh", ["--prefix", str(real)], box / "home").returncode == 0
    link = box / "link"
    link.symlink_to(real)
    given = str(link) + suffix
    done = run_script(bundles["v1"], "uninstall.sh", ["--prefix", given], box / "home")
    assert done.returncode == 5 and "symbolic link" in done.stderr and (real / "venv").is_dir() and (real / "INSTALL.json").is_file() and link.is_symlink(), (suffix, done.stderr)
    done = run_script(bundles["v1"], "install.sh", ["--prefix", given], box / "home")
    assert done.returncode == 5 and "symbolic link" in done.stderr, (suffix, done.stderr)
    link.unlink()
    assert run_script(bundles["v1"], "uninstall.sh", ["--prefix", str(real) + suffix], box / "home").returncode == 0 and not real.exists()      # the real directory is fine with the same endings


def test_a_trailing_slash_or_dot_does_not_change_which_directory_is_installed_or_what_the_launcher_says(bundles, box):
    prefix = box / "qa"
    assert run_script(bundles["v1"], "install.sh", ["--prefix", str(prefix) + "/."], box / "home").returncode == 0
    assert json.loads((prefix / "INSTALL.json").read_text())["prefix"] == str(prefix.resolve())
    assert f"exec '{prefix}/venv/bin/python'" in (prefix / "bin" / "redevops-qa").read_text()          # no doubled or dotted path in the launcher
    assert run_script(bundles["v1"], "uninstall.sh", ["--prefix", str(prefix) + "/"], box / "home").returncode == 0 and not prefix.exists()


# ------------------------------------------------------------------------------------------------ SHA256SUMS: no duplicate, empty or malformed line
@pytest.mark.parametrize("label,edit", [
    ("a duplicated line", lambda lines: lines + [lines[1]]),
    ("an empty line", lambda lines: lines[:2] + [""] + lines[2:]),
    ("an upper-case digest", lambda lines: [lines[0].replace(lines[0][:64], lines[0][:64].upper(), 1)] + lines[1:]),
    ("a line without a path", lambda lines: lines + ["0" * 64 + "  "]),
    ("a path outside the bundle", lambda lines: lines + ["0" * 64 + "  ../x"]),
])
def test_sha256sums_with_a_duplicate_empty_or_malformed_line_is_refused_before_anything_is_created(bundles, box, label, edit):
    bundle = fresh_copy(bundles["v1"], box)
    lines = (bundle / "SHA256SUMS").read_text().splitlines()
    (bundle / "SHA256SUMS").write_text("\n".join(edit(lines)) + "\n")
    done = run_script(bundle, "install.sh", ["--prefix", str(box / "qa")], box / "home")
    assert done.returncode == 4 and "does not accept" in done.stderr and not (box / "qa").exists(), (label, done.stderr)


# ------------------------------------------------------------------------------------------------ the prefix must be somewhere the adapter path policy accepts (F1: root, HOME=/root)
import os  # noqa: E402

from bundle_helpers import ROOT  # noqa: E402


def kit_is_denied():
    import qa_adapter_kit.paths as kit            # the source of truth the installer reads from the bundle's own copy of it
    return kit


@pytest.fixture(scope="module")
def policy_bundle(tmp_path_factory):
    return make_mini_bundle(tmp_path_factory.mktemp("policy"), with_kit=True)


@pytest.fixture()
def failing_venv_python(box):
    """The real interpreter, except that `-m venv` fails at once: an install the path policy accepted then ends with exit 6 instead of taking seconds to finish."""
    wrapper = box / "fastfail"
    wrapper.write_text(f"#!/bin/sh\nif [ \"$1\" = \"-m\" ] && [ \"$2\" = \"venv\" ]; then exit 1; fi\nexec '{sys.executable}' \"$@\"\n")
    wrapper.chmod(0o755)
    return str(wrapper)


@pytest.mark.parametrize("prefix,rule", [("/root/redevops-qa", "the directory /root"), ("/root", "the directory /root"), ("/etc/redevops-qa", "the directory /etc"), ("/proc/x", "the directory /proc"),
                                         ("/sys/x", "the directory /sys"), ("/dev/x", "the directory /dev"), ("/run/x", "the directory /run"), ("/var/run/x", "the directory /var/run"),
                                         ("/boot/x", "the directory /boot"), ("/home/u/.config/qa", "a path component named .config"), ("/home/u/.ssh/qa", "a path component named .ssh"),
                                         ("/opt/credentials", "a file named credentials"), ("/root/redevops-qa/", "the directory /root"), ("/root/./x/..", "the directory /root")])
def test_a_prefix_the_adapter_path_policy_refuses_is_refused_with_exit_2_naming_the_rule_and_nothing_is_created(policy_bundle, box, prefix, rule):
    done = run_script(policy_bundle, "install.sh", ["--prefix", prefix], box / "home")
    assert done.returncode == 2, done.stderr
    assert rule in done.stderr and "adapter path policy" in done.stderr and "PROHIBITED_PATH" in done.stderr and "/opt/redevops-qa" in done.stderr and "Nothing was changed" in done.stderr
    assert tree_listing(box / "home") == []


def test_a_prefix_through_a_symbolic_link_into_a_refused_directory_is_refused_by_its_resolved_path(policy_bundle, box):
    target = box / ".config"
    target.mkdir()
    link = box / "viaparent"
    link.symlink_to(target)
    done = run_script(policy_bundle, "install.sh", ["--prefix", str(link / "qa")], box / "home")
    assert done.returncode == 2 and "with symbolic links resolved" in done.stderr and ".config" in done.stderr and not (target / "qa").exists()


def test_the_installer_applies_exactly_the_rule_of_the_adapter_kit_for_a_battery_of_prefixes(policy_bundle, box, failing_venv_python):
    kit = kit_is_denied()
    version = "%d.%d" % sys.version_info[:2]
    # prefixes the rule refuses, and prefixes that only look like them; an accepted prefix goes on to make its directory (exit 5 where / is not writable, 6 where the fake interpreter then fails),
    # so near misses under system directories are only run by a user who cannot create them
    refused_battery = ["/root/x", "/etc", "/run/user/1000/x", "/var/run/x", "/home/u/.config/q", "/home/u/.aws/q", "/srv/credentials", "/srv/credentials.json", "/dev/shm/x", "/boot", "/tmp/a/docker.sock",
                       "/tmp/id_rsa.pub", "/proc/1/x", "/sys/x"]
    accepted_battery = [str(box / "qa"), str(box / "config" / "q"), str(box / "credentialsx")]
    if os.geteuid() != 0:
        accepted_battery += ["/rootless/x", "/etc2/x", "/runner/x", "/var/runner/x", "/devx/y", "/bootx", "/opt/redevops-qa"]
    mismatches = []
    for prefix in refused_battery + accepted_battery:
        expected_refused = any(kit.is_denied(p) for p in (prefix, prefix + "/venv/bin/python", f"{prefix}/venv/lib/python{version}/site-packages/qa_runner/robot_guard.py"))
        done = run_script(policy_bundle, "install.sh", ["--prefix", prefix], box / "home", python=failing_venv_python)
        refused = done.returncode == 2
        if refused != expected_refused or (not refused and done.returncode not in (5, 6)):
            mismatches.append((prefix, expected_refused, done.returncode, done.stderr[-120:]))
    assert mismatches == []
    assert [p for p in refused_battery if not any(kit.is_denied(x) for x in (p, p + "/venv/bin/python"))] == []          # every entry of the first list really is refused by the kit


def test_the_installer_reads_the_rule_from_the_kit_of_the_bundle_so_it_cannot_drift_from_the_runner(tmp_path_factory, box, failing_venv_python):
    text = (ROOT / "packages" / "qa-adapter-kit" / "src" / "qa_adapter_kit" / "paths.py").read_text(encoding="utf-8")
    assert '"/boot", "/private/etc"' in text
    changed = make_mini_bundle(tmp_path_factory.mktemp("kit2"), kit_paths_text=text.replace('"/boot", "/private/etc"', '"/boot", "/srv", "/private/etc"'))
    done = run_script(changed, "install.sh", ["--prefix", "/srv/qa"], box / "home", python=failing_venv_python)
    assert done.returncode == 2 and "the directory /srv" in done.stderr
    same = make_mini_bundle(tmp_path_factory.mktemp("kit3"), with_kit=True)
    assert run_script(same, "install.sh", ["--prefix", str(box / "srv" / "qa")], box / "home", python=failing_venv_python).returncode == 6        # the unchanged kit accepts what it did not list


def test_a_kit_whose_policy_constants_cannot_be_read_stops_the_install_before_anything_is_created(tmp_path_factory, box):
    broken = make_mini_bundle(tmp_path_factory.mktemp("kit4"), kit_paths_text="DENIED_PREFIXES = ('/etc',)\n")
    done = run_script(broken, "install.sh", ["--prefix", str(box / "qa")], box / "home")
    assert done.returncode == 4 and "does not define the path policy" in done.stderr and not (box / "qa").exists()


def test_an_ordinary_prefix_still_installs_with_the_kit_present(policy_bundle, box):
    prefix = box / "qa"
    assert run_script(policy_bundle, "install.sh", ["--prefix", str(prefix)], box / "home").returncode == 0
    assert run_script(policy_bundle, "uninstall.sh", ["--prefix", str(prefix)], box / "home").returncode == 0


def test_the_installer_documents_the_new_exit_status():
    text = (ROOT / "bundle" / "install.sh").read_text(encoding="utf-8")
    assert "2 usage, or a prefix under a path the adapter path policy refuses (for example /root)" in text
