# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""install-browser.sh against a bundle whose installation carries a browser pin, with stand-in archives served from a directory (--mirror) or by a local HTTP server: the archives are
checked against the pin before anything is unpacked, a bad archive installs nothing and leaves nothing, --with-deps runs after the check and before the placement, a re-run is idempotent, a
tampered install is never replaced, and the bundle's lock must be the installation's. Real bash, real venv, real pip; no browser, no network beyond loopback."""
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import browser_helpers as bh
from bundle_helpers import bb, cb, clean_env, host_target, make_kit_wheel, make_wheel, resum, run_script, tree_listing

SCRIPT = "install-browser.sh"


@pytest.fixture(scope="module")
def fake(tmp_path_factory):
    return bh.make_fake_browser(tmp_path_factory.mktemp("fake"))


@pytest.fixture(scope="module")
def world(tmp_path_factory, fake):
    """One bundle and one installation of it (installing takes seconds); every test starts from the same state: no browsers directory."""
    base = tmp_path_factory.mktemp("world")
    bundle = bh.make_browser_bundle(base / "bundle", fake)
    home = base / "home"
    home.mkdir()
    prefix = base / "qa"
    done = run_script(bundle, "install.sh", ["--prefix", str(prefix)], home)
    assert done.returncode == 0, done.stderr
    return {"bundle": bundle, "prefix": prefix, "home": home, "base": base}


@pytest.fixture()
def w(world):
    shutil.rmtree(world["prefix"] / "browsers", ignore_errors=True)
    yield world
    shutil.rmtree(world["prefix"] / "browsers", ignore_errors=True)


def browser_step(w, *args, env=None, bundle=None):
    e = clean_env(w["home"])
    e.update(env or {})
    return subprocess.run(["bash", str((bundle or w["bundle"]) / SCRIPT), "--prefix", str(w["prefix"]), *args], env=e, cwd=str(w["home"]), capture_output=True, text=True, timeout=300)


def prefix_entries(w):
    return sorted(os.listdir(w["prefix"]))


# ------------------------------------------------------------------------------------------------------------------------------ the bundle carries the pin
def test_the_bundle_and_the_installation_carry_the_same_lock_and_the_bundle_passes_the_checker(world, fake):
    bundle, prefix = world["bundle"], world["prefix"]
    site = next((prefix / "venv" / "lib").glob("python*"))
    assert (bundle / "browser.lock.json").read_bytes() == fake.lock_bytes == (prefix / "venv" / "share" / "redevops-qa" / "browser.lock.json").read_bytes()
    assert cb.check_bundle(bundle, allow_test_target=True) == []
    assert (site / "site-packages" / "qa_runner" / "browser_pin.py").is_file()
    assert "browser.lock.json" in (bundle / "SHA256SUMS").read_text(encoding="utf-8")


# ------------------------------------------------------------------------------------------------------------------------------ a good install
def test_a_good_install_checks_every_archive_unpacks_checks_the_tree_and_places_it(w, fake):
    done = browser_step(w, "--mirror", str(fake.archives_dir))
    assert done.returncode == 0, done.stderr
    for a in fake.lock.archives:
        assert f"{a.file}: sha256 {a.sha256} matches the pin" in done.stdout
    assert "exactly the pinned Chromium 9.9.9.9" in done.stdout and "the operating system libraries are not covered" in done.stdout
    assert bh.pin_module().verify_tree(w["prefix"] / "browsers", fake.lock) == []
    assert sorted(os.listdir(w["prefix"] / "browsers")) == sorted(fake.lock.dirs())          # no staging directory is left
    assert prefix_entries(w) == ["INSTALL.json", "bin", "browsers", "venv"]


def test_the_mirror_can_be_a_file_url_or_a_local_http_server_and_the_bytes_are_still_checked(w, fake, tmp_path):
    done = browser_step(w, "--mirror", fake.archives_dir.as_uri())
    assert done.returncode == 0, done.stderr
    shutil.rmtree(w["prefix"] / "browsers")
    with bh.serve(fake.archives_dir) as url:
        done = browser_step(w, "--mirror", url)
    assert done.returncode == 0 and "127.0.0.1" in done.stdout, done.stderr


def test_the_launcher_is_what_doctor_uses_and_the_install_leaves_the_tree_the_check_accepts_after_a_umask_of_077(w, fake):
    done = subprocess.run(["bash", "-c", f"umask 077; exec bash {w['bundle'] / SCRIPT} --prefix {w['prefix']} --mirror {fake.archives_dir}"], env=clean_env(w["home"]), capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert bh.pin_module().verify_tree(w["prefix"] / "browsers", fake.lock) == []


# ------------------------------------------------------------------------------------------------------------------------------ a bad archive installs nothing
def bad_mirror(w, fake, name, edit):
    mirror = w["base"] / f"mirror-{name}"
    if mirror.exists():
        shutil.rmtree(mirror)
    shutil.copytree(fake.archives_dir, mirror)
    edit(mirror)
    return mirror


def assert_nothing_installed(w, before):
    assert prefix_entries(w) == ["INSTALL.json", "bin", "venv"], prefix_entries(w)          # no browsers directory, no staging directory
    assert tree_listing(w["prefix"]) == before


def test_a_truncated_archive_fails_with_exit_6_names_the_expected_and_the_actual_hash_and_leaves_nothing(w, fake):
    before = tree_listing(w["prefix"])
    mirror = bad_mirror(w, fake, "trunc", lambda m: (m / "chrome-linux64.zip").write_bytes((m / "chrome-linux64.zip").read_bytes()[:-40]))
    done = browser_step(w, "--mirror", str(mirror))
    wanted = next(a for a in fake.lock.archives if a.file == "chrome-linux64.zip")
    assert done.returncode == 6
    assert f"expected sha256 {wanted.sha256}" in done.stderr and f"got sha256 {hashlib.sha256((mirror / 'chrome-linux64.zip').read_bytes()).hexdigest()}" in done.stderr
    assert "nothing was installed" in done.stderr
    assert_nothing_installed(w, before)


def test_one_changed_byte_in_one_archive_installs_none_of_the_three(w, fake):
    def flip(m):
        data = bytearray((m / "ffmpeg-linux.zip").read_bytes())
        data[10] ^= 0xFF
        (m / "ffmpeg-linux.zip").write_bytes(bytes(data))
    before = tree_listing(w["prefix"])
    done = browser_step(w, "--mirror", str(bad_mirror(w, fake, "flip", flip)))
    assert done.returncode == 6 and "ffmpeg-linux.zip does not match its pin" in done.stderr
    assert_nothing_installed(w, before)


def test_an_archive_that_is_missing_from_the_mirror_fails_and_leaves_nothing(w, fake):
    before = tree_listing(w["prefix"])
    done = browser_step(w, "--mirror", str(bad_mirror(w, fake, "gone", lambda m: (m / "ffmpeg-linux.zip").unlink())))
    assert done.returncode == 6 and "the download failed" in done.stderr
    assert_nothing_installed(w, before)


def test_an_unreachable_host_fails_with_exit_6_and_leaves_nothing(w):
    before = tree_listing(w["prefix"])
    done = browser_step(w, "--mirror", "http://127.0.0.1:9/")
    assert done.returncode == 6 and "http://127.0.0.1:9/" in done.stderr
    assert_nothing_installed(w, before)


def test_the_urls_of_the_lock_are_used_without_a_mirror_and_a_failure_names_them(w, fake):
    """No mirror: the https URLs of the lock (example.invalid here) are tried; the host does not exist, nothing is installed, and the message names the URL."""
    before = tree_listing(w["prefix"])
    done = browser_step(w)
    assert done.returncode == 6 and "https://example.invalid/first/" in done.stderr
    assert_nothing_installed(w, before)


def test_an_interrupted_install_leaves_no_staging_directory(w, fake):
    """A signal during the download: the trap removes the staging directory and the browsers directory this run created."""
    import signal
    import time
    with bh.serve(fake.archives_dir, delay=3) as url:
        e = clean_env(w["home"])
        proc = subprocess.Popen(["bash", str(w["bundle"] / SCRIPT), "--prefix", str(w["prefix"]), "--mirror", url], env=e, cwd=str(w["home"]), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                start_new_session=True)
        deadline = time.time() + 60
        while time.time() < deadline and not (w["prefix"] / "browsers").exists():
            time.sleep(0.05)
        assert (w["prefix"] / "browsers").exists()
        time.sleep(0.5)
        os.killpg(proc.pid, signal.SIGTERM)
        proc.communicate(timeout=60)
    assert prefix_entries(w) == ["INSTALL.json", "bin", "venv"]


# ------------------------------------------------------------------------------------------------------------------------------ --with-deps
def read_log(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


def test_with_deps_runs_after_the_archives_were_verified_and_before_anything_is_placed(w, fake):
    log = w["base"] / "stub.log"
    log.unlink(missing_ok=True)
    done = browser_step(w, "--with-deps", "--mirror", str(fake.archives_dir), env={"STUB_LOG": str(log)})
    assert done.returncode == 0, done.stderr
    calls = read_log(log)
    assert len(calls) == 1 and calls[0]["argv"] == ["install-deps", "chromium"]
    assert len(calls[0]["listing"]) == 1 and calls[0]["listing"][0].startswith(".staging-")            # only the staging directory existed: nothing was placed yet
    assert "not covered by the pin" in done.stdout
    assert bh.pin_module().verify_tree(w["prefix"] / "browsers", fake.lock) == []


def test_without_with_deps_the_system_packages_are_not_touched(w, fake):
    log = w["base"] / "stub2.log"
    log.unlink(missing_ok=True)
    assert browser_step(w, "--mirror", str(fake.archives_dir), env={"STUB_LOG": str(log)}).returncode == 0
    assert not log.exists()


def test_a_bad_archive_stops_before_with_deps_runs(w, fake):
    log = w["base"] / "stub3.log"
    log.unlink(missing_ok=True)
    mirror = bad_mirror(w, fake, "deps-bad", lambda m: (m / "ffmpeg-linux.zip").write_bytes(b"junk"))
    done = browser_step(w, "--with-deps", "--mirror", str(mirror), env={"STUB_LOG": str(log)})
    assert done.returncode == 6 and not log.exists(), "apt must not run for an archive that does not match the pin"


def test_a_failing_with_deps_places_nothing(w, fake):
    before = tree_listing(w["prefix"])
    done = browser_step(w, "--with-deps", "--mirror", str(fake.archives_dir), env={"STUB_EXIT": "7"})
    assert done.returncode == 6 and "operating system libraries could not be installed" in done.stderr
    assert_nothing_installed(w, before)


# ------------------------------------------------------------------------------------------------------------------------------ re-running
def test_a_second_run_finds_the_install_identical_to_the_pin_downloads_nothing_and_succeeds(w, fake):
    assert browser_step(w, "--mirror", str(fake.archives_dir)).returncode == 0
    inode = (w["prefix"] / "browsers" / "ffmpeg-1000" / "ffmpeg-linux").stat().st_ino
    done = browser_step(w, "--mirror", "http://127.0.0.1:9/")                  # a mirror that would fail if it were used
    assert done.returncode == 0 and "already installed and identical to the pin" in done.stdout, done.stderr
    assert (w["prefix"] / "browsers" / "ffmpeg-1000" / "ffmpeg-linux").stat().st_ino == inode


def test_a_tampered_install_is_not_replaced_and_the_run_fails(w, fake):
    assert browser_step(w, "--mirror", str(fake.archives_dir)).returncode == 0
    target = w["prefix"] / "browsers" / "ffmpeg-1000" / "ffmpeg-linux"
    target.write_bytes(b"#!/bin/sh\necho tamper!!!!!!!!\n")
    done = browser_step(w, "--mirror", str(fake.archives_dir))
    assert done.returncode == 6 and "is not the pinned build, so it was not touched" in done.stderr and "ffmpeg-1000/ffmpeg-linux" in done.stderr
    assert target.read_bytes() == b"#!/bin/sh\necho tamper!!!!!!!!\n"
    assert (w["prefix"] / "browsers").is_dir(), "a browsers directory that was there before is not removed"


def test_a_failed_run_does_not_remove_an_install_that_was_already_there(w, fake):
    assert browser_step(w, "--mirror", str(fake.archives_dir)).returncode == 0
    shutil.rmtree(w["prefix"] / "browsers" / "ffmpeg-1000")
    done = browser_step(w, "--mirror", str(bad_mirror(w, fake, "partial", lambda m: (m / "ffmpeg-linux.zip").write_bytes(b"junk"))))
    assert done.returncode == 6
    assert sorted(os.listdir(w["prefix"] / "browsers")) == ["chromium-1000", "chromium_headless_shell-1000"]


def test_uninstall_removes_the_browsers_directory_with_everything_else(w, fake, tmp_path):
    base = w["base"] / "second"
    base.mkdir(exist_ok=True)
    home = base / "home"
    home.mkdir(exist_ok=True)
    prefix = base / "qa"
    assert run_script(w["bundle"], "install.sh", ["--prefix", str(prefix)], home).returncode == 0
    done = subprocess.run(["bash", str(w["bundle"] / SCRIPT), "--prefix", str(prefix), "--mirror", str(fake.archives_dir)], env=clean_env(home), cwd=str(home), capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert run_script(w["bundle"], "uninstall.sh", ["--prefix", str(prefix)], home).returncode == 0 and not prefix.exists()


# ------------------------------------------------------------------------------------------------------------------------------ the pin must belong to the installation
def test_a_script_from_another_bundle_whose_lock_differs_is_refused_before_anything_is_created(w, fake, tmp_path):
    other = bh.make_browser_bundle(tmp_path / "other", fake, lock_bytes=fake.lock_bytes.replace(b'"1.0.0"', b'"1.0.1"'), name="redevops-qa-bundle-other")
    done = browser_step(w, "--mirror", str(fake.archives_dir), bundle=other)
    assert done.returncode == 4 and "belongs to another bundle" in done.stderr
    assert prefix_entries(w) == ["INSTALL.json", "bin", "venv"]


def test_a_bundle_directory_without_its_lock_is_refused(w, fake, tmp_path):
    copy = tmp_path / "copy"
    shutil.copytree(w["bundle"], copy)
    (copy / "browser.lock.json").unlink()
    done = browser_step(w, "--mirror", str(fake.archives_dir), bundle=copy)
    assert done.returncode == 4 and "browser.lock.json is missing" in done.stderr
    assert prefix_entries(w) == ["INSTALL.json", "bin", "venv"]


def test_an_installation_without_the_pin_is_refused(tmp_path, fake):
    """An installation made by a bundle that has no browser lock in its wheels: the step does not guess a pin."""
    bundle = bh.make_browser_bundle(tmp_path / "b", fake, ship_lock_in_wheel=False)
    home = tmp_path / "home"
    home.mkdir()
    prefix = tmp_path / "qa"
    assert run_script(bundle, "install.sh", ["--prefix", str(prefix)], home).returncode == 0
    done = subprocess.run(["bash", str(bundle / SCRIPT), "--prefix", str(prefix), "--mirror", str(fake.archives_dir)], env=clean_env(home), cwd=str(home), capture_output=True, text=True)
    assert done.returncode == 5 and "does not carry browser.lock.json" in done.stderr and sorted(os.listdir(prefix)) == ["INSTALL.json", "bin", "venv"]


def test_the_usual_refusals_are_unchanged(w, tmp_path):
    assert browser_step(w, "--bogus").returncode == 2
    done = subprocess.run(["bash", str(w["bundle"] / SCRIPT), "--prefix", "relative"], env=clean_env(w["home"]), capture_output=True, text=True)
    assert done.returncode == 2
    done = subprocess.run(["bash", str(w["bundle"] / SCRIPT), "--prefix", str(tmp_path / "nothing")], env=clean_env(w["home"]), capture_output=True, text=True)
    assert done.returncode == 5 and "not an installation" in done.stderr
    help_text = subprocess.run(["bash", str(w["bundle"] / SCRIPT), "--help"], env=clean_env(w["home"]), capture_output=True, text=True).stdout
    assert "--mirror" in help_text and "NOT covered by the pin" in help_text and "browser.lock.json" in help_text and "set -eu" not in help_text


def test_a_symbolic_link_as_the_browsers_directory_is_refused(w, fake, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, w["prefix"] / "browsers")
    done = browser_step(w, "--mirror", str(fake.archives_dir))
    assert done.returncode == 5 and os.listdir(elsewhere) == []
    (w["prefix"] / "browsers").unlink()


# ------------------------------------------------------------------------------------------------------------------------------ the checker and the builder
def test_the_script_text_states_what_is_pinned_and_what_is_not():
    text = (bh.ROOT / "bundle" / SCRIPT).read_text(encoding="utf-8")
    assert "not hashed" not in text and "browser.lock.json" in text and "NOT covered by the pin" in text and "BEFORE unpacking" in text
