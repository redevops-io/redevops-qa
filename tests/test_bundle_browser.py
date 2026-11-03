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
# ------------------------------------------------------------------------------------------------------------------------------ signals sent to the script alone
def children_of(pid):
    """The download process of the script: its child whose command line is the `browser_pin ... stage` step (not an early short-lived child such as `cmp` or `pin dirs`)."""
    out = subprocess.run(["pgrep", "-P", str(pid), "-f", "qa_runner.browser_pin stage"], capture_output=True, text=True).stdout.split()
    return [int(x) for x in out]


def alive(pid):
    """Still that process: a pid that was recycled for another program is not the download process."""
    command = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True, text=True).stdout
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return "qa_runner.browser_pin stage" in command and bool(state) and not state.startswith("Z")


@pytest.mark.parametrize("sig_name,code", [("SIGTERM", 143), ("SIGINT", 130), ("SIGHUP", 129)])
def test_a_signal_sent_to_the_script_alone_stops_the_download_at_once_and_cleans_up(w, fake, sig_name, code):
    """Not to the process group: what `kill <pid>`, systemd and `timeout` do. The script exits promptly with the signal's status, the download process it started is gone too, and neither the
    staging directory nor the browsers directory this run made is left."""
    import signal
    import time
    before = tree_listing(w["prefix"])
    with bh.serve(fake.archives_dir, delay=30) as url:
        # SIGINT is ignored by a process that a non-interactive shell started with `&` (and so by everything it starts): put the default back so that the script can trap it, as it can from a terminal
        proc = subprocess.Popen(["bash", str(w["bundle"] / SCRIPT), "--prefix", str(w["prefix"]), "--mirror", url], env=clean_env(w["home"]), cwd=str(w["home"]), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL))
        try:
            deadline = time.time() + 60
            kids = []
            while time.time() < deadline and not kids:
                kids = children_of(proc.pid)
                time.sleep(0.1)
            assert kids, "the download process was never started"
            time.sleep(0.5)
            t0 = time.time()
            os.kill(proc.pid, getattr(signal, sig_name))
            proc.communicate(timeout=20)
            elapsed = time.time() - t0
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
    assert proc.returncode == code and elapsed < 10, (proc.returncode, elapsed)
    time.sleep(0.5)
    assert not any(alive(k) for k in kids), "the download process outlived the script"
    assert prefix_entries(w) == ["INSTALL.json", "bin", "venv"] and tree_listing(w["prefix"]) == before


# ------------------------------------------------------------------------------------------------------------------------------ a staging directory left by a killed run
def dead_pid():
    for pid in range(99990, 90000, -1):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return pid
        except PermissionError:
            continue
    raise AssertionError("no unused pid")


def test_the_next_run_removes_the_staging_directory_of_a_run_that_was_killed_and_leaves_the_rest(w, fake, tmp_path):
    browsers = w["prefix"] / "browsers"
    browsers.mkdir()
    gone = dead_pid()
    stale = browsers / f".staging-{gone}"
    (stale / "downloads").mkdir(parents=True)
    (stale / "downloads" / "partial.zip").write_bytes(b"x" * 1000)
    other = browsers / ".staging-notapid"
    other.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    os.symlink(outside, browsers / f".staging-{gone - 1}")
    running = subprocess.Popen(["sleep", "120"])
    try:
        busy = browsers / f".staging-{running.pid}"
        busy.mkdir()
        done = browser_step(w, "--mirror", str(fake.archives_dir))
        assert done.returncode == 0, done.stderr
        assert not stale.exists() and f"removing the staging directory {stale}" in done.stdout
        assert other.is_dir() and busy.is_dir(), "a directory that is not an earlier run's, or whose process is running, is not touched"
        assert (browsers / f".staging-{gone - 1}").is_symlink() and (outside / "keep.txt").read_text() == "keep", "a link is never followed"
    finally:
        running.kill()
        running.wait()
    assert bh.pin_module().verify_tree(browsers, fake.lock) == []


def test_a_stale_staging_directory_that_cannot_be_removed_is_a_warning_and_the_run_goes_on(w, fake, tmp_path):
    """A directory of a dead pid that this user may not remove (an earlier run as root, killed): named in a warning, left alone, and the install (and an idempotent re-run) still succeed. The removal
    is made to fail by a stand-in `rm` in front of the real one, so that the test is the same for a normal user and for root."""
    browsers = w["prefix"] / "browsers"
    browsers.mkdir()
    gone = dead_pid()
    stale = browsers / f".staging-{gone}"
    stale.mkdir()
    (stale / "left-by-root").write_text("x")
    stub = tmp_path / "bin"
    stub.mkdir()
    real_rm = shutil.which("rm")
    (stub / "rm").write_text(f'#!/bin/sh\ncase "$*" in *"$STUB_RM_FAIL"*) echo "rm: cannot remove: Permission denied" >&2; exit 1 ;; esac\nexec {real_rm} "$@"\n')
    (stub / "rm").chmod(0o755)
    env = {"PATH": f"{stub}:{os.environ.get('PATH', '/usr/bin:/bin')}", "STUB_RM_FAIL": f".staging-{gone}"}
    done = browser_step(w, "--mirror", str(fake.archives_dir), env=env)
    assert done.returncode == 0, done.stderr
    assert f"warning: cannot remove {stale}" in done.stdout and "Permission denied" not in done.stderr and (stale / "left-by-root").is_file()
    assert bh.pin_module().verify_tree(browsers, fake.lock) == []
    again = browser_step(w, "--mirror", "http://127.0.0.1:9/", env=env)                         # idempotent path, with the directory still there
    assert again.returncode == 0 and "already installed and identical to the pin" in again.stdout and f"warning: cannot remove {stale}" in again.stdout


# ------------------------------------------------------------------------------------------------------------------------------ usage, credentials, a failed final check
@pytest.mark.parametrize("bad", ["ftp://example.invalid/x", "relative/dir", "gopher://user:s3cret@host/"])
def test_an_unusable_mirror_is_a_usage_error_with_exit_2_and_changes_nothing(w, bad):
    before = tree_listing(w["prefix"])
    done = browser_step(w, "--mirror", bad)
    assert done.returncode == 2 and "--mirror takes" in done.stderr and "s3cret" not in done.stderr + done.stdout
    assert_nothing_installed(w, before)


def test_credentials_in_a_mirror_url_do_not_appear_in_the_output(w):
    before = tree_listing(w["prefix"])
    done = browser_step(w, "--mirror", "http://alice:s3cret@127.0.0.1:9/")
    assert done.returncode == 6 and "127.0.0.1:9" in done.stderr
    assert "s3cret" not in done.stderr + done.stdout and "alice" not in done.stderr + done.stdout
    assert_nothing_installed(w, before)


def test_a_failed_final_check_removes_what_this_run_placed_and_keeps_what_was_there(tmp_path, fake):
    """The check after the placement is forced to fail (the installed copy of the module is edited to report a difference when asked): the install directories this run moved into place are
    removed again, an install directory that was already there is not, and the exit status is 6."""
    patch = ('problems = verify_tree(browsers, lock)\n            if args.json:', 'problems = verify_tree(browsers, lock) + ([Problem("CHANGED", "x", "forced")] if os.environ.get("QA_TEST_FAIL_VERIFY") else [])\n            if args.json:')
    bundle = bh.make_browser_bundle(tmp_path / "b", fake, patch=patch)
    home = tmp_path / "home"
    home.mkdir()
    prefix = tmp_path / "qa"
    assert run_script(bundle, "install.sh", ["--prefix", str(prefix)], home).returncode == 0
    env = clean_env(home)
    argv = ["bash", str(bundle / SCRIPT), "--prefix", str(prefix), "--mirror", str(fake.archives_dir)]
    done = subprocess.run(argv, env={**env, "QA_TEST_FAIL_VERIFY": "1"}, cwd=str(home), capture_output=True, text=True)
    assert done.returncode == 6 and "the installed tree does not match the pin" in done.stderr
    assert sorted(os.listdir(prefix)) == ["INSTALL.json", "bin", "venv"]
    assert subprocess.run(argv, env=env, cwd=str(home), capture_output=True, text=True).returncode == 0           # without the forced failure the same run installs
    shutil.rmtree(prefix / "browsers" / "ffmpeg-1000")
    done = subprocess.run(argv, env={**env, "QA_TEST_FAIL_VERIFY": "1"}, cwd=str(home), capture_output=True, text=True)
    assert done.returncode == 6 and sorted(os.listdir(prefix / "browsers")) == ["chromium-1000", "chromium_headless_shell-1000"]


def test_install_sh_records_the_digest_of_the_browser_lock_it_installed(world, fake):
    doc = json.loads((world["prefix"] / "INSTALL.json").read_text(encoding="utf-8"))
    assert doc["browser_lock_sha256"] == hashlib.sha256(fake.lock_bytes).hexdigest()
    assert doc["entries"] == ["venv", "bin", "browsers", "INSTALL.json"]



def test_the_script_text_states_what_is_pinned_and_what_is_not():
    text = (bh.ROOT / "bundle" / SCRIPT).read_text(encoding="utf-8")
    assert "not hashed" not in text and "browser.lock.json" in text and "NOT covered by the pin" in text and "BEFORE unpacking" in text
