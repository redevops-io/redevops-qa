# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``doctor`` and ``run`` against the browser pin: a browser that is not installed says so, one that differs from the pin fails and is not launched, one that matches passes, a pin for
another revision or another Playwright fails; a plan without a browser lane does not need the browser. Synthetic prefixes and a stand-in browser; nothing is launched."""
import hashlib
import json
import os
from pathlib import Path

import pytest

import qa_runner.doctor as doctor
from qa_runner import browser_pin as bp
from qa_runner import constants as K
from qr_browser_fake import REGISTRY, make_fake_browser
from test_qr_doctor_bundle import plan_file, reaches_run_plan, run_cli


@pytest.fixture()
def box(tmp_path):
    """A bundle-like prefix (share/redevops-qa/browser.lock.json), a registry file standing for the Playwright package's browsers.json, and a browsers directory."""
    fake = make_fake_browser(tmp_path)
    prefix = tmp_path / "prefix"
    share = prefix / "share" / "redevops-qa"
    share.mkdir(parents=True)
    (share / bp.LOCK_NAME).write_bytes(fake.lock_bytes)
    registry = tmp_path / "browsers.json"
    registry.write_bytes(REGISTRY)
    browsers = tmp_path / "pw-browsers"
    return type("Box", (), {"fake": fake, "prefix": prefix, "registry": registry, "browsers": browsers, "tmp": tmp_path})


def check(box, **kw):
    args = {"prefix": str(box.prefix), "browsers": box.browsers, "registry": box.registry, "playwright_version": "1.0.0"}
    args.update(kw)
    return doctor.check_browser_pin(**args)


# ------------------------------------------------------------------------------------------------------------------------ the check
def test_outside_a_bundle_install_there_is_no_pin_and_the_check_says_it_did_not_run(tmp_path):
    c = doctor.check_browser_pin(prefix=str(tmp_path), browsers=tmp_path / "nothing")
    assert c.status == "WARN" and c.name == "browser build" and "not checked" in c.detail and "not a bundle install" in c.detail and "applies to bundle installs only" in c.detail


def test_a_browser_that_was_never_installed_is_reported_as_not_installed_with_the_command_that_installs_it(box):
    c = check(box)
    assert c.status == "FAIL" and c.detail.startswith("not installed") and "browser step has not been run" in c.detail and str(box.browsers) in c.detail
    assert "./install-browser.sh --prefix" in c.remedy and "--with-deps" in c.remedy


def test_an_empty_browsers_directory_is_also_not_installed(box):
    box.browsers.mkdir()
    assert check(box).detail.startswith("not installed")


def test_an_installation_identical_to_the_pin_passes_and_the_detail_says_what_is_and_is_not_covered(box):
    box.fake.install(box.browsers)
    c = check(box)
    assert c.status == "OK" and "Chromium 9.9.9.9" in c.detail and f"{len(box.fake.lock.files)} files in 3 install directories" in c.detail
    assert "operating system libraries" in c.detail and "changes after this check" in c.detail and box.fake.lock.digest[:12] in c.detail


def test_the_marker_playwright_writes_when_it_first_launches_the_browser_does_not_fail_the_check(box):
    box.fake.install(box.browsers)
    (box.browsers / "chromium_headless_shell-1000" / "DEPENDENCIES_VALIDATED").write_bytes(b"")
    assert check(box).status == "OK"


def test_a_changed_browser_file_fails_and_names_the_file_and_the_remedy(box):
    box.fake.install(box.browsers)
    target = box.browsers / "chromium_headless_shell-1000/chrome-headless-shell-linux64/chrome-headless-shell"
    target.write_bytes(b"#!/bin/sh\necho evil headless shell!!!\n")
    c = check(box)
    assert c.status == "FAIL" and "not the pinned build" in c.detail and "chromium_headless_shell-1000/chrome-headless-shell-linux64/chrome-headless-shell" in c.detail
    assert "do not use this browser" in c.remedy and "install-browser.sh" in c.remedy


@pytest.mark.parametrize("what,edit", [
    ("a changed mode", lambda b: os.chmod(b / "chromium-1000/chrome-linux64/chrome", 0o777)),
    ("an extra file", lambda b: (b / "chromium-1000/chrome-linux64/extra.so").write_bytes(b"x")),
    ("a missing file", lambda b: (b / "chromium-1000/chrome-linux64/resources.pak").unlink()),
    ("a missing install directory", lambda b: __import__("shutil").rmtree(b / "ffmpeg-1000")),
    ("a linked file", lambda b: (os.unlink(b / "ffmpeg-1000/COPYING.LGPLv2.1"), os.symlink("/etc/hostname", b / "ffmpeg-1000/COPYING.LGPLv2.1"))),
])
def test_every_kind_of_difference_fails(box, what, edit):
    box.fake.install(box.browsers)
    edit(box.browsers)
    c = check(box)
    assert c.status == "FAIL" and "not installed" not in c.detail.split(":")[0], what


def test_a_pin_for_another_revision_than_the_installed_playwright_expects_fails(box):
    box.fake.install(box.browsers)
    box.registry.write_bytes(json.dumps({"browsers": [{"name": "chromium", "revision": "1001", "browserVersion": "9.9.9.10"}]}).encode())
    c = check(box)
    assert c.status == "FAIL" and "browsers.json" in c.detail and "is not the pinned one" in c.detail and "revision 1000" in c.detail
    assert check(box, registry=box.tmp / "missing.json").status == "FAIL"


def test_a_pin_for_another_playwright_version_fails(box):
    box.fake.install(box.browsers)
    c = check(box, playwright_version="1.2.3")
    assert c.status == "FAIL" and "pin is for playwright 1.0.0" in c.detail and "1.2.3" in c.detail
    missing = check(box, playwright_version="")
    assert missing.status == "FAIL" and "has no playwright" in missing.detail


def test_a_lock_that_cannot_be_used_fails_and_does_not_pass_as_not_a_bundle(box):
    (box.prefix / "share" / "redevops-qa" / bp.LOCK_NAME).write_text("{}")
    c = check(box)
    assert c.status == "FAIL" and "cannot be used" in c.detail


def test_the_browsers_directory_is_the_one_playwright_will_use(tmp_path):
    assert doctor.browsers_directory({"PLAYWRIGHT_BROWSERS_PATH": "/opt/x/browsers", "HOME": "/h"}) == Path("/opt/x/browsers")
    assert doctor.browsers_directory({"HOME": "/h"}) == Path("/h/.cache/ms-playwright")
    assert doctor.browsers_directory({"HOME": "/h", "XDG_CACHE_HOME": "/xdg"}) == Path("/xdg/ms-playwright")
    assert doctor.browsers_directory({"PLAYWRIGHT_BROWSERS_PATH": "0"}).name == ".local-browsers"


def test_the_check_follows_playwright_browsers_path_when_no_directory_is_given(box, monkeypatch):
    box.fake.install(box.browsers)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(box.browsers))
    assert doctor.check_browser_pin(prefix=str(box.prefix), registry=box.registry, playwright_version="1.0.0").status == "OK"
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(box.tmp / "elsewhere"))
    assert doctor.check_browser_pin(prefix=str(box.prefix), registry=box.registry, playwright_version="1.0.0").detail.startswith("not installed")


# ------------------------------------------------------------------------------------------------------------------------ doctor as a whole
def stub_others(monkeypatch):
    for name in ("check_python", "check_platform", "check_workdir", "check_first_party_modules", "check_pins", "check_pinned_files", "check_robot", "check_fixture_app", "check_egress_gateway"):
        monkeypatch.setattr(doctor, name, lambda name=name: doctor.Check(name, "OK", "stubbed"))
    monkeypatch.setattr(doctor, "check_path_policy", lambda robot=True: doctor.Check("adapter path policy", "OK", "stubbed"))


def test_doctor_does_not_launch_a_browser_that_failed_the_pin_check(monkeypatch):
    stub_others(monkeypatch)
    launched = []
    monkeypatch.setattr(doctor, "check_playwright", lambda run=None: launched.append(1) or doctor.Check("chromium", "OK", "launched"))
    monkeypatch.setattr(doctor, "check_browser_pin", lambda: doctor.Check("browser build", "FAIL", "the browser in X is not the pinned build", "reinstall it"))
    checks = doctor.run_doctor((K.ENGINE_PLAYWRIGHT,))
    by = {c.name: c for c in checks}
    assert launched == [] and by["browser build"].status == "FAIL" and by["chromium"].status == "FAIL" and "not launched" in by["chromium"].detail and by["chromium"].remedy == "reinstall it"
    assert [c.name for c in checks].index("browser build") < [c.name for c in checks].index("chromium")


def test_doctor_launches_the_browser_when_the_pin_check_passes_or_does_not_apply(monkeypatch):
    stub_others(monkeypatch)
    launched = []
    monkeypatch.setattr(doctor, "check_playwright", lambda run=None: launched.append(1) or doctor.Check("chromium", "OK", "launched"))
    for status in ("OK", "WARN"):
        monkeypatch.setattr(doctor, "check_browser_pin", lambda status=status: doctor.Check("browser build", status, "fine"))
        assert not any(c.status == "FAIL" for c in doctor.run_doctor((K.ENGINE_PLAYWRIGHT,)))
    assert launched == [1, 1]


def test_doctor_with_a_robot_only_plan_does_not_check_the_browser_at_all(monkeypatch):
    stub_others(monkeypatch)
    called = []
    monkeypatch.setattr(doctor, "check_browser_pin", lambda: called.append(1) or doctor.Check("browser build", "FAIL", "x"))
    monkeypatch.setattr(doctor, "check_playwright", lambda run=None: called.append(2) or doctor.Check("chromium", "FAIL", "x"))
    checks = doctor.run_doctor((K.ENGINE_ROBOT,))
    assert called == [] and not any(c.status == "FAIL" for c in checks) and "browser build" not in [c.name for c in checks]


def test_a_doctor_report_of_a_missing_browser_exits_3_with_the_remedy_in_the_text(monkeypatch, tmp_path):
    stub_others(monkeypatch)
    monkeypatch.setattr(doctor, "check_browser_pin", lambda: doctor.Check("browser build", "FAIL", "not installed: none of x is in y", "run ./install-browser.sh --prefix <dir>"))
    code, out, _err = run_cli("doctor", "--plan", str(plan_file(tmp_path, {K.ENGINE_PLAYWRIGHT})))
    assert code == K.EXIT_ENVIRONMENT == 3 and "[FAIL] browser build: not installed" in out and "to fix: run ./install-browser.sh" in out and "[FAIL] chromium: not launched" in out


# ------------------------------------------------------------------------------------------------------------------------ run and demo
def fail_pin(monkeypatch, calls=None):
    def fail():
        if calls is not None:
            calls.append(1)
        return doctor.Check("browser build", "FAIL", "the browser in /x is not the pinned build: 1 difference(s) from the pin (1 CHANGED): CHANGED chromium-1000/chrome-linux64/chrome", "reinstall it")
    monkeypatch.setattr(doctor, "check_browser_pin", fail)


def test_run_refuses_a_browser_lane_against_a_browser_that_fails_the_pin_and_starts_nothing(monkeypatch, tmp_path):
    fail_pin(monkeypatch)
    out_dir = tmp_path / "evidence"
    for engines in ({K.ENGINE_PLAYWRIGHT}, {K.ENGINE_PLAYWRIGHT, K.ENGINE_ROBOT}):
        reached, code, _out, err = reaches_run_plan(monkeypatch, tmp_path, "run", str(plan_file(tmp_path, engines)), "--out", str(out_dir))
        assert reached == [] and code == K.EXIT_ENVIRONMENT and "BROWSER_PIN" in err and "not the pinned build" in err and "Nothing was started and no evidence directory was made" in err
        assert not out_dir.exists()


def test_demo_makes_the_same_check(monkeypatch, tmp_path):
    fail_pin(monkeypatch)
    out_dir = tmp_path / "evidence"
    reached, code, _out, err = reaches_run_plan(monkeypatch, tmp_path, "demo", "--out", str(out_dir))
    assert reached == [] and code == K.EXIT_ENVIRONMENT and "BROWSER_PIN" in err and not out_dir.exists()


def test_a_plan_without_a_browser_lane_is_not_stopped_by_the_browser_and_does_not_even_check_it(monkeypatch, tmp_path):
    calls = []
    fail_pin(monkeypatch, calls)
    reached, code, _out, err = reaches_run_plan(monkeypatch, tmp_path, "run", str(plan_file(tmp_path, {K.ENGINE_ROBOT})), "--out", str(tmp_path / "evidence"))
    assert reached == [1] and calls == [] and "BROWSER_PIN" not in err


def test_a_passing_browser_check_lets_the_run_start(monkeypatch, tmp_path):
    monkeypatch.setattr(doctor, "check_browser_pin", lambda: doctor.Check("browser build", "OK", "fine"))
    reached, code, _out, err = reaches_run_plan(monkeypatch, tmp_path, "run", str(plan_file(tmp_path, {K.ENGINE_PLAYWRIGHT})), "--out", str(tmp_path / "evidence"))
    assert reached == [1] and "BROWSER_PIN" not in err


def test_the_run_check_is_the_doctor_check_not_a_copy(monkeypatch):
    """cli takes ``check_browser_pin`` from doctor at the moment of the run: one definition of what 'the pinned build' means."""
    import inspect
    from qa_runner import cli
    src = inspect.getsource(cli._refuse_a_browser_that_is_not_the_pinned_build)
    assert "from .doctor import check_browser_pin" in src and "check_browser_pin()" in src


def test_the_real_check_in_a_development_environment_passes_and_says_it_was_not_made(tmp_path, monkeypatch):
    """No bundle share directory under this Python's prefix: the same code path run and demo take in a checkout (the CI jobs that run the browser tests in one)."""
    monkeypatch.setattr(doctor, "_share", lambda prefix=None: tmp_path / "no-share")
    c = doctor.check_browser_pin()
    assert c.status == "WARN" and "not checked" in c.detail and "bundle installs only" in c.detail


# ------------------------------------------------------------------------------------------------------------------------ a bundle installation that lost its pin
def make_install(box, **doc):
    """INSTALL.json beside the prefix (the virtual environment): what makes a directory a bundle installation."""
    (box.prefix.parent / "INSTALL.json").write_text(json.dumps({"schema": "redevops-qa/install", **doc}))


def test_a_bundle_installation_whose_lock_is_missing_fails_and_is_not_called_not_a_bundle_install(box):
    make_install(box)
    lock = box.prefix / "share" / "redevops-qa" / bp.LOCK_NAME
    lock.unlink()
    c = check(box)
    assert c.status == "FAIL" and "this is a bundle installation" in c.detail and "missing" in c.detail and "not a bundle install" not in c.detail and "reinstall" in c.remedy


def test_a_bundle_installation_whose_lock_is_a_directory_unreadable_or_not_a_lock_fails(box):
    make_install(box)
    lock = box.prefix / "share" / "redevops-qa" / bp.LOCK_NAME
    lock.unlink()
    lock.mkdir()
    assert check(box).status == "FAIL"
    lock.rmdir()
    lock.write_bytes(b"\xff\xfe")
    assert check(box).status == "FAIL" and "cannot be used" in check(box).detail


def test_run_and_demo_refuse_a_browser_lane_in_a_bundle_installation_that_lost_its_lock(box, monkeypatch, tmp_path):
    make_install(box)
    (box.prefix / "share" / "redevops-qa" / bp.LOCK_NAME).unlink()
    box.fake.install(box.browsers)
    (box.browsers / "ffmpeg-1000/COPYING.LGPLv2.1").write_bytes(b"changed")                 # a modified browser, and no pin to notice it by
    monkeypatch.setattr(doctor.sys, "prefix", str(box.prefix))
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(box.browsers))
    out_dir = tmp_path / "evidence"
    for argv in (("run", str(plan_file(tmp_path, {K.ENGINE_PLAYWRIGHT})), "--out", str(out_dir)), ("demo", "--out", str(out_dir))):
        reached, code, _out, err = reaches_run_plan(monkeypatch, tmp_path, *argv)
        assert reached == [] and code == K.EXIT_ENVIRONMENT and "BROWSER_PIN" in err and "bundle installation" in err and not out_dir.exists()
    code, out, _err = run_cli("doctor", "--plan", str(plan_file(tmp_path, {K.ENGINE_PLAYWRIGHT})))
    assert code == K.EXIT_ENVIRONMENT and "[FAIL] browser build: this is a bundle installation" in out
    reached, code, _out, err = reaches_run_plan(monkeypatch, tmp_path, "run", str(plan_file(tmp_path, {K.ENGINE_ROBOT})), "--out", str(out_dir))
    assert reached == [1] and "BROWSER_PIN" not in err


def test_a_lock_that_is_not_the_one_install_sh_recorded_fails_and_a_matching_or_absent_record_passes(box):
    box.fake.install(box.browsers)
    make_install(box, browser_lock_sha256="0" * 64)
    c = check(box)
    assert c.status == "FAIL" and "not the browser pin install.sh recorded" in c.detail and box.fake.lock.digest in c.detail
    make_install(box, browser_lock_sha256=box.fake.lock.digest)
    assert check(box).status == "OK"
    make_install(box)                                    # an installation made before the record existed
    assert check(box).status == "OK"
    (box.prefix.parent / "INSTALL.json").write_text("not json")
    assert check(box).status == "OK"


def test_a_bundle_installation_without_playwright_browsers_path_is_a_failure_that_names_the_launcher(box, monkeypatch):
    make_install(box)
    monkeypatch.setattr(doctor.sys, "prefix", str(box.prefix))
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    c = doctor.check_browser_pin(registry=box.registry, playwright_version="1.0.0")
    assert c.status == "FAIL" and "PLAYWRIGHT_BROWSERS_PATH is not set" in c.detail and "bin/redevops-qa" in c.remedy
    box.fake.install(box.browsers)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(box.browsers))
    assert doctor.check_browser_pin(registry=box.registry, playwright_version="1.0.0").status == "OK"
