# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The mobile adapter (Android wiring) against the fake device, through the shared InteractiveSession."""
import hashlib
import json

import pytest

from ap_support import PKG, a, make_session
from qa_adapter_kit import ErrorCode, Limits, Status, canonical_status, map_to_canonical
from qa_appium import MobileConfig, parse_mobile_locator
from qa_appium.testing.fake import FakeDevice, FakeNode, PNG, default_screens

TITLE = f"id={PKG}:id/title"


def start(s, step=0):
    r = s.perform(a(step, "open_app"))
    assert r.status is Status.PASS, r
    return r


def test_open_tap_read_back(tmp_path):
    s, _, holder = make_session(tmp_path)
    start(s)
    assert s.perform(a(1, "tap", "acc=Continue")).status is Status.PASS and holder["device"].screen == "done"
    assert s.perform(a(2, "read", f"id={PKG}:id/result")).observations[0].summary == f"text of id={PKG}:id/result: Done"
    assert s.perform(a(3, "back")).status is Status.PASS and holder["device"].screen == "home"


def test_the_app_must_be_in_the_foreground_for_open_app(tmp_path):
    s, _, _ = make_session(tmp_path, device=FakeDevice(PKG, foreground="com.other.app"))
    r = s.perform(a(0, "open_app"))
    assert r.status is Status.ERROR and "foreground" in r.error_message and r.error_code is ErrorCode.RETRY_LIMIT        # retried, then limited


def test_read_normalises_whitespace_and_is_bounded(tmp_path):
    screens = default_screens()
    screens["home"][TITLE].text = "x" * 5000
    s, _, _ = make_session(tmp_path, device=FakeDevice(PKG, screens))
    start(s)
    assert len(s.perform(a(1, "read", TITLE)).observations[0].summary) < 2100
    s2, _, _ = make_session(tmp_path / "b")
    start(s2)
    assert s2.perform(a(1, "read", TITLE)).observations[0].summary.endswith("Welcome aboard")


def test_typing_never_echoes_the_text_and_a_secret_never_reaches_a_log_or_result(tmp_path):
    secret = "pw-" + hashlib.sha256(b"y").hexdigest()[:16]
    s, _, holder = make_session(tmp_path)
    start(s)
    r = s.perform(a(1, "type", f"id={PKG}:id/name", secret_value=secret))
    assert r.status is Status.PASS and secret not in json.dumps(r.to_dict()) and "typed 19 characters" in r.observations[0].summary
    assert secret not in " ".join(holder["device"].log)
    back = s.perform(a(2, "read", f"id={PKG}:id/name", secret_value=secret))
    assert secret not in json.dumps(back.to_dict())


def test_type_needs_a_value_and_an_unknown_action_is_refused(tmp_path):
    s, _, _ = make_session(tmp_path)
    start(s)
    assert s.perform(a(1, "type", f"id={PKG}:id/name")).error_code is ErrorCode.INVALID_REQUEST
    assert s.perform(a(2, "shell", "x")).error_code is ErrorCode.INVALID_REQUEST


@pytest.mark.parametrize("target", ["", "//android.widget.Button", "xpath=//a", "id=", "id=a;b", "acc=a\nb", "id=" + "x" * 300, "text=Continue"])
def test_locators_are_id_or_accessibility_id_only(tmp_path, target):
    s, _, _ = make_session(tmp_path)
    start(s)
    r = s.perform(a(1, "tap", target))
    assert r.status is Status.ERROR and r.attempts == 1


@pytest.mark.parametrize("text,kind", [("id=com.example.app:id/title", "id"), ("acc=Continue", "acc"), ("acc=Sign in", "acc")])
def test_valid_locators(text, kind):
    loc = parse_mobile_locator(text)
    assert loc.kind == kind and str(loc) == text


# ---------------------------------------------------------------------------------------------- checks
def test_a_matching_check_is_native_evidence_and_stays_unverified_for_the_oracle(tmp_path):
    s, _, _ = make_session(tmp_path)
    start(s)
    r = s.perform(a(1, "check", TITLE, value="Welcome aboard", assertion_id="A-1"))
    [ev] = map_to_canonical(r, ("A-1",), {r.native_assertions[0].native_id: "A-1"}).evidence
    assert r.status is Status.PASS and ev.native_status is Status.PASS and canonical_status(ev) is Status.UNVERIFIED


def test_a_differing_check_fails_without_echoing_screen_text(tmp_path):
    s, _, _ = make_session(tmp_path)
    start(s)
    r = s.perform(a(1, "check", TITLE, value="Goodbye", assertion_id="A-1"))
    msg = r.native_assertions[0].message
    assert r.status is Status.FAIL and "Welcome" not in msg and "Goodbye" not in msg and "expected 7 characters, found 14" in msg


def test_a_check_on_a_missing_element_fails_and_one_without_a_declared_id_supports_nothing(tmp_path):
    s, _, _ = make_session(tmp_path)
    start(s)
    r = s.perform(a(1, "check", f"id={PKG}:id/nope", value="x", assertion_id="A-1"))
    assert r.status is Status.FAIL and r.native_assertions[0].message == "the element was not found"
    r2 = s.perform(a(2, "check", TITLE, value="Welcome aboard"))
    assert map_to_canonical(r2, ("A-1",), {r2.native_assertions[0].native_id: "A-1"}).evidence[0].native_status is Status.UNVERIFIED


# ---------------------------------------------------------------------------------------------- screenshots
def test_screenshots_are_off_by_default_and_stored_and_hashed_when_enabled(tmp_path):
    s, _, _ = make_session(tmp_path)
    start(s)
    assert "cannot be redacted" in s.perform(a(1, "screenshot")).error_message
    s2, _, _ = make_session(tmp_path / "b", config=MobileConfig(app_package=PKG, allow_screenshots=True))
    start(s2)
    r = s2.perform(a(1, "screenshot"))
    assert r.status is Status.PASS and r.artifacts[0].sha256 == hashlib.sha256(PNG).hexdigest()


# ---------------------------------------------------------------------------------------------- faults
def test_a_stale_node_is_retried_and_one_that_stays_stale_ends_at_the_limit(tmp_path):
    s, _, _ = make_session(tmp_path)
    start(s)
    r = s.perform(a(1, "read", f"id={PKG}:id/flaky"))
    assert r.status is Status.PASS and r.attempts == 2
    r2 = s.perform(a(2, "read", f"id={PKG}:id/stale"))
    assert r2.error_code is ErrorCode.RETRY_LIMIT and r2.attempts == 3


def test_a_disabled_node_is_not_interactable_and_a_missing_one_is_not_retried(tmp_path):
    s, _, _ = make_session(tmp_path)
    start(s)
    assert s.perform(a(1, "tap", f"id={PKG}:id/disabled")).error_code is ErrorCode.RETRY_LIMIT
    r = s.perform(a(2, "tap", f"id={PKG}:id/nope"))
    assert r.attempts == 1 and "NOT_FOUND" in r.error_message


def test_a_crash_is_an_adapter_crash_without_driver_text(tmp_path):
    s, _, _ = make_session(tmp_path, device=FakeDevice(PKG, crash_on="tap"))
    start(s)
    assert s.perform(a(1, "tap", "acc=Continue")).error_code is ErrorCode.ADAPTER_CRASH


def test_a_missing_device_is_unavailable_never_a_pass_or_a_skip(tmp_path):
    from qa_adapter_kit import AdapterUnavailable
    def factory():
        from qa_appium import DriverFault, FaultKind
        raise DriverFault(FaultKind.UNAVAILABLE)
    s, _, _ = make_session(tmp_path, factory=factory)
    r = s.perform(a(0, "open_app"))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.UNAVAILABLE and r.attempts == 1


def test_the_driver_is_created_lazily_and_closed(tmp_path):
    calls = []

    def factory():
        calls.append(1)
        return FakeDevice(PKG)
    s, adapter, _ = make_session(tmp_path, factory=factory)
    assert calls == []
    start(s)
    s.close()
    assert calls == [1] and adapter._driver is None


def test_the_step_limit_applies(tmp_path):
    s, _, _ = make_session(tmp_path, limits=Limits(deadline_s=30, max_steps=2, max_retries=1))
    start(s)
    assert s.perform(a(1, "back")).status is Status.PASS
    assert s.perform(a(2, "back")).error_code is ErrorCode.STEP_LIMIT


@pytest.mark.parametrize("package", ["", "app", "com..x", "Com.example;rm", "com.example.app extra", "1com.example"])
def test_the_app_package_must_look_like_a_package_name(package):
    with pytest.raises(ValueError):
        MobileConfig(app_package=package)
