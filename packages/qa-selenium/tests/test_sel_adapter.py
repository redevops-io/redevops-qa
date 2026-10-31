# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The interactive Selenium adapter against the fake browser, through the shared InteractiveSession."""
import hashlib
import json

import pytest

from sel_support import HOSTS, act, make_session
from qa_adapter_kit import ErrorCode, Limits, Status, canonical_status, map_to_canonical
from qa_selenium import AdapterConfig, DriverFault, FaultKind, check_url
from qa_selenium.testing.fake import FakeBrowser, PNG, site

HOME = "http://app.test:8080/"


def open_home(s, step=0):
    r = s.perform(act(step, "open", HOME))
    assert r.status is Status.PASS, r
    return r


# ---------------------------------------------------------------------------------------------- navigation policy
@pytest.mark.parametrize("url", ["http://evil.test/", "http://app.test/", "http://app.test:9999/", "ftp://app.test:8080/",
                                 "file:///etc/passwd", "javascript:alert(1)", "data:text/html,x", "http://user:pw@app.test:8080/",
                                 "http://app.test:8080@evil.test/", "http://127.0.0.1:8080/", "app.test:8080", "", "http://", "http://[::1"])
def test_a_navigation_outside_the_allowlist_is_refused_before_the_browser_is_touched(tmp_path, url):
    s, adapter, holder = make_session(tmp_path)
    r = s.perform(act(0, "open", url))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.INVALID_REQUEST and "browser" not in holder


def test_no_allowlist_means_no_navigation(tmp_path):
    s, _, holder = make_session(tmp_path, config=AdapterConfig())
    assert s.perform(act(0, "open", HOME)).error_code is ErrorCode.INVALID_REQUEST and "browser" not in holder


def test_host_entries_and_ports():
    check_url("http://a.test/", frozenset({"a.test"}))
    check_url("https://a.test/", frozenset({"a.test"}))
    check_url("http://a.test:80/", frozenset({"a.test"}))
    check_url("http://a.test:8080/", frozenset({"a.test:8080"}))
    for url in ("http://a.test:8080/", "https://a.test:8443/"):
        with pytest.raises(Exception):
            check_url(url, frozenset({"a.test"}))


def test_a_redirect_to_a_host_that_is_not_allowed_is_refused_and_the_browser_is_sent_away(tmp_path):
    s, _, holder = make_session(tmp_path)
    r = s.perform(act(0, "open", "http://app.test:8080/jump"))
    assert r.status is Status.ERROR and "redirected" in r.error_message
    assert holder["browser"].url == "about:blank" and holder["browser"].log[-1] == "open about:blank"


# ---------------------------------------------------------------------------------------------- actions
def test_open_click_read(tmp_path):
    s, _, holder = make_session(tmp_path)
    open_home(s)
    assert s.perform(act(1, "click", "testid=submit")).status is Status.PASS
    r = s.perform(act(2, "read", "id=result"))
    assert r.observations[0].summary == "text of id=result: Done" and holder["browser"].url == "http://app.test:8080/done"


def test_read_normalises_whitespace(tmp_path):
    s, _, _ = make_session(tmp_path)
    open_home(s)
    assert s.perform(act(1, "read", "id=title")).observations[0].summary.endswith("Welcome home")


def test_a_long_text_is_cut(tmp_path):
    pages = site()
    pages[HOME].elements['[id="title"]'].text = "x" * 5000
    s, _, _ = make_session(tmp_path, browser=FakeBrowser(pages))
    open_home(s)
    assert len(s.perform(act(1, "read", "id=title")).observations[0].summary) < 2100


def test_typing_never_echoes_the_text_and_a_secret_never_reaches_a_log_or_result(tmp_path):
    secret = "pw-" + hashlib.sha256(b"x").hexdigest()[:16]
    s, _, holder = make_session(tmp_path)
    open_home(s)
    r = s.perform(act(1, "type", "name=user", secret_value=secret))
    assert r.status is Status.PASS and secret not in json.dumps(r.to_dict()) and r.observations[0].summary == "typed 19 characters into name=user"
    assert secret not in " ".join(holder["browser"].log)
    # reading the field back is redacted by the session because the secret is known to it
    back = s.perform(act(2, "read", "name=user", secret_value=secret))
    assert secret not in json.dumps(back.to_dict())


def test_type_needs_a_value(tmp_path):
    s, _, _ = make_session(tmp_path)
    open_home(s)
    assert s.perform(act(1, "type", "name=user")).error_code is ErrorCode.INVALID_REQUEST


def test_an_unknown_action_is_refused_by_the_session(tmp_path):
    s, _, _ = make_session(tmp_path)
    assert s.perform(act(0, "navigate", HOME)).error_code is ErrorCode.INVALID_REQUEST


def test_a_bad_locator_is_refused(tmp_path):
    s, _, _ = make_session(tmp_path)
    open_home(s)
    r = s.perform(act(1, "click", "//a[@href]"))
    assert r.status is Status.ERROR and r.attempts == 1


# ---------------------------------------------------------------------------------------------- checks
def test_a_matching_check_is_a_native_pass_that_proves_nothing_alone(tmp_path):
    s, _, _ = make_session(tmp_path)
    open_home(s)
    r = s.perform(act(1, "check", "id=title", value="Welcome home", assertion_id="A-1"))
    assert r.status is Status.PASS and r.native_assertions[0].declared_assertion_ids == ("A-1",)
    [ev] = map_to_canonical(r, ("A-1",), {r.native_assertions[0].native_id: "A-1"}).evidence
    assert ev.native_status is Status.PASS and canonical_status(ev) is Status.UNVERIFIED


def test_a_differing_check_fails_without_echoing_page_text(tmp_path):
    s, _, _ = make_session(tmp_path)
    open_home(s)
    r = s.perform(act(1, "check", "id=title", value="Goodbye", assertion_id="A-1"))
    assert r.status is Status.FAIL and "Welcome" not in r.native_assertions[0].message and "Goodbye" not in r.native_assertions[0].message
    assert "expected 7 characters, found 12" in r.native_assertions[0].message


def test_a_check_on_a_missing_element_fails(tmp_path):
    s, _, _ = make_session(tmp_path)
    open_home(s)
    r = s.perform(act(1, "check", "id=nope", value="x", assertion_id="A-1"))
    assert r.status is Status.FAIL and r.native_assertions[0].message == "the element was not found"


def test_a_check_without_a_declared_assertion_cannot_support_one(tmp_path):
    s, _, _ = make_session(tmp_path)
    open_home(s)
    r = s.perform(act(1, "check", "id=title", value="Welcome home"))
    [ev] = map_to_canonical(r, ("A-1",), {r.native_assertions[0].native_id: "A-1"}).evidence
    assert r.status is Status.PASS and ev.native_status is Status.UNVERIFIED


def test_a_check_needs_an_expected_value(tmp_path):
    s, _, _ = make_session(tmp_path)
    open_home(s)
    assert s.perform(act(1, "check", "id=title")).error_code is ErrorCode.INVALID_REQUEST


# ---------------------------------------------------------------------------------------------- screenshots
def test_screenshots_are_off_by_default(tmp_path):
    s, _, _ = make_session(tmp_path)
    open_home(s)
    r = s.perform(act(1, "screenshot"))
    assert r.status is Status.ERROR and "cannot be redacted" in r.error_message


def test_an_enabled_screenshot_is_stored_and_hashed(tmp_path):
    s, _, _ = make_session(tmp_path, config=AdapterConfig(allowed_hosts=HOSTS, allow_screenshots=True))
    open_home(s)
    r = s.perform(act(1, "screenshot"))
    assert r.status is Status.PASS and r.artifacts[0].sha256 == hashlib.sha256(PNG).hexdigest() and r.artifacts[0].media_type == "image/png"
    assert (tmp_path / "out" / r.artifacts[0].path).read_bytes() == PNG


def test_a_screenshot_that_is_not_a_png_is_refused(tmp_path):
    class Bad(FakeBrowser):
        def screenshot_png(self):
            return b"not an image"
    s, _, _ = make_session(tmp_path, browser=Bad(site()), config=AdapterConfig(allowed_hosts=HOSTS, allow_screenshots=True))
    open_home(s)
    assert s.perform(act(1, "screenshot")).status is Status.ERROR


# ---------------------------------------------------------------------------------------------- faults and retries
def test_a_stale_element_is_retried_and_then_succeeds(tmp_path):
    s, _, _ = make_session(tmp_path)
    open_home(s)
    r = s.perform(act(1, "read", "id=flaky"))
    assert r.status is Status.PASS and r.attempts == 2


def test_an_element_that_stays_stale_ends_at_the_retry_limit(tmp_path):
    s, _, _ = make_session(tmp_path)
    open_home(s)
    r = s.perform(act(1, "read", "id=always-stale"))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.RETRY_LIMIT and r.attempts == 3


def test_a_hidden_element_is_not_interactable_and_retried_to_the_limit(tmp_path):
    s, _, _ = make_session(tmp_path)
    open_home(s)
    r = s.perform(act(1, "click", "id=hidden"))
    assert r.error_code is ErrorCode.RETRY_LIMIT


def test_a_missing_element_is_not_retried(tmp_path):
    s, _, _ = make_session(tmp_path)
    open_home(s)
    r = s.perform(act(1, "click", "id=nope"))
    assert r.status is Status.ERROR and r.attempts == 1 and "NOT_FOUND" in r.error_message


def test_a_browser_crash_is_an_adapter_crash_without_the_driver_text(tmp_path):
    s, _, _ = make_session(tmp_path, browser=FakeBrowser(site(), crash_on="click"))
    open_home(s)
    r = s.perform(act(1, "click", "testid=submit"))
    assert r.error_code is ErrorCode.ADAPTER_CRASH and r.attempts == 1


def test_a_missing_browser_is_unavailable_never_a_pass_or_a_skip(tmp_path):
    s, _, _ = make_session(tmp_path, factory=lambda: FakeBrowser(unavailable=True))
    r = s.perform(act(0, "open", HOME))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.UNAVAILABLE


def test_an_import_failure_in_the_factory_is_a_classified_error(tmp_path):
    def factory():
        raise ModuleNotFoundError("no selenium")
    s, _, _ = make_session(tmp_path, factory=factory)
    assert s.perform(act(0, "open", HOME)).status is Status.ERROR


def test_a_page_load_timeout_is_a_non_retryable_error(tmp_path):
    s, _, _ = make_session(tmp_path)
    r = s.perform(act(0, "open", "http://app.test:8080/missing"))
    assert r.status is Status.ERROR and r.attempts == 1 and "TIMEOUT" in r.error_message


def test_close_and_abort_quit_the_browser(tmp_path):
    s, adapter, holder = make_session(tmp_path)
    open_home(s)
    s.close()
    assert holder["browser"].quit_called
    s2, adapter2, holder2 = make_session(tmp_path / "b")
    open_home(s2)
    adapter2.abort()
    assert holder2["browser"].quit_called


def test_the_step_limit_applies(tmp_path):
    s, _, _ = make_session(tmp_path, limits=Limits(deadline_s=30, max_steps=2, max_retries=1))
    open_home(s)
    assert s.perform(act(1, "read", "id=title")).status is Status.PASS
    assert s.perform(act(2, "read", "id=title")).error_code is ErrorCode.STEP_LIMIT


def test_the_driver_is_created_lazily_and_once(tmp_path):
    calls = []

    def factory():
        calls.append(1)
        return FakeBrowser(site())
    s, _, _ = make_session(tmp_path, factory=factory)
    assert calls == []
    open_home(s)
    s.perform(act(1, "read", "id=title"))
    assert calls == [1]
