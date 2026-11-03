# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Starting the browser has a budget of its own, and a start that an action timeout abandoned does not leave a browser running.

A slow factory stands in for a cold first start of ChromeDriver and Chrome. Delays are fractions of a second; nothing here needs Selenium."""
import time

import pytest

from sel_support import HOSTS, act, make_session
from qa_adapter_kit import AdapterFault, AdapterUnavailable, ErrorCode, Status
from qa_selenium import AdapterConfig, DriverFault, FaultKind
from qa_selenium.testing.fake import FakeBrowser, site

HOME = "http://app.test:8080/"


def slow_factory(delay, made, *, fail=None):
    def factory():
        time.sleep(delay)
        if fail is not None:
            raise fail
        made.append(FakeBrowser(site()))
        return made[-1]
    return factory


def config(launch):
    return AdapterConfig(allowed_hosts=HOSTS, launch_timeout_s=launch)


def eventually(check, within=3.0):
    end = time.monotonic() + within
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.02)
    return check()


def test_the_default_launch_budget_is_generous_and_documented():
    assert AdapterConfig().launch_timeout_s == 60.0
    assert "launch_timeout_s" in (__import__("qa_selenium").SeleniumInteractiveAdapter.__doc__ or "")


def test_a_start_that_takes_longer_than_an_action_timeout_is_not_charged_to_the_first_action(tmp_path):
    made = []
    s, adapter, _ = make_session(tmp_path, factory=slow_factory(0.8, made), config=config(5))
    began = time.monotonic()
    adapter.start()
    assert time.monotonic() - began >= 0.7 and len(made) == 1          # the start took its own time
    r = s.perform(act(0, "open", HOME, timeout_s=0.3))                 # shorter than the start took
    assert r.status is Status.PASS, (r.error_code, r.error_message, r.duration_s)
    assert s.perform(act(1, "read", "id=title", timeout_s=0.3)).status is Status.PASS and len(made) == 1


def test_start_is_idempotent_and_the_factory_runs_once(tmp_path):
    made = []
    _, adapter, _ = make_session(tmp_path, factory=slow_factory(0.05, made), config=config(5))
    adapter.start()
    adapter.start()
    assert len(made) == 1 and adapter._driver is made[0]


def test_a_start_over_the_launch_budget_is_a_timeout_fault_and_the_late_browser_is_quit(tmp_path):
    made = []
    _, adapter, _ = make_session(tmp_path, factory=slow_factory(0.8, made), config=config(0.2))
    began = time.monotonic()
    with pytest.raises(AdapterFault) as info:
        adapter.start()
    assert info.value.code is ErrorCode.TIMEOUT and not info.value.retryable and time.monotonic() - began < 0.7
    assert adapter._driver is None
    assert eventually(lambda: made and made[0].quit_called), "the browser that finished starting after the budget must be quit"
    assert adapter._driver is None


def test_an_action_timeout_during_the_start_leaves_no_browser_behind(tmp_path):
    made = []
    s, adapter, _ = make_session(tmp_path, factory=slow_factory(0.8, made), config=config(5))
    r = s.perform(act(0, "open", HOME, timeout_s=0.2))                 # the start is charged to this action and does not fit
    assert r.status is Status.ERROR and r.error_code is ErrorCode.TIMEOUT
    assert eventually(lambda: made and made[0].quit_called), "the abandoned start must not leave a running browser"
    assert adapter._driver is None


def test_close_cancels_a_start_that_has_not_finished(tmp_path):
    made = []
    _, adapter, _ = make_session(tmp_path, factory=slow_factory(0.6, made), config=config(5))
    errors = []

    def starter():
        try:
            adapter.start()
        except AdapterFault as exc:
            errors.append(exc)
    import threading
    t = threading.Thread(target=starter)
    t.start()
    time.sleep(0.1)
    adapter.close()                                                    # while the factory is still running
    t.join(5)
    assert errors and errors[0].code is ErrorCode.INVALID_REQUEST
    assert eventually(lambda: made and made[0].quit_called) and adapter._driver is None


def test_a_driver_that_is_not_available_is_still_unavailable_through_start_and_through_an_action(tmp_path):
    _, adapter, _ = make_session(tmp_path, factory=slow_factory(0.05, [], fail=DriverFault(FaultKind.UNAVAILABLE)), config=config(5))
    with pytest.raises(AdapterUnavailable):
        adapter.start()
    s, _, _ = make_session(tmp_path / "b", factory=slow_factory(0.05, [], fail=DriverFault(FaultKind.UNAVAILABLE)), config=config(5))
    r = s.perform(act(0, "open", HOME))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.UNAVAILABLE


def test_a_timed_out_start_is_not_retried(tmp_path):
    made = []
    s, adapter, _ = make_session(tmp_path, factory=slow_factory(0.6, made), config=config(0.15))
    r = s.perform(act(0, "open", HOME, timeout_s=5))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.TIMEOUT and r.attempts == 1
    time.sleep(0.8)
    assert len(made) == 1                                              # one start, never a second
