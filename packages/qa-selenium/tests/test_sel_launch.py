# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Starting the browser has a budget of its own, and a start that an action timeout abandoned does not leave a browser running.

A slow factory stands in for a cold first start of ChromeDriver and Chrome. Delays are fractions of a second; nothing here needs Selenium."""
import threading
import time

import pytest

from sel_support import HOSTS, act, make_session
from qa_adapter_kit import AdapterFault, AdapterUnavailable, ErrorCode, Status
import qa_selenium.adapter as adapter_module
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


# ---------------------------------------------------------------------------------------------- the state after a timed-out start
def test_a_start_that_returns_in_the_instant_the_budget_runs_out_counts_as_a_success_and_its_browser_is_kept(tmp_path, monkeypatch):
    class SlowSet(threading.Event):
        def set(self):                    # widens the window between "the browser is stored" and "the launch is signalled done"
            time.sleep(0.3)
            super().set()
    original = adapter_module._Launch.__init__

    def init(self):
        original(self)
        self.done = SlowSet()
    monkeypatch.setattr(adapter_module._Launch, "__init__", init)
    made = []
    _, adapter, _ = make_session(tmp_path, factory=slow_factory(0, made), config=config(0.1))
    adapter.start()                                                    # no TIMEOUT: the browser was already stored when the budget ran out
    assert len(made) == 1 and adapter._driver is made[0] and not made[0].quit_called
    adapter.start()
    assert len(made) == 1                                              # and a second start() is the no-op it always was
    adapter.close()
    assert made[0].quit_called


def test_after_a_timed_out_start_the_adapter_is_terminal_until_close(tmp_path):
    made = []
    _, adapter, _ = make_session(tmp_path, factory=slow_factory(0.5, made), config=config(0.1))
    with pytest.raises(AdapterFault) as first:
        adapter.start()
    assert first.value.code is ErrorCode.TIMEOUT
    with pytest.raises(AdapterFault) as second:                        # no second browser, and no success while the first one is still starting
        adapter.start()
    assert second.value.code is ErrorCode.TIMEOUT and "close()" in str(second.value)
    assert eventually(lambda: made and made[0].quit_called)
    with pytest.raises(AdapterFault):                                  # still terminal after the late browser was quit
        adapter.start()
    assert len(made) == 1 and adapter._driver is None
    adapter.close()                                                    # close() makes it usable again
    adapter._factory = slow_factory(0, made)
    adapter.start()
    assert len(made) == 2 and adapter._driver is made[1]


def test_a_launch_budget_timeout_in_the_lazy_path_starts_no_second_browser_for_the_next_action(tmp_path):
    made = []
    s, adapter, _ = make_session(tmp_path, factory=slow_factory(0.5, made), config=config(0.1))
    first = s.perform(act(0, "open", HOME, timeout_s=5))
    assert first.status is Status.ERROR and first.error_code is ErrorCode.TIMEOUT
    second = s.perform(act(1, "open", HOME, timeout_s=5))
    assert second.status is Status.ERROR and second.error_code is ErrorCode.TIMEOUT
    assert eventually(lambda: made and made[0].quit_called)
    time.sleep(0.7)                                                    # longer than a second start would take: a second browser would exist by now
    assert len(made) == 1 and adapter._driver is None
    s.close()


# ---------------------------------------------------------------------------------------------- concurrency, close, threads, factory exceptions
def test_concurrent_starts_make_one_browser(tmp_path):
    made = []
    _, adapter, _ = make_session(tmp_path, factory=slow_factory(0.3, made), config=config(5))
    errors = []

    def starter():
        try:
            adapter.start()
        except BaseException as exc:      # noqa: BLE001
            errors.append(exc)
    threads = [threading.Thread(target=starter) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    assert not errors and len(made) == 1 and adapter._driver is made[0]


def test_start_after_close_starts_a_new_browser(tmp_path):
    made = []
    _, adapter, _ = make_session(tmp_path, factory=slow_factory(0.05, made), config=config(5))
    adapter.start()
    adapter.close()
    assert made[0].quit_called and adapter._driver is None
    adapter.start()
    assert len(made) == 2 and adapter._driver is made[1] and not made[1].quit_called


def test_the_launch_runs_on_a_daemon_thread_so_a_hung_start_cannot_keep_the_process_alive(tmp_path):
    seen = []

    def factory():
        seen.append((threading.current_thread().daemon, threading.current_thread() is threading.main_thread()))
        return FakeBrowser(site())
    _, adapter, _ = make_session(tmp_path, factory=factory, config=config(5))
    adapter.start()
    assert seen == [(True, False)]


def test_a_factory_raising_adapter_unavailable_is_unavailable_and_the_next_start_is_tried_again(tmp_path):
    calls = []

    def factory():
        calls.append(1)
        if len(calls) == 1:
            raise AdapterUnavailable("no browser on this worker")
        return FakeBrowser(site())
    _, adapter, _ = make_session(tmp_path, factory=factory, config=config(5))
    with pytest.raises(AdapterUnavailable):
        adapter.start()
    adapter.start()
    assert len(calls) == 2 and adapter._driver is not None
    s, _, _ = make_session(tmp_path / "b", factory=lambda: (_ for _ in ()).throw(AdapterUnavailable("no browser")), config=config(5))
    r = s.perform(act(0, "open", HOME))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.UNAVAILABLE


@pytest.mark.parametrize("exc_type", [KeyboardInterrupt, SystemExit])
def test_a_factory_raising_a_base_exception_propagates_it_unchanged_and_leaves_the_adapter_usable(tmp_path, exc_type):
    calls = []

    def factory():
        calls.append(1)
        if len(calls) == 1:
            raise exc_type()
        return FakeBrowser(site())
    _, adapter, _ = make_session(tmp_path, factory=factory, config=config(5))
    with pytest.raises(exc_type):                                      # not reported as an adapter crash
        adapter.start()
    adapter.start()
    assert len(calls) == 2 and adapter._driver is not None


def test_a_start_after_a_close_that_came_while_a_browser_was_starting_starts_a_new_one(tmp_path):
    made = []
    _, adapter, _ = make_session(tmp_path, factory=slow_factory(0.5, made), config=config(5))
    first = threading.Thread(target=lambda: _swallow(adapter.start))
    first.start()
    time.sleep(0.1)
    adapter.close()                                                    # the first start is still running its factory
    adapter.start()                                                    # must not wait on the cancelled start: a new browser
    first.join(5)
    assert eventually(lambda: len(made) == 2 and made[0].quit_called)
    assert adapter._driver is made[1] and not made[1].quit_called


def _swallow(fn):
    try:
        fn()
    except Exception:
        pass


def test_a_waiter_left_behind_by_close_does_not_re_arm_the_terminal_state(tmp_path):
    made = []
    delays = [0.8, 0.0]                                                # the first start is slow, the next one is fast

    def factory():
        time.sleep(delays.pop(0))
        made.append(FakeBrowser(site()))
        return made[-1]
    _, adapter, _ = make_session(tmp_path, factory=factory, config=config(0.3))
    outcome = []

    def starter():
        try:
            adapter.start()
            outcome.append("started")
        except AdapterFault as exc:
            outcome.append(exc.code)
    t = threading.Thread(target=starter)
    t.start()
    time.sleep(0.1)
    adapter.close()                                                    # while the start is running; the waiter's budget (0.3 s) runs out afterwards
    t.join(5)
    assert outcome == [ErrorCode.INVALID_REQUEST]                      # "closed while starting", not a timeout
    adapter.start()                                                    # the adapter was closed: a fresh start works, no second close() needed
    held = adapter._driver
    assert held is not None and not held.quit_called
    assert eventually(lambda: len(made) == 2)                          # the abandoned slow start finishes later and is quit, the held browser is not
    late = next(b for b in made if b is not held)
    assert eventually(lambda: late.quit_called) and not held.quit_called
    adapter.close()


def test_two_callers_waiting_on_the_same_too_slow_start_both_get_a_timeout(tmp_path):
    made = []
    _, adapter, _ = make_session(tmp_path, factory=slow_factory(0.8, made), config=config(0.2))
    codes = []
    lock = threading.Lock()

    def starter(delay):
        time.sleep(delay)
        try:
            adapter.start()
        except AdapterFault as exc:
            with lock:
                codes.append(exc.code)
    first, second = threading.Thread(target=starter, args=(0,)), threading.Thread(target=starter, args=(0.05,))
    first.start()
    second.start()
    first.join(5)
    second.join(5)
    assert codes == [ErrorCode.TIMEOUT, ErrorCode.TIMEOUT]             # nobody closed the adapter: neither caller may be told it was closed
    assert eventually(lambda: len(made) == 1 and made[0].quit_called) and adapter._driver is None
