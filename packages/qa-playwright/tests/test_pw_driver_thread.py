# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Thread ownership of the real driver, proved offline against a fake ``playwright.sync_api`` that has the real API's two rules:
it refuses to start on a thread with a running asyncio loop, and its objects belong to the thread that started it."""
import asyncio
import gc
import threading
import time

import pytest
from agent_harness.qa.blobs import MemoryBlobSink
from agent_harness.qa.egress import AllowEntry, EgressPolicy
from agent_harness.qa.records import (Action, ActionKind, ActionRequest, CaptureKind, ObserveRequest, Phase, SessionProfile)
from agent_harness.qa.redaction import PatternRedactor, RedactionConfig
from qa_playwright import (AdapterConfig, ContextSpec, DriverFault, DriverUnavailable, EgressProfile, FaultKind, PlaywrightAdapter,
                           PlaywrightDriver)
from qa_playwright.testing.fake import FakeClock

from qa_pw_fakepw import LOOP_MESSAGE, Error, FakeSyncApi, Manager, World

SPEC = ContextSpec(session_id="s1", profile_id="p")


BASE = [0]


def worker_threads():
    """Worker threads alive beyond those that were already alive when the test started."""
    alive = [t for t in threading.enumerate() if t.name == "qa-playwright-worker"]
    return alive[BASE[0]:]


@pytest.fixture(autouse=True)
def no_leaked_worker():
    gc.collect()                                       # drivers other tests dropped without close() end their threads here
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and [t for t in threading.enumerate() if t.name == "qa-playwright-worker"]:
        time.sleep(0.01)
    BASE[0] = len([t for t in threading.enumerate() if t.name == "qa-playwright-worker"])
    yield
    deadline = time.monotonic() + 3
    while worker_threads() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert worker_threads() == [], "a worker thread outlived its test"


def driver(world=None, **kw):
    api = FakeSyncApi(world)
    return PlaywrightDriver(module=api, **kw), api.world


# ---- the simulated guard is the real one's ---------------------------------------------------------------------------------
def test_the_fake_refuses_to_start_inside_a_running_loop_with_the_real_message_and_starts_outside_one():
    async def inside():
        with pytest.raises(Error) as err:
            FakeSyncApi().sync_playwright().start()
        assert str(err.value) == LOOP_MESSAGE
    asyncio.run(inside())


def test_the_fake_objects_belong_to_the_thread_that_started_playwright():
    api = FakeSyncApi()
    api.sync_playwright().start()                      # no loop on this thread: it starts, and owns the objects
    api.world.touch("same-thread")
    failures = []

    def other():
        try:
            api.world.touch("other-thread")
        except Error as exc:
            failures.append(exc)
    thread = threading.Thread(target=other)
    thread.start()
    thread.join()
    assert len(failures) == 1


# ---- start, from anywhere ----------------------------------------------------------------------------------------------------
def test_the_driver_starts_on_a_thread_that_runs_an_asyncio_loop():
    async def inside():
        asyncio.get_running_loop()                    # a loop IS running on this thread
        d, world = driver()
        try:
            s = d.new_session(SPEC)
            s.goto("http://app.test/", 1000)
            assert s.current_url() == "http://app.test/"
            s.close()
        finally:
            d.close()
        return world
    world = asyncio.run(inside())
    assert world.calls and threading.get_ident() not in world.threads() and len(world.threads()) == 1


def test_the_driver_starts_from_a_plain_thread_and_from_the_main_thread():
    out = {}

    def run():
        d, world = driver()
        out["worker"] = world.threads()
        out["me"] = threading.get_ident()
        d.close()
    t = threading.Thread(target=run)
    t.start()
    t.join(10)
    assert len(out["worker"]) == 1 and out["me"] not in out["worker"]
    d, world = driver()
    assert threading.get_ident() not in world.threads()
    d.close()


def test_every_call_of_a_whole_session_runs_on_the_one_worker_thread_never_on_the_callers():
    d, world = driver()
    s = d.new_session(ContextSpec(session_id="s1", profile_id="p", record_trace=False, request_gate=lambda info: True))
    s.goto("http://app.test/", 1000)
    s.settle(10)
    s.page_meta()
    s.accessibility_snapshot()
    s.screenshot()
    s.console_log()
    s.network_log()
    s.reset()
    s.goto("http://app.test/two", 1000)
    s.close()
    d.close()
    names = {n for n, _ in world.calls}
    assert {"start", "launch", "new_context", "new_page", "goto", "wait_for_timeout", "evaluate", "aria_snapshot", "screenshot",
            "context.close", "browser.close", "stop"} <= names
    assert len(world.threads()) == 1 and threading.get_ident() not in world.threads()


def test_calls_from_several_threads_and_from_inside_a_loop_are_all_serialised_onto_the_worker():
    d, world = driver()
    s = d.new_session(SPEC)
    errors = []

    def hit(i):
        try:
            s.goto(f"http://app.test/{i}", 1000)
            s.page_meta()
        except Exception as exc:                       # pragma: no cover - reported below
            errors.append(exc)
    threads = [threading.Thread(target=hit, args=(i,)) for i in range(8)]
    [t.start() for t in threads]
    [t.join(10) for t in threads]

    async def inside():
        s.goto("http://app.test/loop", 1000)
    asyncio.run(inside())
    assert errors == [] and len(world.threads()) == 1
    d.close()


def test_the_worker_starts_on_first_use_not_at_import_and_a_second_driver_gets_its_own():
    assert worker_threads() == []
    d1, w1 = driver()
    d2, w2 = driver()
    assert len(worker_threads()) == 2 and w1.home_thread != w2.home_thread
    d1.close()
    d2.close()


# ---- close, leak -------------------------------------------------------------------------------------------------------------
def test_close_tears_down_on_the_worker_joins_it_and_is_idempotent():
    d, world = driver()
    s = d.new_session(SPEC)
    s.close()
    d.close()
    assert world.stopped and world.browsers_closed == 1 and world.contexts_closed == 1
    assert worker_threads() == [] and not d.leaked_worker
    d.close()                                          # again: nothing happens, nothing raises
    assert {ident for n, ident in world.calls if n in ("browser.close", "stop")} == {world.home_thread}


def test_after_close_a_session_call_is_session_closed_and_a_new_session_is_driver_unavailable():
    d, world = driver()
    s = d.new_session(SPEC)
    d.close()
    with pytest.raises(DriverFault) as err:
        s.goto("http://app.test/", 1000)
    assert err.value.kind is FaultKind.SESSION_CLOSED
    assert s.is_closed()
    report = s.close()
    assert report.leaked == ("context", "page") and report.released == ()
    with pytest.raises(DriverUnavailable):
        d.new_session(SPEC)


def test_a_failed_start_is_driver_unavailable_without_text_and_leaves_no_thread():
    world = World()
    world.fail_start = RuntimeError("cannot find /secret/path/to/driver")
    with pytest.raises(DriverUnavailable) as err:
        PlaywrightDriver(module=FakeSyncApi(world))
    assert err.value.details == {"reason": "RuntimeError"} and "/secret" not in str(err.value) + repr(err.value.details)
    assert worker_threads() == []


def test_a_failed_launch_is_driver_unavailable_and_the_driver_stays_usable():
    world = World()
    d = PlaywrightDriver(module=FakeSyncApi(world))
    world.fail_launch = OSError("no browser at /nowhere")
    with pytest.raises(DriverUnavailable) as err:
        d.new_session(SPEC)
    assert "/nowhere" not in str(err.value) and err.value.details == {"reason": "OSError"}
    world.fail_launch = None
    d.new_session(SPEC).close()
    d.close()


def test_an_exception_from_inside_playwright_is_classified_and_its_text_dropped():
    world = World()
    d = PlaywrightDriver(module=FakeSyncApi(world))
    s = d.new_session(SPEC)
    world.die_on_goto = Error("Page crashed at /secret/dir")
    with pytest.raises(DriverFault) as err:
        s.goto("http://app.test/", 1000)
    assert err.value.kind is FaultKind.CRASHED and "/secret" not in str(err.value)
    world.die_on_goto = Error("odd failure /secret/dir")
    with pytest.raises(DriverFault) as err:
        s.goto("http://app.test/", 1000)
    assert err.value.kind is FaultKind.OTHER and str(err.value) == "OTHER"
    d.close()


# ---- timeouts and a dying worker -----------------------------------------------------------------------------------------------
def test_a_call_that_does_not_return_is_a_timeout_then_the_driver_is_crashed_and_close_still_returns():
    world = World()
    world.block_goto = threading.Event()
    d = PlaywrightDriver(module=FakeSyncApi(world), slack_s=0.2, join_timeout_s=0.3, call_timeout_s=0.5)
    s = d.new_session(SPEC)
    started = time.monotonic()
    with pytest.raises(DriverFault) as err:
        s.goto("http://app.test/", 100)                 # 100 ms + 0.2 s of slack
    assert err.value.kind is FaultKind.TIMEOUT and time.monotonic() - started < 3
    with pytest.raises(DriverFault) as err2:
        s.page_meta()                                   # a wedged worker is never asked again: it fails at once
    assert err2.value.kind is FaultKind.CRASHED
    assert s.is_closed()
    started = time.monotonic()
    d.close()
    assert time.monotonic() - started < 3 and d.leaked_worker
    world.block_goto.set()                              # let the stuck call finish so the thread can end
    deadline = time.monotonic() + 3
    while worker_threads() and time.monotonic() < deadline:
        time.sleep(0.01)


def test_a_worker_that_dies_fails_every_later_and_queued_call_as_crashed():
    world = World()
    d = PlaywrightDriver(module=FakeSyncApi(world))
    s = d.new_session(SPEC)
    world.die_on_goto = SystemExit()
    with pytest.raises(DriverFault) as err:
        s.goto("http://app.test/", 1000)
    assert err.value.kind is FaultKind.CRASHED
    deadline = time.monotonic() + 3
    while worker_threads() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert worker_threads() == []
    with pytest.raises(DriverFault) as err2:
        s.current_url()
    assert err2.value.kind is FaultKind.CRASHED and s.is_closed()
    assert s.close().leaked == ("context", "page")
    with pytest.raises(DriverUnavailable):
        d.new_session(SPEC)
    d.close()


def test_a_call_made_from_the_worker_itself_runs_inline_and_cannot_deadlock():
    d, world = driver()
    seen = []
    d._worker.call(lambda: seen.append(d._worker.call(lambda: threading.get_ident(), timeout_s=1)), timeout_s=2)
    assert seen == [world.home_thread]
    d.close()


# ---- the adapter over the real driver (fake module) ------------------------------------------------------------------------------
def test_the_adapter_runs_a_session_over_the_threaded_driver_from_inside_a_running_loop():
    clock = FakeClock()
    redactor = PatternRedactor(RedactionConfig(acknowledged_unredacted_media=("image/png",)))
    entry = AllowEntry.parse("http://app.test:80")
    from agent_harness.qa.egress import StaticResolver
    profile = EgressProfile("p", EgressPolicy(entries=entry), StaticResolver({"app.test": ["93.184.216.34"]}))

    async def inside():
        asyncio.get_running_loop()
        d, world = driver()
        adapter = PlaywrightAdapter(d, blobs=MemoryBlobSink(), redactor=redactor, clock=clock, egress_profiles={"p": profile},
                                    config=AdapterConfig())
        h = adapter.open_session(SessionProfile(egress_profile="p", redaction_policy_id=redactor.policy_id))
        adapter.act(h, ActionRequest(action=Action(kind=ActionKind.NAVIGATE, value="http://app.test/x"), idempotency_key="k",
                                     policy_decision_ref="rcv1:" + "ab" * 32, step_id="s"), None)
        obs = adapter.observe(h, ObserveRequest(phase=Phase.AFTER, step_id="s"))
        report = adapter.close_session(h)
        adapter.shutdown()
        return world, obs, report
    world, obs, report = asyncio.run(inside())
    assert obs.url == "http://app.test/x" and dict(obs.dom_meta)["title"] == "Home" and report.verified
    assert len(world.threads()) == 1 and threading.get_ident() not in world.threads() and worker_threads() == []


def test_a_driver_dropped_without_close_still_ends_its_worker_thread():
    d, world = driver()
    assert len(worker_threads()) == 1
    del d
    gc.collect()
    deadline = time.monotonic() + 3
    while worker_threads() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert worker_threads() == []
