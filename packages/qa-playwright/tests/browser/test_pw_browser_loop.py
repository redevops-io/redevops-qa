# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The real driver owns its Playwright objects on a worker thread, so it works from a thread that already runs an asyncio loop.

Playwright's sync API refuses to start on such a thread; these tests start the driver inside a running loop, from a plain
thread, and with the egress gateway's own loop alive in the same process, against a real Chromium.

NOT RUN in the environment this file was written in (no Playwright package, no browser). It runs in the browser CI job only.
"""
import asyncio
import threading

import pytest
from agent_harness.qa.records import ObserveRequest, Phase

from test_pw_browser_driver import build, goto

pytestmark = pytest.mark.browser


def _title_of(adapter, handle):
    return dict(adapter.observe(handle, ObserveRequest(phase=Phase.AFTER, step_id="s")).dom_meta)["title"]


def test_the_driver_starts_and_works_inside_a_running_asyncio_loop(playwright_available, fixture_server):
    async def inside():
        asyncio.get_running_loop()                     # a loop is running on this thread: the sync API would refuse here
        adapter, handle = build(fixture_server)
        try:
            goto(adapter, handle, fixture_server, "/home")
            return _title_of(adapter, handle)
        finally:
            adapter.shutdown()
    assert asyncio.run(inside()) == "Home"


def test_the_driver_works_from_a_plain_thread_and_a_second_driver_from_the_main_thread(playwright_available, fixture_server):
    out = {}

    def run():
        adapter, handle = build(fixture_server)
        try:
            goto(adapter, handle, fixture_server, "/home")
            out["title"] = _title_of(adapter, handle)
        finally:
            adapter.shutdown()
    thread = threading.Thread(target=run)
    thread.start()
    thread.join(60)
    assert out == {"title": "Home"}
    adapter, handle = build(fixture_server)
    try:
        goto(adapter, handle, fixture_server, "/home")
        assert _title_of(adapter, handle) == "Home"
    finally:
        adapter.shutdown()


def test_closing_the_driver_ends_its_worker_thread_and_nothing_is_left_behind(playwright_available, fixture_server):
    adapter, handle = build(fixture_server)
    goto(adapter, handle, fixture_server, "/home")
    assert [t for t in threading.enumerate() if t.name == "qa-playwright-worker"]
    adapter.shutdown()
    assert not [t for t in threading.enumerate() if t.name == "qa-playwright-worker"]
