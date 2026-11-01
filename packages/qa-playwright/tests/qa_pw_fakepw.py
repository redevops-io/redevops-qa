# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A fake ``playwright.sync_api`` module that reproduces the two rules of the real sync API that matter for thread ownership:

* ``sync_playwright().start()`` refuses, with the real error text, on a thread that has a running asyncio loop;
* every object belongs to the thread that started Playwright: a call from any other thread fails (the real API fails with a
  greenlet error).

Every call is recorded with the thread it ran on, so a test can prove all of them ran on one thread that is not the caller's."""
from __future__ import annotations

import asyncio
import threading
from typing import Any, Dict, List, Optional, Tuple

LOOP_MESSAGE = "It looks like you are using Playwright Sync API inside the asyncio loop. Please use the Async API instead."


class Error(Exception):
    """Named like Playwright's own ``Error``."""


class World:
    def __init__(self) -> None:
        self.calls: List[Tuple[str, int]] = []
        self.home_thread: Optional[int] = None
        self.block_goto: Optional[threading.Event] = None
        self.fail_start: Optional[BaseException] = None
        self.fail_launch: Optional[BaseException] = None
        self.die_on_goto: Optional[BaseException] = None
        self.stopped = False
        self.browsers_closed = 0
        self.contexts_closed = 0
        self.cdp_sessions: List[CdpSession] = []

    def touch(self, name: str) -> None:
        ident = threading.get_ident()
        self.calls.append((name, ident))
        if self.home_thread is not None and ident != self.home_thread:
            raise Error("greenlet.error: Cannot switch to a different thread")

    def threads(self) -> set:
        return {ident for _, ident in self.calls}


class _Obj:
    def __init__(self, world: World) -> None:
        self._world = world


class Tracing(_Obj):
    def start(self, **kw: Any) -> None:
        self._world.touch("tracing.start")

    def stop(self, **kw: Any) -> None:
        self._world.touch("tracing.stop")


class Locator(_Obj):
    def aria_snapshot(self, **kw: Any) -> str:
        self._world.touch("aria_snapshot")
        return '- heading "Welcome"'


class CdpSession(_Obj):
    """A DevTools session: records ``send`` calls and keeps the ``Fetch.requestPaused`` handler so a test can fire events."""

    def __init__(self, world: World) -> None:
        super().__init__(world)
        self.handlers: Dict[str, Any] = {}
        self.sent: List[Tuple[str, Dict[str, Any]]] = []

    def on(self, event: str, handler: Any) -> None:
        self._world.touch("cdp.on")
        self.handlers[event] = handler

    def send(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._world.touch("cdp.send")
        self.sent.append((method, dict(params or {})))
        return {}


class Page(_Obj):
    def __init__(self, world: World) -> None:
        super().__init__(world)
        self.url = "about:blank"
        self.handlers: Dict[str, Any] = {}

    def on(self, event: str, handler: Any) -> None:
        self._world.touch("page.on")
        self.handlers[event] = handler

    def goto(self, url: str, timeout: int = 0, wait_until: str = "load") -> None:
        self._world.touch("goto")
        if self._world.die_on_goto is not None:
            raise self._world.die_on_goto
        if self._world.block_goto is not None:
            self._world.block_goto.wait(30)
        self.url = url
        return None

    def wait_for_timeout(self, ms: int) -> None:
        self._world.touch("wait_for_timeout")

    def evaluate(self, script: str, *args: Any) -> Any:
        self._world.touch("evaluate")
        return {"title": "Home", "lang": "en", "ready": "complete", "elements": 3, "links": 0, "forms": 0, "inputs": 0}

    def locator(self, selector: str) -> Locator:
        self._world.touch("locator")
        return Locator(self._world)

    def screenshot(self, **kw: Any) -> bytes:
        self._world.touch("screenshot")
        return b"\x89PNG\r\n\x1a\n" + b"fake"

    def is_closed(self) -> bool:
        return False

    def close(self) -> None:
        self._world.touch("page.close")


class Context(_Obj):
    def __init__(self, world: World) -> None:
        super().__init__(world)
        self.tracing = Tracing(world)
        self.pages: List[Page] = []

    def set_default_timeout(self, ms: int) -> None:
        self._world.touch("set_default_timeout")

    def route(self, pattern: str, handler: Any) -> None:
        self._world.touch("route")

    def route_web_socket(self, pattern: str, handler: Any) -> None:
        self._world.touch("route_web_socket")

    def new_cdp_session(self, page: Any) -> CdpSession:
        self._world.touch("new_cdp_session")
        session = CdpSession(self._world)
        self._world.cdp_sessions.append(session)
        return session

    def new_page(self) -> Page:
        self._world.touch("new_page")
        page = Page(self._world)
        self.pages.append(page)
        return page

    def on(self, event: str, handler: Any) -> None:
        self._world.touch("context.on")

    def close(self) -> None:
        self._world.touch("context.close")
        self._world.contexts_closed += 1


class Browser(_Obj):
    version = "fake-1.0"

    def is_connected(self) -> bool:
        self._world.touch("is_connected")
        return True

    def new_context(self, **kw: Any) -> Context:
        self._world.touch("new_context")
        return Context(self._world)

    def close(self) -> None:
        self._world.touch("browser.close")
        self._world.browsers_closed += 1


class Chromium(_Obj):
    def launch(self, **kw: Any) -> Browser:
        self._world.touch("launch")
        if self._world.fail_launch is not None:
            raise self._world.fail_launch
        return Browser(self._world)


class Playwright(_Obj):
    def __init__(self, world: World) -> None:
        super().__init__(world)
        self.chromium = Chromium(world)


class Manager(_Obj):
    def start(self) -> Playwright:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise Error(LOOP_MESSAGE)
        if self._world.fail_start is not None:
            raise self._world.fail_start
        self._world.home_thread = threading.get_ident()
        self._world.touch("start")
        return Playwright(self._world)

    def stop(self) -> None:
        self._world.touch("stop")
        self._world.stopped = True


class FakeSyncApi:
    """Stands in for the module ``playwright.sync_api``."""

    def __init__(self, world: Optional[World] = None) -> None:
        self.world = world if world is not None else World()

    def sync_playwright(self) -> Manager:
        return Manager(self.world)
