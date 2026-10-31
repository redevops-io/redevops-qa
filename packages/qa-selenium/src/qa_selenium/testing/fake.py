# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A deterministic fake ``BrowserDriver``: pages with elements, redirects, stale and covered elements, a crash and an unavailable
browser, scripted per test. No Selenium, no browser and no network."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from ..driver import DriverFault, FaultKind
from ..locators import Locator

PNG = b"\x89PNG\r\n\x1a\n" + b"fake-image-bytes"


@dataclass
class FakeElement:
    text: str = ""
    visible: bool = True
    enabled: bool = True
    stale_reads: int = 0              # the next N uses raise STALE, then succeed
    on_click: Optional[str] = None    # a URL to navigate to when clicked
    value: str = ""


@dataclass
class FakePage:
    elements: Dict[str, FakeElement] = field(default_factory=dict)        # key: the locator's css() form
    redirect_to: Optional[str] = None


class FakeBrowser:
    def __init__(self, pages: Optional[Dict[str, FakePage]] = None, *, crash_on: Optional[str] = None, unavailable: bool = False):
        self.pages = pages or {}
        self.url = "about:blank"
        self.log: List[str] = []
        self.quit_called = False
        self.crash_on = crash_on
        if unavailable:
            raise DriverFault(FaultKind.UNAVAILABLE)

    def _maybe_crash(self, op: str) -> None:
        if self.crash_on == op:
            raise DriverFault(FaultKind.CRASH)

    def open(self, url: str, timeout_s: float) -> None:
        self._maybe_crash("open")
        self.log.append(f"open {url}")
        if url == "about:blank":
            self.url = url
            return
        page = self.pages.get(url)
        if page is None:
            raise DriverFault(FaultKind.TIMEOUT)
        self.url = page.redirect_to or url

    def current_url(self) -> str:
        return self.url

    def _element(self, locator: Locator) -> FakeElement:
        page = self.pages.get(self.url)
        el = page.elements.get(locator.css()) if page else None
        if el is None:
            raise DriverFault(FaultKind.NOT_FOUND)
        if el.stale_reads > 0:
            el.stale_reads -= 1
            raise DriverFault(FaultKind.STALE)
        return el

    def click(self, locator: Locator, timeout_s: float) -> None:
        self._maybe_crash("click")
        el = self._element(locator)
        if not el.visible or not el.enabled:
            raise DriverFault(FaultKind.NOT_INTERACTABLE)
        self.log.append(f"click {locator}")
        if el.on_click:
            self.open(el.on_click, timeout_s)

    def type_text(self, locator: Locator, text: str, timeout_s: float) -> None:
        el = self._element(locator)
        if not el.visible or not el.enabled:
            raise DriverFault(FaultKind.NOT_INTERACTABLE)
        el.value = text
        self.log.append(f"type {locator} <{len(text)} characters>")

    def read_text(self, locator: Locator, timeout_s: float) -> str:
        el = self._element(locator)
        return el.value or el.text

    def screenshot_png(self) -> bytes:
        return PNG

    def quit(self) -> None:
        self.quit_called = True


def site() -> Dict[str, FakePage]:
    """A tiny two-page site on the host the tests allow."""
    home = "http://app.test:8080/"
    done = "http://app.test:8080/done"
    return {
        home: FakePage({
            '[id="title"]': FakeElement(text="Welcome   home"),
            '[name="user"]': FakeElement(),
            '[data-testid="submit"]': FakeElement(text="Go", on_click=done),
            '[id="hidden"]': FakeElement(text="x", visible=False),
            '[id="flaky"]': FakeElement(text="eventually", stale_reads=1),
            '[id="always-stale"]': FakeElement(text="never", stale_reads=100),
        }),
        done: FakePage({'[id="result"]': FakeElement(text="Done")}),
        "http://app.test:8080/jump": FakePage({}, redirect_to="http://evil.test/landing"),
        "http://evil.test/landing": FakePage({'[id="x"]': FakeElement(text="not on the allowlist")}),
    }
