# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A deterministic fake :class:`~qa_playwright.driver.BrowserDriver`, for the offline tests (and for any other package that
needs a scripted browser).

It models what the adapter has to cope with: pages with roles, accessible names, labels and test ids; visibility and
enabled state that change with time; ambiguity (several matches); overlays that cover a target until a time; a stale
element after a re-render; a session that is lost or crashes; slow actions; a fixture that changed under the test; a
request gate that sees every navigation, redirect hop and subresource; console and network logs; per-context storage that a
new context never sees. Time is a :class:`FakeClock` that only moves when the driver "waits" (``settle``) or an action takes
time, so every run is the same run.

Page text in this module is test data. The fake never evaluates anything.
"""
from __future__ import annotations

import copy
import hashlib
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence, Tuple

from ..driver import (CloseReport, ConsoleEvent, ContextSpec, DriverFault, ElementInfo, ElementQuery, ElementReading,
                      EventLog, FaultKind, NetworkEvent, PageMeta, RequestInfo)
from ..errors import DriverUnavailable

PNG_HEADER = b"\x89PNG\r\n\x1a\n"
MAX_REDIRECTS = 10


class FakeClock:
    """A ``Clock`` whose time moves only when told to."""

    def __init__(self, start_ms: int = 1_000) -> None:
        self.ms = start_ms
        self.utc = "2026-01-01T00:00:00Z"

    def now_utc(self) -> str:
        return self.utc

    def monotonic_ms(self) -> int:
        return self.ms

    def advance(self, ms: int) -> None:
        self.ms += max(0, ms)


@dataclass
class FakeElement:
    role: str
    name: str
    label: Optional[str] = None
    test_id: Optional[str] = None
    text: str = ""
    value: Optional[str] = None
    kind: str = "text"                 # "text", "input", "checkbox", "select"
    checked: bool = False
    frame: Tuple[str, ...] = ()
    visible_after_ms: int = 0          # visible this long after the page loaded
    hidden_after_ms: Optional[int] = None
    enabled_after_ms: int = 0
    covered_until_ms: Optional[int] = None
    covered_by: str = "dialog"
    sensitive: bool = False
    editable: bool = True
    on_click: Optional[Callable[["FakeSession", "FakeElement"], None]] = None
    key: str = ""


@dataclass
class FakePage:
    url: str
    title: str = ""
    lang: str = "en"
    elements: List[FakeElement] = field(default_factory=list)
    subresources: List[Tuple[str, str]] = field(default_factory=list)       # (url, resource_type) fetched on load
    console: List[Tuple[str, str]] = field(default_factory=list)            # (level, text) logged on load
    status: int = 200
    extra_a11y: str = ""


class FakeSite:
    """The world the fake browser can reach: pages by URL, redirects, and a fixture version."""

    def __init__(self) -> None:
        self.pages: Dict[str, FakePage] = {}
        self.redirects: Dict[str, str] = {}
        self.fixture_version = 1
        self.fixture_resets = 0

    def add(self, page: FakePage) -> FakePage:
        for i, el in enumerate(page.elements):
            if not el.key:
                el.key = f"{page.url}#{i}"
        self.pages[page.url] = page
        return page

    def reset_fixture(self, scope: str = "FIXTURE") -> bool:
        self.fixture_version = 1
        self.fixture_resets += 1
        return True


class FakeSession:
    def __init__(self, driver: "FakeBrowserDriver", spec: ContextSpec) -> None:
        self.driver = driver
        self.spec = spec
        self.clock = driver.clock
        self.closed = False
        self.crashed = False
        self.generation = 1
        self.page: FakePage = FakePage(url="about:blank")
        self.loaded_at = self.clock.ms
        self.local_storage: Dict[str, str] = {}
        self.cookies: Dict[str, str] = {}
        self.typed: List[str] = []
        self.console: Deque[ConsoleEvent] = deque(maxlen=spec.max_console_events)
        self.network: Deque[NetworkEvent] = deque(maxlen=spec.max_network_events)
        self.dropped = {"console": 0, "network": 0}
        self.fail_next: Optional[DriverFault] = None
        self.action_delay_ms = 0
        self.trace_exports = 0

    # -- helpers -----------------------------------------------------------------------------------------------
    def _live(self) -> None:
        self.driver.calls.append("live")
        if self.closed:
            raise DriverFault(FaultKind.SESSION_CLOSED)
        if self.crashed:
            raise DriverFault(FaultKind.CRASHED)

    def _fault(self) -> None:
        if self.fail_next is not None:
            fault, self.fail_next = self.fail_next, None
            raise fault

    def _log(self, ring: Deque[Any], which: str, event: Any) -> None:
        if len(ring) == ring.maxlen:
            self.dropped[which] += 1
        ring.append(event)

    def age(self) -> int:
        return self.clock.ms - self.loaded_at

    def _gate(self, url: str, rtype: str, nav: bool) -> bool:
        gate = self.spec.request_gate
        return True if gate is None else bool(gate(RequestInfo(url=url, resource_type=rtype, is_navigation=nav)))

    def fire_request(self, url: str, resource_type: str = "fetch") -> bool:
        """What a page script doing a request would do: the request gate decides, the network log records."""
        self._live()
        allowed = self._gate(url, resource_type, False)
        self._log(self.network, "network", NetworkEvent(method="GET", url=url, resource_type=resource_type,
                                                        status=200 if allowed else None, blocked=not allowed))
        return allowed

    def _load(self, url: str) -> None:
        hops = 0
        while url in self.driver.site.redirects:
            hops += 1
            if hops > MAX_REDIRECTS:
                raise DriverFault(FaultKind.OTHER)
            nxt = self.driver.site.redirects[url]
            self._log(self.network, "network", NetworkEvent(method="GET", url=url, resource_type="document", status=302))
            if not self._gate(nxt, "document", True):
                self._log(self.network, "network", NetworkEvent(method="GET", url=nxt, resource_type="document", blocked=True))
                raise DriverFault(FaultKind.NAVIGATION_BLOCKED)
            url = nxt
        found = self.driver.site.pages.get(url)
        page = copy.deepcopy(found) if found is not None else FakePage(url=url, status=404, title="not found")
        self.page = page
        self.loaded_at = self.clock.ms
        self.generation += 1
        self._log(self.network, "network", NetworkEvent(method="GET", url=url, resource_type="document", status=page.status))
        for level, text in page.console:
            self._log(self.console, "console", ConsoleEvent(level=level, text=text))
        for sub_url, rtype in page.subresources:
            self.fire_request(sub_url, rtype)

    # -- DriverSession -----------------------------------------------------------------------------------------
    def current_url(self) -> str:
        self._live()
        return self.page.url

    def goto(self, url: str, timeout_ms: int) -> None:
        self._live()
        self._fault()
        if not self._gate(url, "document", True):
            self._log(self.network, "network", NetworkEvent(method="GET", url=url, resource_type="document", blocked=True))
            raise DriverFault(FaultKind.NAVIGATION_BLOCKED)
        self.clock.advance(self.driver.navigation_ms)
        self._load(url)

    def settle(self, ms: int) -> None:
        self._live()
        self.clock.advance(ms)

    def _info(self, el: FakeElement) -> ElementInfo:
        age = self.age()
        visible = age >= el.visible_after_ms and (el.hidden_after_ms is None or age < el.hidden_after_ms)
        covered = el.covered_until_ms is not None and age < el.covered_until_ms
        return ElementInfo(ref=f"g{self.generation}:{el.key}", role=el.role, name=el.name, visible=visible,
                           enabled=age >= el.enabled_after_ms, editable=el.kind in ("input", "select") and el.editable,
                           sensitive=el.sensitive, obscured_by=el.covered_by if (covered and visible) else None)

    @staticmethod
    def _match(actual: Optional[str], wanted: Optional[str], exact: bool) -> bool:
        if wanted is None:
            return True
        if actual is None:
            return False
        return actual == wanted if exact else wanted.lower() in actual.lower()

    def query(self, q: ElementQuery) -> Sequence[ElementInfo]:
        self._live()
        self._fault()
        out = []
        for el in self.page.elements:
            if el.frame != tuple(q.frame_path):
                continue
            if q.role is not None and not self._match(el.role, q.role, True):
                continue
            if not self._match(el.name, q.name, q.exact):
                continue
            if q.label is not None and not self._match(el.label, q.label, q.exact):
                continue
            if q.test_id is not None and el.test_id != q.test_id:
                continue
            if q.text_hint is not None and q.text_hint.lower() not in el.text.lower():
                continue
            out.append(self._info(el))
        return tuple(out)

    def _element(self, ref: str) -> FakeElement:
        prefix, _, key = ref.partition(":")
        if prefix != f"g{self.generation}":
            raise DriverFault(FaultKind.DETACHED)
        for el in self.page.elements:
            if el.key == key:
                return el
        raise DriverFault(FaultKind.DETACHED)

    def inspect(self, ref: str) -> ElementInfo:
        self._live()
        return self._info(self._element(ref))

    def read(self, ref: str) -> ElementReading:
        self._live()
        el = self._element(ref)
        if el.sensitive:
            return ElementReading(kind="value", sensitive=True)
        if el.kind == "checkbox":
            return ElementReading(kind="checked", checked=el.checked)
        if el.kind in ("input", "select"):
            return ElementReading(kind="value", text=el.value or "")
        return ElementReading(kind="text", text=el.text)

    def perform(self, ref: str, kind: str, value: Optional[str], timeout_ms: int) -> None:
        self._live()
        self._fault()
        el = self._element(ref)
        info = self._info(el)
        if not info.visible:
            raise DriverFault(FaultKind.NOT_VISIBLE)
        if not info.enabled:
            raise DriverFault(FaultKind.DISABLED)
        if info.obscured_by is not None:
            raise DriverFault(FaultKind.OBSCURED, obscurer_role=info.obscured_by)
        if kind == "fill" and not info.editable:
            raise DriverFault(FaultKind.NOT_EDITABLE)
        delay = self.action_delay_ms or self.driver.action_ms
        if delay > timeout_ms:
            self.clock.advance(timeout_ms)
            raise DriverFault(FaultKind.TIMEOUT)
        self.clock.advance(delay)
        if kind == "click":
            if el.kind == "checkbox":
                el.checked = not el.checked
            if el.on_click is not None:
                el.on_click(self, el)
        elif kind == "fill":
            el.value = value
        elif kind == "press":
            self.typed.append(value or "")
        elif kind == "select":
            el.value = value
        elif kind in ("check", "uncheck"):
            el.checked = kind == "check"
        elif kind == "hover":
            pass
        else:
            raise DriverFault(FaultKind.INVALID)

    def navigate_from_page(self, url: str) -> None:
        """What a click handler does: load another page (through the request gate)."""
        if not self._gate(url, "document", True):
            raise DriverFault(FaultKind.NAVIGATION_BLOCKED)
        self._load(url)

    def rerender(self) -> None:
        """The application replaced its DOM: every element reference taken before is stale."""
        self.generation += 1

    def page_meta(self) -> PageMeta:
        self._live()
        els = self.page.elements
        return PageMeta(title=self.page.title, lang=self.page.lang, ready_state="complete", elements=len(els),
                        links=sum(1 for e in els if e.role == "link"), forms=sum(1 for e in els if e.role == "form"),
                        inputs=sum(1 for e in els if e.kind in ("input", "checkbox", "select")))

    def _visible_elements(self) -> List[FakeElement]:
        return [e for e in self.page.elements if self._info(e).visible]

    def accessibility_snapshot(self) -> str:
        self._live()
        lines = []
        for e in self._visible_elements():
            line = f'- {e.role} "{e.name}"'
            if e.kind == "checkbox":
                line += f" [checked={str(e.checked).lower()}]"
            elif e.kind in ("input", "select") and not e.sensitive and e.value:
                line += f": {e.value}"
            elif e.text:
                line += f": {e.text}"
            lines.append(line)
        return "\n".join(lines) + (("\n" + self.page.extra_a11y) if self.page.extra_a11y else "")

    def screenshot(self) -> bytes:
        self._live()
        digest = hashlib.sha256(self.accessibility_snapshot().encode("utf-8") + self.page.url.encode("utf-8")).digest()
        return PNG_HEADER + digest

    def console_log(self) -> EventLog:
        self._live()
        return EventLog(events=tuple(self.console), dropped=self.dropped["console"])

    def network_log(self) -> EventLog:
        self._live()
        return EventLog(events=tuple(self.network), dropped=self.dropped["network"])

    def export_trace(self) -> bytes:
        self._live()
        if not self.spec.record_trace:
            raise DriverFault(FaultKind.INVALID)
        self.trace_exports += 1
        return b"PK\x03\x04" + hashlib.sha256(repr(list(self.network)).encode("utf-8")).digest()

    def reset(self) -> None:
        self._live()
        if self.driver.fail_reset:
            raise DriverFault(FaultKind.OTHER)
        self.local_storage.clear()
        self.cookies.clear()
        self.typed.clear()
        self.console.clear()
        self.network.clear()
        self.dropped = {"console": 0, "network": 0}
        self.page = FakePage(url="about:blank")
        self.loaded_at = self.clock.ms
        self.generation += 1

    def close(self) -> CloseReport:
        if self.driver.fail_close:
            raise DriverFault(FaultKind.OTHER)
        self.closed = True
        if self.driver.leak_on_close:
            return CloseReport(released=("page",), leaked=("context",))
        return CloseReport(released=("context", "page"), leaked=())

    def is_closed(self) -> bool:
        return self.closed


class FakeBrowserDriver:
    """The fake ``BrowserDriver``. ``calls`` is a flat log of driver activity; ``specs`` the context specs it was given."""

    browser_name = "fake-chromium"
    browser_version = "0.0.0"

    def __init__(self, site: Optional[FakeSite] = None, clock: Optional[FakeClock] = None, *, unavailable: bool = False) -> None:
        self.site = site if site is not None else FakeSite()
        self.clock = clock if clock is not None else FakeClock()
        self.unavailable = unavailable
        self.sessions: Dict[str, FakeSession] = {}
        self.specs: List[ContextSpec] = []
        self.calls: List[str] = []
        self.navigation_ms = 20
        self.action_ms = 10
        self.fail_reset = False
        self.fail_close = False
        self.leak_on_close = False
        self.closed = False

    def new_session(self, spec: ContextSpec) -> FakeSession:
        if self.unavailable:
            raise DriverUnavailable("the fake driver was told it is unavailable")
        self.specs.append(spec)
        session = FakeSession(self, spec)
        self.sessions[spec.session_id] = session
        return session

    def lose(self, session_id: str) -> None:
        """The browser context disappeared (closed from outside)."""
        self.sessions[session_id].closed = True

    def close(self) -> None:
        self.closed = True
