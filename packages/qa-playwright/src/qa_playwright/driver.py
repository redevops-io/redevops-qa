# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The driver layer: the small surface the adapter needs from a browser.

The adapter (``adapter.py``) holds all the QA logic: uniqueness reporting, actionability waits against the injected
``Clock``, redaction, hashing, error mapping. The driver does only browser work and reports facts. Two
implementations satisfy these protocols: the real one (``playwright_driver.PlaywrightDriver``, which imports
``playwright.sync_api`` lazily) and the deterministic fake (``qa_playwright.testing.fake``) the offline tests use.

Rules for every driver:

* A driver reports **page facts as data** (strings, numbers, booleans). It never receives or returns a policy, a spec or an
  assertion; nothing in this module can carry one.
* A driver failure is a :class:`DriverFault` with a fixed ``kind``; its message never contains page content. The
  adapter maps each kind to one harness error code.
* ``query`` and ``inspect`` have no side effects. ``perform`` is the only call that changes the page.
* ``settle(ms)`` waits (the real driver sleeps in the browser; the fake advances its clock). The adapter polls with it
  and decides every deadline from the injected clock.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional, Protocol, Sequence, Tuple, runtime_checkable


class FaultKind(enum.StrEnum):
    SESSION_CLOSED = "SESSION_CLOSED"            # the context, page or browser was closed under us
    CRASHED = "CRASHED"                          # the renderer or the browser process died
    TIMEOUT = "TIMEOUT"                          # a driver-side wait ran out
    DETACHED = "DETACHED"                        # the element is gone (re-render, navigation)
    NOT_VISIBLE = "NOT_VISIBLE"
    DISABLED = "DISABLED"
    OBSCURED = "OBSCURED"
    NOT_EDITABLE = "NOT_EDITABLE"
    NAVIGATION_BLOCKED = "NAVIGATION_BLOCKED"    # the browser-level request gate refused the navigation
    DIALOG = "DIALOG"                            # a modal dialog interrupted the operation
    LIMIT = "LIMIT"                              # a bound (size, count) was hit
    INVALID = "INVALID"                          # the request itself is not something the driver can do
    OTHER = "OTHER"


class DriverFault(Exception):
    """A driver-side failure. ``kind`` is the whole message: nothing from the page is ever put in it."""

    def __init__(self, kind: FaultKind, *, obscurer_role: Optional[str] = None) -> None:
        super().__init__(kind.value)
        self.kind = kind
        self.obscurer_role = obscurer_role      # the ARIA role of the covering element (a closed vocabulary), if known


@dataclass(frozen=True)
class ProxySettings:
    server: str
    bypass: str = ""


@dataclass(frozen=True)
class RequestInfo:
    """What the browser-level request gate is told about one request: never a body, never a header value."""

    url: str
    resource_type: str
    is_navigation: bool
    method: str = "GET"


RequestGate = Callable[[RequestInfo], bool]      # True: let the request go; False: abort it


@dataclass(frozen=True)
class ContextSpec:
    """Everything that defines one fresh, ephemeral browser context. No ``storageState``, no user-data directory, no
    shared profile exists in this type: a context starts empty and ends with the session."""

    session_id: str
    profile_id: str
    launch_args: Tuple[str, ...] = ()
    proxy: Optional[ProxySettings] = None
    accept_downloads: bool = False
    allow_popups: bool = False
    allow_file_choosers: bool = False
    service_workers: str = "block"
    permissions: Tuple[str, ...] = ()
    viewport: Tuple[int, int] = (1280, 720)
    locale: str = "en-US"
    timezone_id: str = "UTC"
    record_trace: bool = False
    max_console_events: int = 200
    max_network_events: int = 500
    request_gate: Optional[RequestGate] = field(default=None, compare=False)


@dataclass(frozen=True)
class ElementQuery:
    """A locator: role / label / test id first. ``exact`` is the EXACT locate mode (equality); otherwise the match is a
    case-insensitive substring. ``text_hint`` is only used in the semantic mode."""

    role: Optional[str] = None
    name: Optional[str] = None
    label: Optional[str] = None
    test_id: Optional[str] = None
    text_hint: Optional[str] = None
    frame_path: Tuple[str, ...] = ()
    exact: bool = True


@dataclass(frozen=True)
class ElementInfo:
    ref: str                       # opaque to the adapter; stable for one element while it stays attached to the document it was resolved in
    role: str
    name: str
    visible: bool
    enabled: bool
    editable: bool = False
    sensitive: bool = False        # a password-type control: its value is never read
    obscured_by: Optional[str] = None     # None: not covered; otherwise the covering element's role ("" if unknown)


@dataclass(frozen=True)
class ElementReading:
    kind: str                      # "text", "value" or "checked"
    text: str = ""
    checked: Optional[bool] = None
    sensitive: bool = False


@dataclass(frozen=True)
class PageMeta:
    title: str = ""
    lang: str = ""
    ready_state: str = ""
    elements: int = 0
    links: int = 0
    forms: int = 0
    inputs: int = 0


@dataclass(frozen=True)
class ConsoleEvent:
    level: str
    text: str


@dataclass(frozen=True)
class NetworkEvent:
    method: str
    url: str
    resource_type: str
    status: Optional[int] = None
    failed: bool = False
    blocked: bool = False


@dataclass(frozen=True)
class EventLog:
    """A bounded excerpt of an event stream: the newest entries and how many older ones were dropped."""

    events: Tuple[object, ...] = ()
    dropped: int = 0


@dataclass(frozen=True)
class CloseReport:
    released: Tuple[str, ...] = ()
    leaked: Tuple[str, ...] = ()


@runtime_checkable
class DriverSession(Protocol):
    """One ephemeral browser context with one page."""

    def current_url(self) -> str: ...

    def goto(self, url: str, timeout_ms: int) -> None: ...

    def settle(self, ms: int) -> None: ...

    def query(self, query: ElementQuery) -> Sequence[ElementInfo]: ...

    def inspect(self, ref: str) -> ElementInfo: ...

    def read(self, ref: str) -> ElementReading: ...

    def perform(self, ref: str, kind: str, value: Optional[str], timeout_ms: int) -> None: ...

    def page_meta(self) -> PageMeta: ...

    def accessibility_snapshot(self) -> str: ...

    def screenshot(self) -> bytes: ...

    def console_log(self) -> EventLog: ...

    def network_log(self) -> EventLog: ...

    def export_trace(self) -> bytes: ...

    def reset(self) -> None: ...

    def close(self) -> CloseReport: ...

    def is_closed(self) -> bool: ...


@runtime_checkable
class BrowserDriver(Protocol):
    browser_name: str
    browser_version: str

    def new_session(self, spec: ContextSpec) -> DriverSession: ...

    def close(self) -> None: ...


PERFORM_KINDS = ("click", "fill", "press", "select", "check", "uncheck", "hover")
