# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The real driver: Chromium through ``playwright.sync_api``.

``playwright`` is imported inside :class:`PlaywrightDriver` (never at module level), so importing this package never needs
it. If it is missing, or the browser cannot be started, construction fails with ``DriverUnavailable``: there is no
fallback and no download at run time (the browser comes from the pinned install step, see the README).

This file is exercised only by the real-browser lane (``tests/browser``), which a separate CI job runs with Playwright and
Chromium installed. It maps Playwright's behaviour onto the driver protocol and nothing else: every decision (uniqueness,
actionability deadlines, redaction, hashing, error codes) lives in ``adapter.py`` and is tested offline.

**Thread ownership.** Playwright's sync API cannot start on a thread that runs an asyncio loop, and its objects belong to the
thread that started it. ``PlaywrightDriver`` therefore owns one worker thread (no loop, started on first use, joined by
``close``) and runs every Playwright call on it; ``ThreadedSession`` is the proxy the adapter holds. Callers on any thread or
loop get results or the typed errors; a call that does not return in time is a ``TIMEOUT`` and makes the worker unusable
(``CRASHED`` afterwards), a worker that ends is ``CRASHED``, and a call after ``close`` is ``SESSION_CLOSED``.

Page text never leaves this module in an exception message: a failure is classified into a :class:`FaultKind` from the
exception's type and text and the text is then dropped.
"""
from __future__ import annotations

import importlib
import os
import queue
import re
import tempfile
import threading
import weakref
from collections import deque
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence, Tuple

from .driver import (CloseReport, ConsoleEvent, ContextSpec, DriverFault, ElementInfo, ElementQuery, ElementReading,
                     EventLog, FaultKind, NetworkEvent, PageMeta, RequestInfo)
from .errors import DriverUnavailable

DENIED_HEADER = "x-egress-decision"          # set by the egress gateway on a refusal it answers itself
MAX_ELEMENTS_PER_QUERY = 200
_REDIRECT_STATUSES = frozenset((301, 302, 303, 307, 308))
_ARIA_LINE = re.compile(r'^\s*-\s+([A-Za-z][\w-]*)(?:\s+"((?:[^"\\]|\\.)*)")?')

_JS_OBSCURED = """(el) => {
  const r = el.getBoundingClientRect();
  if (!r.width || !r.height) return null;
  const doc = el.ownerDocument;
  const top = doc.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
  if (!top || top === el || el.contains(top) || top.contains(el)) return null;
  const d = top.closest('dialog,[role=dialog],[role=alertdialog],[aria-modal=true]');
  if (d) return d.getAttribute('role') === 'alertdialog' ? 'alertdialog' : 'dialog';
  return '';
}"""
_JS_READ = """(el) => {
  const tag = el.tagName.toLowerCase();
  const type = (el.getAttribute('type') || '').toLowerCase();
  const role = (el.getAttribute('role') || '').toLowerCase();
  if (tag === 'input' && type === 'password') return {kind: 'value', text: '', checked: null, sensitive: true};
  if (tag === 'input' && (type === 'checkbox' || type === 'radio')) return {kind: 'checked', text: '', checked: !!el.checked, sensitive: false};
  const aria = el.getAttribute('aria-checked');
  if (['checkbox', 'radio', 'switch', 'menuitemcheckbox', 'menuitemradio'].includes(role) && (aria === 'true' || aria === 'false'))
    return {kind: 'checked', text: '', checked: aria === 'true', sensitive: false};
  if (tag === 'input' || tag === 'textarea' || tag === 'select') return {kind: 'value', text: String(el.value), checked: null, sensitive: false};
  return {kind: 'text', text: String(el.innerText || ''), checked: null, sensitive: false};
}"""
_JS_META = """() => ({title: document.title || '', lang: document.documentElement.lang || '', ready: document.readyState,
  elements: document.getElementsByTagName('*').length, links: document.links.length, forms: document.forms.length,
  inputs: document.querySelectorAll('input,textarea,select').length})"""


def _resolve_location(base: str, location: str) -> str:
    """The absolute URL a ``Location`` header names, for the gate to decide. Only the origin matters to the gate, so this
    resolves the forms that can change it (absolute, ``//host``, ``/path``) and treats the rest as the base's origin. A value
    Chromium would normalise in a way this does not model (control characters, a backslash, which Chromium reads as ``/``
    for http and https) is refused by raising: the caller fails the hop closed."""
    if any(ord(c) < 0x21 or ord(c) == 0x7F or c == "\\" for c in location):
        raise ValueError("unmodelled Location form")
    match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", location)
    if match is not None:
        return location
    origin = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*:)//[^/?#]*", base)
    if origin is None:
        raise ValueError("no base origin")
    if location.startswith("//"):
        return origin.group(1) + location
    if location.startswith("/"):
        return origin.group(0) + location
    return origin.group(0) + "/" + location


def _css_string(text: str) -> str:
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
        raise DriverFault(FaultKind.INVALID)
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def classify_error(exc: BaseException) -> DriverFault:
    """Playwright error -> :class:`DriverFault` (the text is read to classify and then dropped)."""
    if isinstance(exc, DriverFault):
        return exc
    name = type(exc).__name__
    text = str(exc).lower()
    if name == "TimeoutError":
        return DriverFault(FaultKind.TIMEOUT)
    if "has been closed" in text or "target closed" in text or "browser has been closed" in text:
        return DriverFault(FaultKind.SESSION_CLOSED)
    if "crashed" in text:
        return DriverFault(FaultKind.CRASHED)
    if "err_blocked_by_client" in text or "err_tunnel_connection_failed" in text:
        return DriverFault(FaultKind.NAVIGATION_BLOCKED)
    if "not attached" in text or "detached" in text or "element is not attached" in text:
        return DriverFault(FaultKind.DETACHED)
    if "intercepts pointer events" in text:
        return DriverFault(FaultKind.OBSCURED, obscurer_role="")
    if "not visible" in text:
        return DriverFault(FaultKind.NOT_VISIBLE)
    if "not enabled" in text or "disabled" in text:
        return DriverFault(FaultKind.DISABLED)
    if "not editable" in text or "readonly" in text:
        return DriverFault(FaultKind.NOT_EDITABLE)
    return DriverFault(FaultKind.OTHER)


class _Worker:
    """One dedicated thread that owns every Playwright object.

    The Playwright sync API refuses to start on a thread that already runs an asyncio loop, and its objects are tied to the
    thread that started it (it dispatches through greenlets). So the driver never touches Playwright from a caller's thread: a
    job (a callable) goes through a queue to this thread, which has no running loop, and the result or the exception comes back
    to the caller, whichever thread or loop it is on. The thread starts on first use, is a daemon (a wedged browser cannot keep
    the process alive), is joined by ``shutdown`` and is never used again after it ends or after a call timed out.
    """

    NAME = "qa-playwright-worker"

    def __init__(self, join_timeout_s: float) -> None:
        self._jobs: "queue.Queue[Optional[Tuple[Callable[[], Any], Future]]]" = queue.Queue()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._join_timeout_s = join_timeout_s
        self.closed = False          # shutdown was requested: no new job is accepted
        self.dead = False            # the thread has ended
        self.wedged = False          # a call did not return in time: the worker's state is unknown
        self.leaked = False          # shutdown could not join the thread

    @property
    def unusable(self) -> bool:
        return self.closed or self.dead or self.wedged

    def on_worker(self) -> bool:
        return self._thread is not None and threading.current_thread() is self._thread

    def _run(self) -> None:
        try:
            while True:
                item = self._jobs.get()
                if item is None:
                    return
                fn, future = item
                if not future.set_running_or_notify_cancel():
                    continue
                try:
                    future.set_result(fn())
                except Exception as exc:
                    future.set_exception(exc)
                except BaseException:                     # the thread is being torn down: report, then end
                    future.set_exception(DriverFault(FaultKind.CRASHED))
                    return
                del item, fn, future                      # an idle worker must not keep the last job (and its driver) alive
        finally:
            self.dead = True
            while True:                                    # nothing queued behind a dead worker waits for ever
                try:
                    item = self._jobs.get_nowait()
                except queue.Empty:
                    break
                if item is not None and item[1].set_running_or_notify_cancel():
                    item[1].set_exception(DriverFault(FaultKind.CRASHED))

    def _ensure(self) -> None:
        with self._lock:
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name=self.NAME, daemon=True)
                self._thread.start()

    def call(self, fn: Callable[..., Any], *args: Any, timeout_s: float) -> Any:
        """Run ``fn(*args)`` on the worker and return its result. A call made from the worker itself runs inline (an event
        handler that calls back cannot deadlock). Raises ``DriverFault`` ``SESSION_CLOSED`` after shutdown, ``CRASHED`` if the
        worker ended or is wedged, ``TIMEOUT`` if the call did not return within ``timeout_s``."""
        if self.on_worker():
            return fn(*args)
        if self.closed:
            raise DriverFault(FaultKind.SESSION_CLOSED)
        if self.dead or self.wedged:
            raise DriverFault(FaultKind.CRASHED)
        self._ensure()
        future: Future = Future()
        self._jobs.put((lambda: fn(*args), future))
        try:
            return future.result(timeout=timeout_s)
        except FutureTimeout:
            self.wedged = True
            future.cancel()
            raise DriverFault(FaultKind.TIMEOUT) from None

    def shutdown(self) -> None:
        """Stop accepting jobs, let the worker end and join it. A worker that does not end in time is recorded as leaked."""
        with self._lock:
            if self.closed:
                return
            self.closed = True
            thread = self._thread
        if thread is None:
            self.dead = True
            return
        self._jobs.put(None)
        thread.join(self._join_timeout_s)
        if thread.is_alive():
            self.leaked = True


class PlaywrightDriver:
    """A :class:`~qa_playwright.driver.BrowserDriver` for Chromium. Safe to construct and use from any thread, including one that
    runs an asyncio loop: all Playwright work happens on its own worker thread (see :class:`_Worker`).

    ``call_timeout_s`` bounds every call that has no timeout of its own, ``slack_s`` is added to a call that has one (so
    Playwright's own timeout fires first), ``start_timeout_s`` bounds starting Playwright and launching a browser, and
    ``join_timeout_s`` bounds ``close``. These are wall-clock bounds on a thread hand-off; the adapter's deadlines stay on the
    injected clock."""

    browser_name = "chromium"

    def __init__(self, *, headless: bool = True, executable_path: Optional[str] = None, chromium_sandbox: bool = False,
                 module: Any = None, call_timeout_s: float = 60.0, slack_s: float = 15.0, start_timeout_s: float = 60.0,
                 join_timeout_s: float = 15.0) -> None:
        self.browser_version = "unknown"
        self._headless = headless
        self._executable_path = executable_path
        self._chromium_sandbox = chromium_sandbox
        self._module = module
        self._call_timeout_s = call_timeout_s
        self._slack_s = slack_s
        self._start_timeout_s = start_timeout_s
        self._worker = _Worker(join_timeout_s)
        weakref.finalize(self, self._worker.shutdown)     # a driver dropped without close() still ends its thread
        self._browsers: Dict[Tuple[Any, ...], Any] = {}
        self._manager: Any = None
        self._pw: Any = None
        try:
            self._worker.call(self._start, timeout_s=start_timeout_s)
        except DriverUnavailable:
            self._worker.shutdown()
            raise
        except Exception as exc:                  # a fault of the worker itself (crash, timeout)
            self._worker.shutdown()
            raise DriverUnavailable("the Playwright driver is not available", reason=type(exc).__name__) from None

    # -- everything below this line that touches Playwright runs on the worker thread -----------------------------------
    def _start(self) -> None:
        try:
            mod = self._module if self._module is not None else importlib.import_module("playwright.sync_api")
            self._manager = mod.sync_playwright()
            self._pw = self._manager.start()
        except Exception as exc:
            raise DriverUnavailable("the Playwright driver is not available", reason=type(exc).__name__) from None

    def _browser_for(self, spec: ContextSpec) -> Any:
        key = (tuple(spec.launch_args), spec.proxy)
        browser = self._browsers.get(key)
        if browser is None or not browser.is_connected():
            kwargs: Dict[str, Any] = {"headless": self._headless, "args": list(spec.launch_args),
                                      "chromium_sandbox": self._chromium_sandbox}
            if spec.proxy is not None:
                kwargs["proxy"] = {"server": spec.proxy.server, "bypass": spec.proxy.bypass}
            if self._executable_path:
                kwargs["executable_path"] = self._executable_path
            try:
                browser = self._pw.chromium.launch(**kwargs)
            except Exception as exc:
                raise DriverUnavailable("the browser could not be started", reason=type(exc).__name__) from None
            self._browsers[key] = browser
            self.browser_version = str(browser.version)
        return browser

    def _open(self, spec: ContextSpec) -> "PlaywrightSession":
        return PlaywrightSession(self._browser_for(spec), spec)

    def _teardown(self) -> None:
        for browser in list(self._browsers.values()):
            try:
                browser.close()
            except Exception:
                pass
        self._browsers.clear()
        try:
            if self._manager is not None:
                self._manager.stop()
        except Exception:
            pass
        self._manager = self._pw = None

    # -- the public surface: callable from any thread ---------------------------------------------------------------------
    @property
    def leaked_worker(self) -> bool:
        """True if ``close`` could not end the worker thread (a browser call was stuck)."""
        return self._worker.leaked

    def new_session(self, spec: ContextSpec) -> "ThreadedSession":
        if self._worker.closed:
            raise DriverUnavailable("the Playwright driver is closed")
        try:
            inner = self._worker.call(self._open, spec, timeout_s=self._start_timeout_s)
        except DriverFault as fault:
            if fault.kind in (FaultKind.SESSION_CLOSED, FaultKind.CRASHED, FaultKind.TIMEOUT):
                raise DriverUnavailable("the Playwright driver cannot open a session", reason=fault.kind.value) from None
            raise
        return ThreadedSession(self._worker, inner, self._call_timeout_s, self._slack_s)

    def close(self) -> None:
        """Close the browsers, stop Playwright and join the worker thread. Idempotent; never raises. A driver that is dropped
        without ``close`` still ends its worker thread when it is collected, but only ``close`` stops the browsers."""
        if self._worker.closed:
            return
        if not self._worker.unusable:
            try:
                self._worker.call(self._teardown, timeout_s=self._call_timeout_s)
            except Exception:
                pass
        self._worker.shutdown()


class ThreadedSession:
    """The session the adapter sees: every method hands the matching call of the worker-confined :class:`PlaywrightSession` to
    the worker thread. Nothing of Playwright is touched on the caller's thread."""

    def __init__(self, worker: _Worker, inner: "PlaywrightSession", call_timeout_s: float, slack_s: float) -> None:
        self._w = worker
        self._inner = inner
        self._t = call_timeout_s
        self._slack = slack_s

    def _run(self, fn: Callable[..., Any], *args: Any, ms: Optional[int] = None) -> Any:
        timeout = self._t if ms is None else ms / 1000.0 + self._slack
        return self._w.call(fn, *args, timeout_s=timeout)

    def is_closed(self) -> bool:
        return self._inner.is_closed() or self._w.unusable

    def current_url(self) -> str:
        return self._run(self._inner.current_url)

    def goto(self, url: str, timeout_ms: int) -> None:
        self._run(self._inner.goto, url, timeout_ms, ms=timeout_ms)

    def settle(self, ms: int) -> None:
        self._run(self._inner.settle, ms, ms=ms)

    def query(self, query: ElementQuery) -> Sequence[ElementInfo]:
        return self._run(self._inner.query, query)

    def inspect(self, ref: str) -> ElementInfo:
        return self._run(self._inner.inspect, ref)

    def read(self, ref: str) -> ElementReading:
        return self._run(self._inner.read, ref)

    def perform(self, ref: str, kind: str, value: Optional[str], timeout_ms: int) -> None:
        self._run(self._inner.perform, ref, kind, value, timeout_ms, ms=timeout_ms)

    def page_meta(self) -> PageMeta:
        return self._run(self._inner.page_meta)

    def accessibility_snapshot(self) -> str:
        return self._run(self._inner.accessibility_snapshot)

    def screenshot(self) -> bytes:
        return self._run(self._inner.screenshot)

    def console_log(self) -> EventLog:
        return self._run(self._inner.console_log)

    def network_log(self) -> EventLog:
        return self._run(self._inner.network_log)

    def export_trace(self) -> bytes:
        return self._run(self._inner.export_trace)

    def reset(self) -> None:
        self._run(self._inner.reset)

    def close(self) -> CloseReport:
        if self._inner.is_closed():
            return CloseReport(released=("context", "page"), leaked=())
        if self._w.unusable:                       # the worker is gone: the context cannot be confirmed closed
            return CloseReport(released=(), leaked=("context", "page"))
        try:
            return self._run(self._inner.close)
        except DriverFault:
            return CloseReport(released=(), leaked=("context", "page"))


class PlaywrightSession:
    """One ephemeral ``BrowserContext`` with one page. No stored state is ever loaded into it or saved from it."""

    def __init__(self, browser: Any, spec: ContextSpec) -> None:
        self._browser = browser
        self._spec = spec
        self._closed = False
        self._crashed = False
        self._counter = 0
        self._handles: Dict[str, Any] = {}
        self._dialogs = 0
        self._open_context()

    # -- context ---------------------------------------------------------------------------------------------------
    def _open_context(self) -> None:
        spec = self._spec
        self._console: Deque[ConsoleEvent] = deque(maxlen=spec.max_console_events)
        self._network: Deque[NetworkEvent] = deque(maxlen=spec.max_network_events)
        self._dropped = {"console": 0, "network": 0}
        self._handles.clear()
        self._context = self._browser.new_context(
            accept_downloads=spec.accept_downloads, service_workers=spec.service_workers, permissions=list(spec.permissions),
            viewport={"width": spec.viewport[0], "height": spec.viewport[1]}, locale=spec.locale,
            timezone_id=spec.timezone_id, java_script_enabled=True, bypass_csp=False, ignore_https_errors=False,
            has_touch=False, reduced_motion="reduce", color_scheme="light")
        self._context.set_default_timeout(5000)
        if spec.request_gate is not None:
            self._context.route("**/*", self._route)
            try:
                self._context.route_web_socket("**/*", self._route_ws)
            except Exception:
                pass            # older drivers: the gateway still sees WebSocket upgrades
        if spec.record_trace:
            self._context.tracing.start(screenshots=False, snapshots=True, sources=False)
        self._page = self._context.new_page()
        self._context.on("page", self._on_page)
        self._wire(self._page)

    def _wire(self, page: Any) -> None:
        page.on("console", lambda m: self._log(self._console, "console", ConsoleEvent(level=str(m.type), text=str(m.text))))
        page.on("pageerror", lambda e: self._log(self._console, "console", ConsoleEvent(level="pageerror", text=str(e))))
        page.on("response", lambda r: self._log(self._network, "network", NetworkEvent(
            method=r.request.method, url=r.url, resource_type=r.request.resource_type, status=r.status)))
        page.on("requestfailed", lambda r: self._log(self._network, "network", NetworkEvent(
            method=r.method, url=r.url, resource_type=r.resource_type, failed=True)))
        page.on("crash", lambda _: setattr(self, "_crashed", True))
        page.on("dialog", self._on_dialog)
        page.on("filechooser", lambda chooser: None)       # never fulfilled: no file is ever offered to a page
        if self._spec.request_gate is not None:
            self._gate_redirects(page)

    def _gate_redirects(self, page: Any) -> None:
        """Put every redirect hop through the request gate *before* the browser requests it.

        ``context.route`` only sees the first URL of a redirect chain: once a route continues the request, Chromium follows the
        ``Location`` itself and the hop never reaches the route (Playwright documents this for ``page.route``; the real-browser
        lane showed a 302 to an unlisted host was fetched, with no gate decision). So a DevTools ``Fetch`` interception at the
        *response* stage, on its own CDP session, sees each 3xx answer with its ``Location`` while the hop is still unrequested.
        A hop the gate refuses is failed as ``BlockedByClient`` (the same outcome as a refused route); every other response is
        continued untouched. Anything unexpected while deciding fails the request closed."""
        cdp = self._context.new_cdp_session(page)

        def paused(event: Dict[str, Any]) -> None:
            request_id = event["requestId"]
            allowed = False
            try:
                status = event.get("responseStatusCode")
                if status not in _REDIRECT_STATUSES:
                    allowed = True
                else:
                    request = event.get("request") or {}
                    headers = {str(h.get("name", "")).lower(): str(h.get("value", "")) for h in event.get("responseHeaders") or ()}
                    location = headers.get("location")
                    if location is None:
                        allowed = True                       # a 3xx without Location is not followed by the browser
                    else:
                        target = _resolve_location(str(request.get("url", "")), location)
                        info = RequestInfo(url=target, resource_type=str(event.get("resourceType", "")).lower(),
                                           is_navigation=event.get("resourceType") == "Document",
                                           method=str(request.get("method", "GET")))
                        allowed = bool(self._spec.request_gate(info))
                        if not allowed:
                            self._log(self._network, "network", NetworkEvent(
                                method=info.method, url=target, resource_type=info.resource_type, blocked=True))
            except Exception:
                allowed = False
            try:
                if allowed:
                    cdp.send("Fetch.continueResponse", {"requestId": request_id})
                else:
                    cdp.send("Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
            except Exception:
                pass                                         # the page went away while the hop was being decided

        cdp.on("Fetch.requestPaused", paused)
        cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Response"}]})

    def _log(self, ring: Deque[Any], which: str, event: Any) -> None:
        if len(ring) == ring.maxlen:
            self._dropped[which] += 1
        ring.append(event)

    def _on_dialog(self, dialog: Any) -> None:
        self._dialogs += 1
        self._log(self._console, "console", ConsoleEvent(level="dialog", text=str(dialog.type)))
        dialog.dismiss()

    def _on_page(self, page: Any) -> None:
        if page is not self._page and not self._spec.allow_popups:
            self._log(self._console, "console", ConsoleEvent(level="popup-blocked", text=""))
            try:
                page.close()
            except Exception:
                pass
        else:
            self._wire(page)

    def _route(self, route: Any) -> None:
        req = route.request
        info = RequestInfo(url=req.url, resource_type=req.resource_type, is_navigation=bool(req.is_navigation_request()),
                           method=req.method)
        allowed = False
        try:
            allowed = bool(self._spec.request_gate(info))
        except Exception:
            allowed = False
        if allowed:
            route.continue_()
        else:
            self._log(self._network, "network", NetworkEvent(method=req.method, url=req.url,
                                                             resource_type=req.resource_type, blocked=True))
            route.abort("blockedbyclient")

    def _route_ws(self, ws: Any) -> None:
        info = RequestInfo(url=ws.url, resource_type="websocket", is_navigation=False, method="GET")
        try:
            allowed = bool(self._spec.request_gate(info))
        except Exception:
            allowed = False
        if allowed:
            ws.connect_to_server()
        else:
            self._log(self._network, "network", NetworkEvent(method="GET", url=ws.url, resource_type="websocket", blocked=True))
            ws.close()

    # -- plumbing --------------------------------------------------------------------------------------------------
    def _live(self) -> None:
        if self._closed or self._page.is_closed():
            raise DriverFault(FaultKind.SESSION_CLOSED)
        if self._crashed:
            raise DriverFault(FaultKind.CRASHED)

    def _call(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        self._live()
        try:
            return fn(*args, **kwargs)
        except DriverFault:
            raise
        except Exception as exc:
            raise classify_error(exc) from None

    def is_closed(self) -> bool:
        return self._closed

    def current_url(self) -> str:
        self._live()
        return str(self._page.url)

    def goto(self, url: str, timeout_ms: int) -> None:
        response = self._call(self._page.goto, url, timeout=timeout_ms, wait_until="load")
        if response is not None and str(response.headers.get(DENIED_HEADER, "")).lower() == "denied":
            raise DriverFault(FaultKind.NAVIGATION_BLOCKED)

    def settle(self, ms: int) -> None:
        self._call(self._page.wait_for_timeout, ms)

    # -- elements --------------------------------------------------------------------------------------------------
    def _base(self, query: ElementQuery) -> Any:
        base: Any = self._page
        for frame in query.frame_path:
            quoted = _css_string(frame)
            base = base.frame_locator(f"iframe[name={quoted}], iframe[title={quoted}]")
        return base

    def _locator(self, query: ElementQuery) -> Tuple[Any, bool]:
        """-> (locator, role_and_name_are_part_of_the_match)."""
        base = self._base(query)
        if query.test_id is not None:
            return base.get_by_test_id(query.test_id), False
        if query.role is not None:
            if query.name is not None:
                return base.get_by_role(query.role, name=query.name, exact=query.exact, include_hidden=True), True
            return base.get_by_role(query.role, include_hidden=True), True
        if query.label is not None:
            return base.get_by_label(query.label, exact=query.exact), False
        if query.name is not None:
            return base.get_by_text(query.name, exact=query.exact), False
        if query.text_hint is not None:
            return base.get_by_text(query.text_hint, exact=False), False
        raise DriverFault(FaultKind.INVALID)

    @staticmethod
    def _role_name(locator: Any) -> Tuple[str, str]:
        """The element's computed role and accessible name, from the first line of its ARIA snapshot."""
        try:
            first = str(locator.aria_snapshot(timeout=2000)).splitlines()[0]
        except Exception:
            return "", ""
        match = _ARIA_LINE.match(first)
        if match is None:
            return "", ""
        name = (match.group(2) or "").replace('\\"', '"').replace("\\\\", "\\")
        return match.group(1), name

    def query(self, query: ElementQuery) -> Sequence[ElementInfo]:
        loc, matched_role_name = self._locator(query)
        count = self._call(loc.count)
        out: List[ElementInfo] = []
        for i in range(min(count, MAX_ELEMENTS_PER_QUERY)):
            item = loc.nth(i)
            role, name = self._call(self._role_name, item)
            if not matched_role_name:
                if query.role is not None and role.lower() != query.role.lower():
                    continue
                if query.name is not None and not self._name_ok(name, query.name, query.exact):
                    continue
            fresh = self._call(item.element_handle, timeout=1000)
            ref, handle = self._ref_for(fresh)
            out.append(self._info(ref, handle, role, name))
        return tuple(out)

    def _ref_for(self, fresh: Any) -> Tuple[str, Any]:
        """The ref for an element, stable for as long as the element stays attached (the contract of ``ElementInfo.ref``).

        The adapter re-queries before it acts and requires the element it resolved earlier to be among the new results *by ref*.
        Playwright returns a new ``ElementHandle`` for every query, so a ref minted per query would never match and every act
        would fail with LOCATOR_NOT_FOUND. The new handle is therefore compared, in one page round trip and by object identity
        (``===``), with the handles already issued: a match reuses that ref and drops the new handle; no match mints a new ref."""
        known = list(self._handles.items())
        if known:
            index = self._call(fresh.evaluate, "(el, others) => others.findIndex((o) => o === el)", [h for _, h in known])
            if isinstance(index, int) and 0 <= index < len(known):
                try:
                    fresh.dispose()
                except Exception:
                    pass
                return known[index]
        self._counter += 1
        ref = f"e{self._counter}"
        self._handles[ref] = fresh
        return ref, fresh

    @staticmethod
    def _name_ok(actual: str, wanted: str, exact: bool) -> bool:
        return actual == wanted if exact else wanted.lower() in actual.lower()

    def _editable(self, handle: Any) -> bool:
        """Whether the element accepts text. Playwright's ``is_editable`` *raises* (it does not return False) for an element that
        is not a form control, a ``contenteditable`` host or a role that allows ``aria-readonly`` (a button, a link, a heading):
        such an element is simply not editable, so that one error is the answer ``False``. Any other failure is classified."""
        self._live()
        try:
            return bool(handle.is_editable())
        except DriverFault:
            raise
        except Exception as exc:
            if "does not have a role allowing [aria-readonly]" in str(exc):
                return False
            raise classify_error(exc) from None

    def _info(self, ref: str, handle: Any, role: str, name: str) -> ElementInfo:
        visible = bool(self._call(handle.is_visible))
        enabled = bool(self._call(handle.is_enabled))
        editable = self._editable(handle)
        kind = str(self._call(handle.get_attribute, "type") or "").lower()
        covered = self._call(handle.evaluate, _JS_OBSCURED) if visible else None
        return ElementInfo(ref=ref, role=role, name=name, visible=visible, enabled=enabled, editable=editable,
                           sensitive=kind == "password", obscured_by=None if covered is None else str(covered))

    def _handle(self, ref: str) -> Any:
        handle = self._handles.get(ref)
        if handle is None:
            raise DriverFault(FaultKind.DETACHED)
        return handle

    def inspect(self, ref: str) -> ElementInfo:
        handle = self._handle(ref)
        if not self._call(handle.evaluate, "(el) => el.isConnected"):
            raise DriverFault(FaultKind.DETACHED)
        return self._info(ref, handle, "", "")

    def read(self, ref: str) -> ElementReading:
        data = self._call(self._handle(ref).evaluate, _JS_READ)
        return ElementReading(kind=str(data["kind"]), text=str(data["text"]), checked=data["checked"],
                              sensitive=bool(data["sensitive"]))

    def perform(self, ref: str, kind: str, value: Optional[str], timeout_ms: int) -> None:
        handle = self._handle(ref)
        before = self._dialogs
        if kind == "click":
            self._call(handle.click, timeout=timeout_ms)
        elif kind == "fill":
            self._call(handle.fill, value or "", timeout=timeout_ms)
        elif kind == "press":
            self._call(handle.press, value or "", timeout=timeout_ms)
        elif kind == "select":
            self._call(handle.select_option, value or "", timeout=timeout_ms)
        elif kind == "check":
            self._call(handle.check, timeout=timeout_ms)
        elif kind == "uncheck":
            self._call(handle.uncheck, timeout=timeout_ms)
        elif kind == "hover":
            self._call(handle.hover, timeout=timeout_ms)
        else:
            raise DriverFault(FaultKind.INVALID)
        if self._dialogs != before:
            raise DriverFault(FaultKind.DIALOG)

    # -- observation -----------------------------------------------------------------------------------------------
    def page_meta(self) -> PageMeta:
        data = self._call(self._page.evaluate, _JS_META)
        return PageMeta(title=str(data["title"]), lang=str(data["lang"]), ready_state=str(data["ready"]),
                        elements=int(data["elements"]), links=int(data["links"]), forms=int(data["forms"]),
                        inputs=int(data["inputs"]))

    def accessibility_snapshot(self) -> str:
        return str(self._call(self._page.locator("body").aria_snapshot, timeout=5000))

    def screenshot(self) -> bytes:
        return bytes(self._call(self._page.screenshot, type="png", animations="disabled", caret="hide", scale="css"))

    def console_log(self) -> EventLog:
        return EventLog(events=tuple(self._console), dropped=self._dropped["console"])

    def network_log(self) -> EventLog:
        return EventLog(events=tuple(self._network), dropped=self._dropped["network"])

    def export_trace(self) -> bytes:
        if not self._spec.record_trace:
            raise DriverFault(FaultKind.INVALID)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "trace.zip")
            self._call(self._context.tracing.stop, path=path)
            with open(path, "rb") as handle:
                data = handle.read()
            self._call(self._context.tracing.start, screenshots=False, snapshots=True, sources=False)
        return data

    # -- lifecycle -------------------------------------------------------------------------------------------------
    def reset(self) -> None:
        self._live()
        try:
            self._context.close()
        except Exception:
            pass
        self._crashed = False
        self._open_context()

    def close(self) -> CloseReport:
        if self._closed:
            return CloseReport(released=("context", "page"), leaked=())
        released: List[str] = []
        leaked: List[str] = []
        try:
            self._context.close()
            released += ["context", "page"]
        except Exception:
            leaked += ["context", "page"]
        self._handles.clear()
        self._closed = True
        return CloseReport(released=tuple(sorted(released)), leaked=tuple(sorted(leaked)))
