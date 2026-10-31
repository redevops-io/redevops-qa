# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The real driver: Chromium through ``playwright.sync_api``.

``playwright`` is imported inside :class:`PlaywrightDriver` (never at module level), so importing this package never needs
it. If it is missing, or the browser cannot be started, construction fails with ``DriverUnavailable``: there is no
fallback and no download at run time (the browser comes from the pinned install step, see the README).

This file is exercised only by the real-browser lane (``tests/browser``), which a separate CI job runs with Playwright and
Chromium installed. It maps Playwright's behaviour onto the driver protocol and nothing else: every decision (uniqueness,
actionability deadlines, redaction, hashing, error codes) lives in ``adapter.py`` and is tested offline.

Page text never leaves this module in an exception message: a failure is classified into a :class:`FaultKind` from the
exception's type and text and the text is then dropped.
"""
from __future__ import annotations

import importlib
import os
import re
import tempfile
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

from .driver import (CloseReport, ConsoleEvent, ContextSpec, DriverFault, ElementInfo, ElementQuery, ElementReading,
                     EventLog, FaultKind, NetworkEvent, PageMeta, RequestInfo)
from .errors import DriverUnavailable

DENIED_HEADER = "x-egress-decision"          # set by the egress gateway on a refusal it answers itself
MAX_ELEMENTS_PER_QUERY = 200
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


class PlaywrightDriver:
    """A :class:`~qa_playwright.driver.BrowserDriver` for Chromium."""

    browser_name = "chromium"

    def __init__(self, *, headless: bool = True, executable_path: Optional[str] = None, chromium_sandbox: bool = False,
                 module: Any = None) -> None:
        self.browser_version = "unknown"
        self._headless = headless
        self._executable_path = executable_path
        self._chromium_sandbox = chromium_sandbox
        try:
            mod = module if module is not None else importlib.import_module("playwright.sync_api")
            self._manager = mod.sync_playwright()
            self._pw = self._manager.start()
        except Exception as exc:
            raise DriverUnavailable("the Playwright driver is not available", reason=type(exc).__name__) from None
        self._browsers: Dict[Tuple[Any, ...], Any] = {}

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

    def new_session(self, spec: ContextSpec) -> "PlaywrightSession":
        return PlaywrightSession(self._browser_for(spec), spec)

    def close(self) -> None:
        for browser in list(self._browsers.values()):
            try:
                browser.close()
            except Exception:
                pass
        self._browsers.clear()
        try:
            self._manager.stop()
        except Exception:
            pass


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
            handle = self._call(item.element_handle, timeout=1000)
            self._counter += 1
            ref = f"e{self._counter}"
            self._handles[ref] = handle
            out.append(self._info(ref, handle, role, name))
        return tuple(out)

    @staticmethod
    def _name_ok(actual: str, wanted: str, exact: bool) -> bool:
        return actual == wanted if exact else wanted.lower() in actual.lower()

    def _info(self, ref: str, handle: Any, role: str, name: str) -> ElementInfo:
        visible = bool(self._call(handle.is_visible))
        enabled = bool(self._call(handle.is_enabled))
        editable = bool(self._call(handle.is_editable))
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
