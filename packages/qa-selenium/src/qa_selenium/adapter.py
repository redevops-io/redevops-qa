# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``SeleniumInteractiveAdapter``: bounded browser actions for the shared ``InteractiveSession``.

Actions: ``open`` (URL on the allowlist, http or https), ``click``, ``type`` (value or secret value; the text is never echoed back),
``read`` (bounded text), ``check`` (compare an element's text with an expected value; a native assertion that declares the assertion
id it is evidence for), ``screenshot`` (off unless enabled, because an image cannot be redacted).

Page content is data. It appears only as a bounded ``read`` observation, which the session redacts; errors never contain it.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, FrozenSet, Optional
from urllib.parse import urlsplit

from qa_adapter_kit import (ActionOutcome, AdapterFault, AdapterManifest, AdapterUnavailable, ArtifactRef, ErrorCode, FrameworkRef,
                            InteractiveActionRequest, InteractiveLayout, InteractiveObservation, Limits, NativeAssertion, Status, AdapterClass)

from .driver import RETRYABLE, BrowserDriver, DriverFault, FaultKind, classify_exception
from .locators import parse_locator

ADAPTER_ID = "selenium-interactive"
ADAPTER_VERSION = "0.1.0"
SELENIUM_RELEASE = "4.52.0"
LICENSE_COMPONENT = "selenium-python"
CAPABILITIES = ("open", "click", "type", "read", "check", "screenshot")
MAX_READ_CHARS = 2000
MAX_SCREENSHOT_BYTES = 5_000_000
_WS = re.compile(r"\s+")


def interactive_manifest(*, limits: Optional[Limits] = None) -> AdapterManifest:
    return AdapterManifest(
        adapter_id=ADAPTER_ID, adapter_version=ADAPTER_VERSION, adapter_class=AdapterClass.INTERACTIVE,
        framework=FrameworkRef(name="selenium", pinned_release=SELENIUM_RELEASE, license_component=LICENSE_COMPONENT),
        capabilities=CAPABILITIES, limits=limits or Limits(deadline_s=120, max_steps=50, max_retries=2), network="egress-gateway")


@dataclass(frozen=True)
class AdapterConfig:
    allowed_hosts: FrozenSet[str] = frozenset()      # "host" or "host:port"; empty means every navigation is refused (default deny)
    allow_screenshots: bool = False
    wait_s: float = 5.0                              # upper bound for one driver wait; the action's own timeout cuts it further
    launch_timeout_s: float = 60.0                   # budget for starting the driver and the browser (see ``SeleniumInteractiveAdapter.start``)


def check_url(url: str, allowed_hosts: FrozenSet[str]) -> str:
    """The URL if it is http(s), has no credentials and its host (or host:port) is on the allowlist; otherwise an ``AdapterFault``."""
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise AdapterFault("the URL cannot be parsed", retryable=False, code=ErrorCode.INVALID_REQUEST) from None
    if parts.scheme not in ("http", "https") or not host or parts.username is not None or parts.password is not None:
        raise AdapterFault("only http and https URLs without credentials are allowed", retryable=False, code=ErrorCode.INVALID_REQUEST)
    default_port = 443 if parts.scheme == "https" else 80
    listed = f"{host}:{port if port is not None else default_port}" in allowed_hosts or (port in (None, default_port) and host in allowed_hosts)
    if not listed:
        raise AdapterFault("the host is not on the navigation allowlist", retryable=False, code=ErrorCode.INVALID_REQUEST)
    return url


def _fault(exc: BaseException) -> Exception:
    kind = exc.kind if isinstance(exc, DriverFault) else classify_exception(exc)
    if kind is FaultKind.UNAVAILABLE:
        return AdapterUnavailable("the browser or its driver is not available on this worker")
    if kind is FaultKind.CRASH:
        return AdapterFault("the browser session failed", retryable=False, code=ErrorCode.ADAPTER_CRASH)
    return AdapterFault(f"browser action failed: {kind.value}", retryable=kind in RETRYABLE, code=ErrorCode.ADAPTER_CRASH)


class _Launch:
    """One driver launch, run on its own thread so that it has a budget of its own and can be cancelled."""

    def __init__(self) -> None:
        self.done = threading.Event()
        self.exc: Optional[BaseException] = None
        self.cancelled = False


def _quit(drv: BrowserDriver) -> None:
    try:
        drv.quit()
    except Exception:
        pass


class SeleniumInteractiveAdapter:
    """``driver_factory`` is called on first use. A factory (or a driver) that raises ``DriverFault(UNAVAILABLE)`` makes the action
    ERROR ``UNAVAILABLE``; there is no fallback to another browser and no download.

    Starting the driver and the browser is the slowest step of a session (a cold first start on a CI runner has taken close to ten
    seconds), so it has its own budget, ``AdapterConfig.launch_timeout_s``. Call ``start()`` once before the first action to start the
    browser under that budget and outside every action's ``timeout_s``. When the first action starts it instead, the session's
    per-action ``timeout_s`` (default 10 s) still bounds it: give that action a ``timeout_s`` of at least the time a start needs.
    ``close()`` and ``abort()`` cancel a start that has not finished: the browser is quit the moment the launch returns, so a start
    that an action timeout abandoned does not leave a browser behind. (The start itself cannot be interrupted from outside; it is
    bounded by the driver's own start-up limits.) There is no retry of a start that timed out."""

    def __init__(self, driver_factory: Callable[[], BrowserDriver], *, config: Optional[AdapterConfig] = None,
                 manifest: Optional[AdapterManifest] = None):
        self.manifest = manifest or interactive_manifest()
        self.config = config or AdapterConfig()
        self._factory = driver_factory
        self._driver: Optional[BrowserDriver] = None
        self._launch: Optional[_Launch] = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the driver and the browser now, within ``launch_timeout_s``. A no-op when it is already running. A start that does
        not finish in time is cancelled and reported as a ``TIMEOUT`` fault; a missing driver is ``UNAVAILABLE`` as for any action."""
        try:
            self._drv()
        except (AdapterFault, AdapterUnavailable):
            raise
        except Exception as exc:
            raise _fault(exc) from None

    def _run_launch(self, launch: _Launch) -> None:
        try:
            drv = self._factory()
        except BaseException as exc:      # noqa: BLE001 - classified by the caller, never kept as text
            launch.exc = exc
            launch.done.set()
            return
        with self._lock:
            keep = not launch.cancelled
            if keep:
                self._driver = drv
        if not keep:
            _quit(drv)                    # abandoned while it was starting: nobody owns this browser, so it is not left running
        launch.done.set()

    def _drv(self) -> BrowserDriver:
        with self._lock:
            if self._driver is not None:
                return self._driver
            launch = self._launch
            if launch is None:
                launch = self._launch = _Launch()
                threading.Thread(target=self._run_launch, args=(launch,), daemon=True, name="qa-selenium-launch").start()
        if not launch.done.wait(self.config.launch_timeout_s):
            self._cancel(launch)
            raise AdapterFault("the browser did not start within the launch budget", retryable=False, code=ErrorCode.TIMEOUT)
        with self._lock:
            if self._launch is launch:
                self._launch = None
            if launch.exc is None and not launch.cancelled and self._driver is not None:
                return self._driver
            exc = launch.exc
        if exc is None:
            raise AdapterFault("the adapter was closed while the browser was starting", retryable=False, code=ErrorCode.INVALID_REQUEST)
        if isinstance(exc, AdapterUnavailable):
            raise exc
        raise _fault(exc) from None

    def _cancel(self, launch: _Launch) -> None:
        with self._lock:
            launch.cancelled = True
            if self._launch is launch:
                self._launch = None

    def perform(self, request: InteractiveActionRequest, layout: InteractiveLayout) -> ActionOutcome:
        wait = min(request.timeout_s, self.config.wait_s)
        try:
            return self._perform(request, layout, wait)
        except (AdapterFault, AdapterUnavailable):
            raise
        except Exception as exc:        # a Selenium or driver exception, classified without keeping its text
            raise _fault(exc) from None

    def _perform(self, request: InteractiveActionRequest, layout: InteractiveLayout, wait: float) -> ActionOutcome:
        kind = request.kind
        if kind == "open":
            url = check_url(request.target, self.config.allowed_hosts)
            drv = self._drv()
            drv.open(url, wait)
            try:
                check_url(drv.current_url(), self.config.allowed_hosts)
            except AdapterFault:
                try:
                    drv.open("about:blank", wait)
                except Exception:
                    pass
                raise AdapterFault("the page redirected to a host that is not on the allowlist", retryable=False,
                                   code=ErrorCode.INVALID_REQUEST) from None
            return ActionOutcome(observations=[InteractiveObservation(kind="open", summary="page opened")])
        if kind == "screenshot":
            if not self.config.allow_screenshots:
                raise AdapterFault("screenshots are disabled for this session: an image cannot be redacted", retryable=False,
                                   code=ErrorCode.INVALID_REQUEST)
            data = self._drv().screenshot_png()
            if not data or len(data) > MAX_SCREENSHOT_BYTES or not data.startswith(b"\x89PNG\r\n\x1a\n"):
                raise AdapterFault("the browser returned an unusable screenshot", retryable=False, code=ErrorCode.ADAPTER_CRASH)
            rel = f"screens/{request.session_id}-step-{request.step_index}.png"
            path = layout.output_dir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            return ActionOutcome(observations=[InteractiveObservation(kind="screenshot", summary="screenshot taken", artifact_paths=(rel,))],
                                 artifacts=[ArtifactRef(path=rel, media_type="image/png", role="screenshot")])
        loc = parse_locator(request.target)
        drv = self._drv()
        if kind == "click":
            drv.click(loc, wait)
            return ActionOutcome(observations=[InteractiveObservation(kind="click", summary=f"clicked {loc}")])
        if kind == "type":
            text = request.secret_value if request.secret_value is not None else request.value
            if text is None:
                raise AdapterFault("type needs a value or a secret value", retryable=False, code=ErrorCode.INVALID_REQUEST)
            drv.type_text(loc, text, wait)
            return ActionOutcome(observations=[InteractiveObservation(kind="type", summary=f"typed {len(text)} characters into {loc}")])
        if kind == "read":
            text = _WS.sub(" ", drv.read_text(loc, wait)).strip()[:MAX_READ_CHARS]
            return ActionOutcome(observations=[InteractiveObservation(kind="read", summary=f"text of {loc}: {text}")])
        if kind == "check":
            if request.value is None:
                raise AdapterFault("check needs the expected text as its value", retryable=False, code=ErrorCode.INVALID_REQUEST)
            declared = (request.assertion_id,) if request.assertion_id else ()
            native_id = f"{request.session_id}-s{request.step_index}"
            try:
                actual = _WS.sub(" ", drv.read_text(loc, wait)).strip()
            except DriverFault as exc:
                if exc.kind is FaultKind.NOT_FOUND:
                    return ActionOutcome(assertions=[NativeAssertion(native_id=native_id, name=f"text of {loc}", status=Status.FAIL,
                                                                     message="the element was not found", declared_assertion_ids=declared)])
                raise
            expected = _WS.sub(" ", request.value).strip()
            ok = actual == expected
            message = "text matches" if ok else f"text differs (expected {len(expected)} characters, found {len(actual)})"
            return ActionOutcome(assertions=[NativeAssertion(native_id=native_id, name=f"text of {loc}",
                                                             status=Status.PASS if ok else Status.FAIL, message=message,
                                                             declared_assertion_ids=declared)])
        raise AdapterFault(f"unsupported action {kind!r}", retryable=False, code=ErrorCode.INVALID_REQUEST)

    def abort(self) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            drv, self._driver = self._driver, None
            launch, self._launch = self._launch, None
            if launch is not None:
                launch.cancelled = True       # a start that has not finished quits its browser when it does
        if drv is not None:
            _quit(drv)
