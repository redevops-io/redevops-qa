# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``SeleniumInteractiveAdapter``: bounded browser actions for the shared ``InteractiveSession``.

Actions: ``open`` (URL on the allowlist, http or https), ``click``, ``type`` (value or secret value; the text is never echoed back),
``read`` (bounded text), ``check`` (compare an element's text with an expected value; a native assertion that declares the assertion
id it is evidence for), ``screenshot`` (off unless enabled, because an image cannot be redacted).

Page content is data. It appears only as a bounded ``read`` observation, which the session redacts; errors never contain it.
"""
from __future__ import annotations

import re
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


class SeleniumInteractiveAdapter:
    """``driver_factory`` is called on first use. A factory (or a driver) that raises ``DriverFault(UNAVAILABLE)`` makes the action
    ERROR ``UNAVAILABLE``; there is no fallback to another browser and no download."""

    def __init__(self, driver_factory: Callable[[], BrowserDriver], *, config: Optional[AdapterConfig] = None,
                 manifest: Optional[AdapterManifest] = None):
        self.manifest = manifest or interactive_manifest()
        self.config = config or AdapterConfig()
        self._factory = driver_factory
        self._driver: Optional[BrowserDriver] = None

    def _drv(self) -> BrowserDriver:
        if self._driver is None:
            try:
                self._driver = self._factory()
            except AdapterUnavailable:
                raise
            except Exception as exc:
                raise _fault(exc) from None
        return self._driver

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
        drv, self._driver = self._driver, None
        if drv is not None:
            try:
                drv.quit()
            except Exception:
                pass
