# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``MobileInteractiveAdapter``: bounded mobile actions for the shared ``InteractiveSession``, for Android and (as an interface) iOS.

Actions: ``open_app`` (starts the session for the configured app package and checks that it is in the foreground), ``tap``, ``type``
(value or secret value; never echoed), ``read`` (bounded), ``check`` (a native assertion declaring the assertion id the request names), ``back``
and ``screenshot`` (off unless enabled). Nothing installs an app, runs a shell command on the device or reaches a host other than the Appium
server. A missing Appium client, server, device or emulator is ``ERROR`` with ``UNAVAILABLE``: never a pass, never a skip, no fallback.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from qa_adapter_kit import (ActionOutcome, AdapterClass, AdapterFault, AdapterManifest, AdapterUnavailable, ArtifactRef, ErrorCode, FrameworkRef,
                            InteractiveActionRequest, InteractiveLayout, InteractiveObservation, Limits, NativeAssertion, Status)

from .driver import RETRYABLE, DriverFault, FaultKind, MobileDriver, classify_exception
from .locators import parse_mobile_locator

APPIUM_RELEASE = "3.9.0"
LICENSE_COMPONENT = "appium-server"
CAPABILITIES = ("open_app", "tap", "type", "read", "check", "back", "screenshot")
MAX_READ_CHARS = 2000
MAX_SCREENSHOT_BYTES = 5_000_000
_WS = re.compile(r"\s+")


def interactive_manifest(adapter_id: str, *, limits: Optional[Limits] = None) -> AdapterManifest:
    return AdapterManifest(
        adapter_id=adapter_id, adapter_version="0.1.0", adapter_class=AdapterClass.INTERACTIVE,
        framework=FrameworkRef(name="appium", pinned_release=APPIUM_RELEASE, license_component=LICENSE_COMPONENT),
        capabilities=CAPABILITIES, limits=limits or Limits(deadline_s=180, max_steps=50, max_retries=2), network="none")


@dataclass(frozen=True)
class MobileConfig:
    app_package: str
    allow_screenshots: bool = False
    wait_s: float = 5.0

    def __post_init__(self) -> None:
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$", self.app_package):
            raise ValueError("app_package must look like com.example.app")


def _fault(exc: BaseException) -> Exception:
    kind = exc.kind if isinstance(exc, DriverFault) else classify_exception(exc)
    if kind is FaultKind.UNAVAILABLE:
        return AdapterUnavailable("the Appium client, server, device or emulator is not available on this worker")
    if kind is FaultKind.CRASH:
        return AdapterFault("the mobile session failed", retryable=False, code=ErrorCode.ADAPTER_CRASH)
    return AdapterFault(f"mobile action failed: {kind.value}", retryable=kind in RETRYABLE, code=ErrorCode.ADAPTER_CRASH)


class MobileInteractiveAdapter:
    def __init__(self, driver_factory: Callable[[], MobileDriver], config: MobileConfig, manifest: AdapterManifest, *, probe_first: bool = False):
        self.manifest = manifest
        self._probe_first = probe_first      # an interface whose first answer must be whether the worker exists (iOS)
        self.config = config
        self._factory = driver_factory
        self._driver: Optional[MobileDriver] = None

    def _drv(self) -> MobileDriver:
        if self._driver is None:
            try:
                self._driver = self._factory()
            except AdapterUnavailable:
                raise
            except Exception as exc:
                raise _fault(exc) from None
        return self._driver

    def perform(self, request: InteractiveActionRequest, layout: InteractiveLayout) -> ActionOutcome:
        try:
            return self._perform(request, layout, min(request.timeout_s, self.config.wait_s))
        except (AdapterFault, AdapterUnavailable):
            raise
        except Exception as exc:
            raise _fault(exc) from None

    def _perform(self, request: InteractiveActionRequest, layout: InteractiveLayout, wait: float) -> ActionOutcome:
        kind = request.kind
        if self._probe_first:
            self._drv()
        if kind == "open_app":
            drv = self._drv()
            if drv.current_package() != self.config.app_package:
                raise AdapterFault("the app under test is not in the foreground", retryable=True, code=ErrorCode.ADAPTER_CRASH)
            return ActionOutcome(observations=[InteractiveObservation(kind="open_app", summary="app is in the foreground")])
        if kind == "back":
            self._drv().back()
            return ActionOutcome(observations=[InteractiveObservation(kind="back", summary="back pressed")])
        if kind == "screenshot":
            if not self.config.allow_screenshots:
                raise AdapterFault("screenshots are disabled for this session: an image cannot be redacted", retryable=False, code=ErrorCode.INVALID_REQUEST)
            data = self._drv().screenshot_png()
            if not data or len(data) > MAX_SCREENSHOT_BYTES or not data.startswith(b"\x89PNG\r\n\x1a\n"):
                raise AdapterFault("the device returned an unusable screenshot", retryable=False, code=ErrorCode.ADAPTER_CRASH)
            rel = f"screens/{request.session_id}-step-{request.step_index}.png"
            path = layout.output_dir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            return ActionOutcome(observations=[InteractiveObservation(kind="screenshot", summary="screenshot taken", artifact_paths=(rel,))],
                                 artifacts=[ArtifactRef(path=rel, media_type="image/png", role="screenshot")])
        loc = parse_mobile_locator(request.target)
        drv = self._drv()
        if kind == "tap":
            drv.tap(loc, wait)
            return ActionOutcome(observations=[InteractiveObservation(kind="tap", summary=f"tapped {loc}")])
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
            return ActionOutcome(assertions=[NativeAssertion(native_id=native_id, name=f"text of {loc}", status=Status.PASS if ok else Status.FAIL,
                                                             message=message, declared_assertion_ids=declared)])
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
