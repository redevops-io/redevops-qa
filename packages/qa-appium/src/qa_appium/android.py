# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Android through Appium (UiAutomator2). The Appium server, the UiAutomator2 driver, the Android SDK and the emulator or device are the
worker's: nothing here installs, downloads or redistributes them (the Android SDK terms forbid redistribution; the licence matrix lists
the SDK and emulator as excluded by default). The adapter drives an app that is already installed on the device or emulator."""
from __future__ import annotations

from typing import Callable, Dict, FrozenSet, Optional
from urllib.parse import urlsplit

from qa_adapter_kit import AdapterFault, ErrorCode

from .adapter import MobileConfig, MobileInteractiveAdapter, interactive_manifest
from .driver import DriverFault, FaultKind, MobileDriver, classify_exception
from .locators import MobileLocator

ADAPTER_ID = "appium-android-interactive"
APPIUM_CLIENT_RELEASE = "6.1.1"
DEFAULT_SERVER = "http://127.0.0.1:4723"
LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})


def android_capabilities(config: MobileConfig, *, app_activity: Optional[str] = None) -> Dict[str, object]:
    """Capabilities for a UiAutomator2 session on an app that is already installed: no APK, no install, no permission grant."""
    caps: Dict[str, object] = {
        "platformName": "Android", "appium:automationName": "UiAutomator2", "appium:appPackage": config.app_package,
        "appium:noReset": False, "appium:autoGrantPermissions": False, "appium:newCommandTimeout": 60,
    }
    if app_activity:
        caps["appium:appActivity"] = app_activity
    return caps


def check_server_url(url: str, allowed_hosts: FrozenSet[str] = frozenset()) -> str:
    """The Appium server must be on this machine unless the operator names its host."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port
    except ValueError:
        raise AdapterFault("the Appium server URL cannot be parsed", retryable=False, code=ErrorCode.INVALID_REQUEST) from None
    if parts.scheme not in ("http", "https") or not host or parts.username is not None or parts.password is not None:
        raise AdapterFault("the Appium server URL must be http or https without credentials", retryable=False, code=ErrorCode.INVALID_REQUEST)
    if host not in LOOPBACK and host not in allowed_hosts:
        raise AdapterFault("the Appium server is not on this machine and its host is not on the allowlist", retryable=False, code=ErrorCode.INVALID_REQUEST)
    return url


def android_adapter(driver_factory: Callable[[], MobileDriver], config: MobileConfig, *, limits=None) -> MobileInteractiveAdapter:
    return MobileInteractiveAdapter(driver_factory, config, interactive_manifest(ADAPTER_ID, limits=limits))


class AppiumAndroidDriver:
    """The real driver: the Appium Python client 6.1.1 against an Appium server. Imported lazily. Session creation fails with ``UNAVAILABLE`` when
    the client is missing or the server cannot start a device session (no SDK, no device); the failure text is dropped."""

    def __init__(self, config: MobileConfig, *, server_url: str = DEFAULT_SERVER, allowed_server_hosts: FrozenSet[str] = frozenset(),
                 app_activity: Optional[str] = None):
        url = check_server_url(server_url, allowed_server_hosts)
        try:
            import importlib.metadata as md
            from appium import webdriver
            from appium.options.android import UiAutomator2Options
            from appium.webdriver.common.appiumby import AppiumBy
            installed = md.version("Appium-Python-Client")
        except Exception:
            raise DriverFault(FaultKind.UNAVAILABLE) from None
        if installed != APPIUM_CLIENT_RELEASE:
            raise DriverFault(FaultKind.UNAVAILABLE)
        options = UiAutomator2Options().load_capabilities(android_capabilities(config, app_activity=app_activity))
        self._by = AppiumBy
        try:
            self._driver = webdriver.Remote(url, options=options)
        except Exception as exc:
            kind = classify_exception(exc)
            raise DriverFault(FaultKind.INVALID if kind is FaultKind.INVALID else FaultKind.UNAVAILABLE) from None

    def _guard(self, fn):
        try:
            return fn()
        except DriverFault:
            raise
        except Exception as exc:
            raise DriverFault(classify_exception(exc)) from None

    def _find(self, locator: MobileLocator, timeout_s: float):
        by = self._by.ID if locator.kind == "id" else self._by.ACCESSIBILITY_ID
        from selenium.webdriver.support import expected_conditions as expected
        from selenium.webdriver.support.ui import WebDriverWait
        try:
            return WebDriverWait(self._driver, timeout_s).until(expected.presence_of_element_located((by, locator.value)))
        except Exception as exc:
            kind = classify_exception(exc)
            raise DriverFault(FaultKind.NOT_FOUND if kind is FaultKind.TIMEOUT else kind) from None

    def current_package(self) -> str:
        return self._guard(lambda: self._driver.current_package or "")

    def tap(self, locator: MobileLocator, timeout_s: float) -> None:
        self._guard(lambda: self._find(locator, timeout_s).click())

    def type_text(self, locator: MobileLocator, text: str, timeout_s: float) -> None:
        def go():
            el = self._find(locator, timeout_s)
            el.clear()
            el.send_keys(text)
        self._guard(go)

    def read_text(self, locator: MobileLocator, timeout_s: float) -> str:
        return self._guard(lambda: self._find(locator, timeout_s).text)

    def back(self) -> None:
        self._guard(lambda: self._driver.back())

    def screenshot_png(self) -> bytes:
        return self._guard(lambda: self._driver.get_screenshot_as_png())

    def quit(self) -> None:
        self._driver.quit()
