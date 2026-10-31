# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The real driver: Selenium 4.52.0 with Chrome, imported lazily.

Selenium Manager is never used: the driver executable is passed to ``Service(executable_path=...)``, and Selenium 4.52.0 skips its
manager when a service path is given (``driver_finder.py`` logs 'Skipping Selenium Manager'). The browser binary and the driver
executable must both be named and exist; the browser is never downloaded. Each driver gets a fresh throwaway profile directory.

This module is exercised only by the real-browser lane (``tests/browser``); the offline suite uses ``testing.fake``.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from typing import Optional

from .driver import DriverFault, FaultKind, classify_exception
from .locators import Locator

SELENIUM_RELEASE = "4.52.0"
CHROME_ARGS = (
    "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-background-networking",
    "--disable-component-update", "--disable-sync", "--disable-default-apps", "--metrics-recording-only", "--no-pings",
    "--disable-dev-shm-usage", "--window-size=1280,800",
)


class SeleniumChromeDriver:
    def __init__(self, chromedriver_path: str, chrome_binary: str, *, proxy_server: Optional[str] = None, extra_args: tuple = ()):
        try:
            import importlib.metadata as md
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support import expected_conditions as expected
            from selenium.webdriver.support.ui import WebDriverWait
            installed = md.version("selenium")
        except Exception:
            raise DriverFault(FaultKind.UNAVAILABLE) from None
        if installed != SELENIUM_RELEASE:
            raise DriverFault(FaultKind.UNAVAILABLE)
        if not (os.path.isfile(chromedriver_path) and os.access(chromedriver_path, os.X_OK)):
            raise DriverFault(FaultKind.UNAVAILABLE)
        if not (os.path.isfile(chrome_binary) and os.access(chrome_binary, os.X_OK)):
            raise DriverFault(FaultKind.UNAVAILABLE)
        self._profile = tempfile.mkdtemp(prefix="qa-selenium-profile-")
        options = Options()
        options.binary_location = chrome_binary
        for arg in CHROME_ARGS + tuple(extra_args):
            options.add_argument(arg)
        options.add_argument(f"--user-data-dir={self._profile}")
        if proxy_server:
            options.add_argument(f"--proxy-server={proxy_server}")
        try:
            self._driver = webdriver.Chrome(service=Service(executable_path=chromedriver_path), options=options)
        except Exception as exc:
            shutil.rmtree(self._profile, ignore_errors=True)
            kind = classify_exception(exc)
            raise DriverFault(FaultKind.UNAVAILABLE if kind in (FaultKind.CRASH, FaultKind.UNAVAILABLE) else kind) from None
        self._by, self._wait, self._ec = By, WebDriverWait, expected

    def _guard(self, fn):
        try:
            return fn()
        except DriverFault:
            raise
        except Exception as exc:
            raise DriverFault(classify_exception(exc)) from None

    def open(self, url: str, timeout_s: float) -> None:
        def go():
            self._driver.set_page_load_timeout(timeout_s)
            self._driver.get(url)
        self._guard(go)

    def current_url(self) -> str:
        return self._guard(lambda: self._driver.current_url)

    def _find(self, locator: Locator, timeout_s: float, *, clickable: bool = False):
        by = (self._by.CSS_SELECTOR, locator.css())
        cond = self._ec.element_to_be_clickable(by) if clickable else self._ec.presence_of_element_located(by)
        try:
            return self._wait(self._driver, timeout_s).until(cond)
        except Exception as exc:
            kind = classify_exception(exc)
            # a wait that ran out for a clickable element means the element exists but is not usable
            raise DriverFault(FaultKind.NOT_FOUND if kind is FaultKind.TIMEOUT and not clickable else kind) from None

    def click(self, locator: Locator, timeout_s: float) -> None:
        self._guard(lambda: self._find(locator, timeout_s, clickable=True).click())

    def type_text(self, locator: Locator, text: str, timeout_s: float) -> None:
        def go():
            el = self._find(locator, timeout_s, clickable=True)
            el.clear()
            el.send_keys(text)
        self._guard(go)

    def read_text(self, locator: Locator, timeout_s: float) -> str:
        def go():
            el = self._find(locator, timeout_s)
            return el.get_attribute("value") if el.tag_name in ("input", "textarea") and el.get_attribute("value") else el.text
        return self._guard(go)

    def screenshot_png(self) -> bytes:
        return self._guard(lambda: self._driver.get_screenshot_as_png())

    def quit(self) -> None:
        try:
            self._driver.quit()
        finally:
            shutil.rmtree(self._profile, ignore_errors=True)
