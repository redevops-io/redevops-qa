# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""What the adapter needs from a mobile session, independent of Appium. The fault vocabulary is the Selenium package's: the Appium Python
client raises Selenium's exceptions, so one classification serves both."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from qa_selenium.driver import RETRYABLE, DriverFault, FaultKind, classify_exception   # noqa: F401  (re-exported)

from .locators import MobileLocator


@runtime_checkable
class MobileDriver(Protocol):
    def current_package(self) -> str: ...

    def tap(self, locator: MobileLocator, timeout_s: float) -> None: ...

    def type_text(self, locator: MobileLocator, text: str, timeout_s: float) -> None: ...

    def read_text(self, locator: MobileLocator, timeout_s: float) -> str: ...

    def back(self) -> None: ...

    def screenshot_png(self) -> bytes: ...

    def quit(self) -> None: ...
