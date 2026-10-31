# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The driver layer: what the adapter needs from a browser, independent of Selenium. ``SeleniumChromeDriver`` implements it for real
(``selenium_driver.py``, Selenium imported lazily); ``qa_selenium.testing.fake.FakeBrowser`` implements it for the offline tests."""
from __future__ import annotations

from enum import Enum
from typing import Protocol, runtime_checkable

from .locators import Locator


class FaultKind(str, Enum):
    NOT_FOUND = "NOT_FOUND"                  # no such element (after the bounded wait)
    STALE = "STALE"                          # the element was replaced between lookup and use
    NOT_INTERACTABLE = "NOT_INTERACTABLE"    # hidden, disabled, covered or intercepted
    TIMEOUT = "TIMEOUT"                      # a wait or a page load ran out
    INVALID = "INVALID"                      # a locator or argument the browser refused
    CRASH = "CRASH"                          # the browser or its driver is gone
    UNAVAILABLE = "UNAVAILABLE"              # Selenium, the browser or the driver executable is not present


RETRYABLE = frozenset({FaultKind.STALE, FaultKind.NOT_INTERACTABLE})


class DriverFault(Exception):
    """A browser failure, already classified. The text is fixed per kind: it never carries page content."""

    def __init__(self, kind: FaultKind):
        super().__init__(kind.value)
        self.kind = kind


# Selenium exception class name -> kind. The real-browser lane asserts that every name is a real class of the pinned Selenium.
SELENIUM_EXCEPTION_KINDS = {
    "NoSuchElementException": FaultKind.NOT_FOUND, "NoSuchShadowRootException": FaultKind.NOT_FOUND,
    "StaleElementReferenceException": FaultKind.STALE, "DetachedShadowRootException": FaultKind.STALE,
    "ElementNotInteractableException": FaultKind.NOT_INTERACTABLE, "ElementClickInterceptedException": FaultKind.NOT_INTERACTABLE,
    "ElementNotVisibleException": FaultKind.NOT_INTERACTABLE, "InvalidElementStateException": FaultKind.NOT_INTERACTABLE,
    "MoveTargetOutOfBoundsException": FaultKind.NOT_INTERACTABLE,
    "TimeoutException": FaultKind.TIMEOUT,
    "InvalidSelectorException": FaultKind.INVALID, "InvalidArgumentException": FaultKind.INVALID,
    "NoSuchDriverException": FaultKind.UNAVAILABLE, "SessionNotCreatedException": FaultKind.UNAVAILABLE,
    "InvalidSessionIdException": FaultKind.CRASH, "NoSuchWindowException": FaultKind.CRASH, "WebDriverException": FaultKind.CRASH,
}


def classify_exception(exc: BaseException) -> FaultKind:
    """The most specific kind for an exception, by class name along its MRO (so a subclass of a mapped class is mapped)."""
    for cls in type(exc).__mro__:
        kind = SELENIUM_EXCEPTION_KINDS.get(cls.__name__)
        if kind is not None:
            return kind
    return FaultKind.CRASH


@runtime_checkable
class BrowserDriver(Protocol):
    def open(self, url: str, timeout_s: float) -> None: ...

    def current_url(self) -> str: ...

    def click(self, locator: Locator, timeout_s: float) -> None: ...

    def type_text(self, locator: Locator, text: str, timeout_s: float) -> None: ...

    def read_text(self, locator: Locator, timeout_s: float) -> str: ...

    def screenshot_png(self) -> bytes: ...

    def quit(self) -> None: ...
