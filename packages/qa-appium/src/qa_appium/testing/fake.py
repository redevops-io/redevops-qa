# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A deterministic fake ``MobileDriver``: an app with screens and elements, stale and covered elements, a crash. No Appium, no device."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from qa_selenium.driver import DriverFault, FaultKind

from ..locators import MobileLocator

PNG = b"\x89PNG\r\n\x1a\n" + b"fake-device-screen"


@dataclass
class FakeNode:
    text: str = ""
    enabled: bool = True
    stale_reads: int = 0
    goes_to: Optional[str] = None
    value: str = ""


class FakeDevice:
    def __init__(self, package: str = "com.example.app", screens: Optional[Dict[str, Dict[str, FakeNode]]] = None, *, crash_on: Optional[str] = None,
                 foreground: Optional[str] = None):
        self.package = package
        self.foreground = foreground or package
        self.screens = screens if screens is not None else default_screens()
        self.screen = "home"
        self.history: List[str] = []
        self.log: List[str] = []
        self.quit_called = False
        self.crash_on = crash_on

    def _crash(self, op: str) -> None:
        if self.crash_on == op:
            raise DriverFault(FaultKind.CRASH)

    def current_package(self) -> str:
        self._crash("current_package")
        return self.foreground

    def _node(self, locator: MobileLocator) -> FakeNode:
        node = self.screens.get(self.screen, {}).get(str(locator))
        if node is None:
            raise DriverFault(FaultKind.NOT_FOUND)
        if node.stale_reads > 0:
            node.stale_reads -= 1
            raise DriverFault(FaultKind.STALE)
        return node

    def tap(self, locator: MobileLocator, timeout_s: float) -> None:
        self._crash("tap")
        node = self._node(locator)
        if not node.enabled:
            raise DriverFault(FaultKind.NOT_INTERACTABLE)
        self.log.append(f"tap {locator}")
        if node.goes_to:
            self.history.append(self.screen)
            self.screen = node.goes_to

    def type_text(self, locator: MobileLocator, text: str, timeout_s: float) -> None:
        node = self._node(locator)
        if not node.enabled:
            raise DriverFault(FaultKind.NOT_INTERACTABLE)
        node.value = text
        self.log.append(f"type {locator} <{len(text)} characters>")

    def read_text(self, locator: MobileLocator, timeout_s: float) -> str:
        node = self._node(locator)
        return node.value or node.text

    def back(self) -> None:
        if self.history:
            self.screen = self.history.pop()

    def screenshot_png(self) -> bytes:
        return PNG

    def quit(self) -> None:
        self.quit_called = True


def default_screens() -> Dict[str, Dict[str, FakeNode]]:
    return {
        "home": {"id=com.example.app:id/title": FakeNode(text="Welcome   aboard"), "id=com.example.app:id/name": FakeNode(),
                 "acc=Continue": FakeNode(text="Continue", goes_to="done"), "id=com.example.app:id/disabled": FakeNode(text="x", enabled=False),
                 "id=com.example.app:id/flaky": FakeNode(text="eventually", stale_reads=1), "id=com.example.app:id/stale": FakeNode(text="never", stale_reads=100)},
        "done": {"id=com.example.app:id/result": FakeNode(text="Done")},
    }
