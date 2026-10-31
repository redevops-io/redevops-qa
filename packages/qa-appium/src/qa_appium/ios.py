# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""iOS is an interface only. Appium's XCUITest driver needs Xcode and Apple SDKs on a Mac, which ReDevOps neither bundles nor downloads (the
licence matrix lists the Apple toolchain as excluded by default). Without a real, licensed worker the adapter reports ``UNAVAILABLE`` for every
action: never a pass, never a skip.

An operator who has such a worker supplies ``driver_factory`` (a ``MobileDriver`` for their worker) from outside this repository; nothing here
imports or starts it.
"""
from __future__ import annotations

from typing import Callable, Optional

from qa_adapter_kit import AdapterUnavailable

from .adapter import MobileConfig, MobileInteractiveAdapter, interactive_manifest
from .driver import MobileDriver

ADAPTER_ID = "appium-ios-interactive"
UNAVAILABLE_MESSAGE = "iOS needs an Apple toolchain on a real, licensed worker; none is configured"


def unavailable_ios_driver() -> MobileDriver:
    raise AdapterUnavailable(UNAVAILABLE_MESSAGE)


def ios_adapter(config: MobileConfig, driver_factory: Optional[Callable[[], MobileDriver]] = None, *, limits=None) -> MobileInteractiveAdapter:
    return MobileInteractiveAdapter(driver_factory or unavailable_ios_driver, config, interactive_manifest(ADAPTER_ID, limits=limits), probe_first=True)
