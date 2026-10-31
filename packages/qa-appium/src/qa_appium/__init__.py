# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``qa_appium``: Appium adapters for ReDevOps QA. Android first (UiAutomator2); iOS only as an interface that reports ``UNAVAILABLE`` without a
real, licensed worker. Importing this package never imports the Appium client."""
from .adapter import (APPIUM_RELEASE, CAPABILITIES, MobileConfig, MobileInteractiveAdapter, interactive_manifest)
from .android import (DEFAULT_SERVER, AppiumAndroidDriver, android_adapter, android_capabilities, check_server_url)
from .driver import DriverFault, FaultKind, MobileDriver
from .ios import UNAVAILABLE_MESSAGE, ios_adapter, unavailable_ios_driver
from .locators import MobileLocator, parse_mobile_locator

__version__ = "0.1.0.dev0"

