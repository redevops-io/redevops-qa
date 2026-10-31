# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``qa_selenium``: Selenium (Python) adapters for ReDevOps QA.

* ``SeleniumInteractiveAdapter``: bounded browser actions over a ``BrowserDriver`` protocol.
* ``SeleniumSuiteAdapter``: runs an existing pytest-based Selenium suite and imports its JUnit XML.

Importing this package never imports Selenium; ``SeleniumChromeDriver`` does, when it is constructed.
"""
from .adapter import (ADAPTER_ID, AdapterConfig, SeleniumInteractiveAdapter, check_url, interactive_manifest)
from .driver import (BrowserDriver, DriverFault, FaultKind, SELENIUM_EXCEPTION_KINDS, classify_exception)
from .junit import ASSERT_PROPERTY, parse_junit, read_junit
from .locators import Locator, parse_locator
from .suite import SeleniumSuiteAdapter, suite_manifest

__version__ = "0.1.0.dev0"


def SeleniumChromeDriver(*args, **kwargs):          # noqa: N802 (a class-like factory so that importing stays lazy)
    from .selenium_driver import SeleniumChromeDriver as _Driver
    return _Driver(*args, **kwargs)
