# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The real-browser tests of the qa-service interface: a real service process-in-a-thread, a real Chromium. Marked ``browser``; a missing Playwright is a failure, never a skip."""
import importlib

import pytest


def pytest_collection_modifyitems(items):
    for item in items:
        if "tests/browser" in str(item.fspath).replace("\\", "/") and item.get_closest_marker("browser") is None:
            item.add_marker(pytest.mark.browser)


@pytest.fixture(scope="session", autouse=True)
def playwright_available():
    try:
        importlib.import_module("playwright.sync_api")
    except Exception as exc:
        pytest.fail(f"the interface tests need the Playwright package: {type(exc).__name__}", pytrace=False)
    return True


@pytest.fixture(scope="session")
def browser():
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()
