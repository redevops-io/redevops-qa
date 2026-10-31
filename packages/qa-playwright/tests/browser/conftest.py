# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The real-browser lane. Every test here is marked ``browser`` and runs only in the browser CI job, which installs the pinned
Playwright and Chromium. Nothing here skips: if Playwright is missing the fixture FAILS, with a message that says so."""
import importlib

import pytest


def pytest_collection_modifyitems(items):
    for item in items:
        if "tests/browser" in str(item.fspath).replace("\\", "/") and item.get_closest_marker("browser") is None:
            item.add_marker(pytest.mark.browser)


@pytest.fixture(scope="session")
def playwright_available():
    try:
        importlib.import_module("playwright.sync_api")
    except Exception as exc:                                     # a failure, never a skip
        pytest.fail(f"the browser lane needs the Playwright package (pip install playwright==1.64.1): {type(exc).__name__}",
                    pytrace=False)
    return True


@pytest.fixture(scope="session")
def fixture_server():
    from qa_pw_browser_site import FixtureServer
    with FixtureServer() as server:
        yield server
