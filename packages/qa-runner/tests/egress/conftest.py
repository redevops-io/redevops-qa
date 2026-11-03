# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The egress lane of qa-runner: a hostile page and hostile loopback listeners against the real Chromium, the egress gateway and the orchestrated browser lane. Every test here is
marked ``egress`` and runs only in the runner egress CI job, which installs the pinned Playwright and Chromium. Nothing here skips: a missing Playwright makes the tests FAIL."""
import importlib

import pytest


def pytest_collection_modifyitems(items):
    for item in items:
        if "tests/egress" in str(item.fspath).replace("\\", "/") and item.get_closest_marker("egress") is None:
            item.add_marker(pytest.mark.egress)


@pytest.fixture(scope="session", autouse=True)
def playwright_available():
    try:
        importlib.import_module("playwright.sync_api")
    except Exception as exc:                                     # a failure, never a skip
        pytest.fail(f"the egress lane needs the Playwright package (pip install playwright==1.64.1): {type(exc).__name__}", pytrace=False)
    return True
