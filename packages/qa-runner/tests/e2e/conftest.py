# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The end-to-end lane of qa-runner: the real Chromium and the real Robot Framework in one run. Every test here is marked ``e2e`` and runs only in the runner end-to-end CI
job, which installs the pinned Playwright, Chromium and Robot Framework. Nothing here skips: a missing dependency makes the tests FAIL."""
import importlib

import pytest


def pytest_collection_modifyitems(items):
    for item in items:
        if "tests/e2e" in str(item.fspath).replace("\\", "/") and item.get_closest_marker("e2e") is None:
            item.add_marker(pytest.mark.e2e)


@pytest.fixture(scope="session", autouse=True)
def engines_available():
    try:
        import importlib.metadata as md
        importlib.import_module("playwright.sync_api")
        import robot  # noqa: F401
        assert md.version("playwright") == "1.64.1", md.version("playwright")
        assert md.version("robotframework") == "7.5", md.version("robotframework")
    except Exception as exc:
        pytest.fail(f"the end-to-end lane needs the pinned Playwright 1.64.1 (with Chromium) and Robot Framework 7.5 ({type(exc).__name__}: {exc})", pytrace=False)
