# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Fixtures for the real Appium lanes. Nothing skips: a missing client, server or device makes the tests that need them fail with a clear
message. The lanes run in their own CI jobs and are not collected by the offline suite (the repository's pytest configuration excludes ``real``
directories)."""
import json
import os
import urllib.request

import pytest

SERVER_VERSION = "3.9.0"
CLIENT_VERSION = "6.1.1"


@pytest.fixture(scope="session")
def appium_client():
    try:
        import importlib.metadata as md
        import appium  # noqa: F401
        version = md.version("Appium-Python-Client")
    except Exception as exc:
        pytest.fail(f"the Appium Python client is not importable ({type(exc).__name__})")
    assert version == CLIENT_VERSION, f"the lane is pinned to Appium-Python-Client {CLIENT_VERSION}, found {version}"
    return version


@pytest.fixture(scope="session")
def server_url():
    url = os.environ.get("QA_APPIUM_URL", "")
    if not url.startswith("http://127.0.0.1:"):
        pytest.fail(f"QA_APPIUM_URL must name a loopback Appium server (got {url!r}); the lane starts none and downloads nothing")
    try:
        with urllib.request.urlopen(url + "/status", timeout=10) as response:      # noqa: S310 (loopback)
            status = json.load(response)
    except Exception as exc:
        pytest.fail(f"no Appium server answers at {url} ({type(exc).__name__})")
    assert status["value"]["ready"] is True
    assert status["value"]["build"]["version"] == SERVER_VERSION, f"the lane is pinned to Appium {SERVER_VERSION}, the server is {status['value']['build']['version']}"
    return url
