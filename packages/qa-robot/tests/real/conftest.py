# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Fixtures for the real Robot Framework lane. Nothing skips: if Robot Framework 7.5 is not importable the tests that need it fail with a
clear message. The lane runs in its own CI job and is not collected by the offline suite (the repository's pytest configuration excludes
``real`` directories)."""
import pytest


@pytest.fixture(scope="session")
def robot_installed():
    try:
        import importlib.metadata as md
        import robot  # noqa: F401
        version = md.version("robotframework")
    except Exception as exc:
        pytest.fail(f"Robot Framework is not importable in the real lane ({type(exc).__name__})")
    assert version == "7.5", f"the lane is pinned to Robot Framework 7.5, found {version}"
    return version
