# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The real Robot Framework lane of qa-runner. Every test here is marked ``robot_real`` and runs only in the runner Robot CI job, which installs the pinned Robot Framework
(and no browser). Nothing here skips: if Robot Framework 7.5 is not importable the tests FAIL."""
import pytest


def pytest_collection_modifyitems(items):
    for item in items:
        if "tests/real" in str(item.fspath).replace("\\", "/") and item.get_closest_marker("robot_real") is None:
            item.add_marker(pytest.mark.robot_real)


@pytest.fixture(scope="session", autouse=True)
def robot_installed():
    try:
        import importlib.metadata as md
        import robot  # noqa: F401
        version = md.version("robotframework")
    except Exception as exc:
        pytest.fail(f"Robot Framework is not importable in the real lane ({type(exc).__name__})")
    assert version == "7.5", f"the lane is pinned to Robot Framework 7.5, found {version}"
    return version
