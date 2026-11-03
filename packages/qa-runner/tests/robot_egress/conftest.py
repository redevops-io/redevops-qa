# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The Robot egress experiments: a hostile Robot library against the real Robot Framework, the real lane child and hostile LOOPBACK listeners of this machine. Every test here is marked
``robot_egress`` and runs only in the runner Robot egress CI job (Linux, the pinned Robot Framework, no browser). Nothing here skips: a missing Robot Framework, a kernel without the layers
or a machine without an IPv6 loopback makes the tests FAIL."""
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))


def pytest_collection_modifyitems(items):
    for item in items:
        if "tests/robot_egress" in str(item.fspath).replace("\\", "/") and item.get_closest_marker("robot_egress") is None:
            item.add_marker(pytest.mark.robot_egress)


@pytest.fixture(scope="session", autouse=True)
def robot_installed():
    try:
        import importlib.metadata as md
        import robot  # noqa: F401
        version = md.version("robotframework")
    except Exception as exc:
        pytest.fail(f"Robot Framework is not importable in the Robot egress lane ({type(exc).__name__})")
    assert version == "7.5", f"the lane is pinned to Robot Framework 7.5, found {version}"
    return version
