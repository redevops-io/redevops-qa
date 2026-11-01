# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Helpers for the qa-runner tests: lane commands that run the test double, process checks."""
import os
import sys
import time
from pathlib import Path

FAKE = str(Path(__file__).resolve().parent / "fake_lane.py")


def fake(mode, *extra):
    """A ``RunOptions.lane_command`` that runs the test double in ``mode`` instead of the browser lane."""
    return lambda lane, input_path: [sys.executable, FAKE, mode, input_path, *extra]


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_gone(pid: int, timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if not alive(pid):
            return True
        time.sleep(0.05)
    return not alive(pid)


GATEWAY_DOWN = str(Path(__file__).resolve().parent / "gateway_down_lane.py")


def gateway_down(lane, input_path):
    return [sys.executable, GATEWAY_DOWN, input_path]
