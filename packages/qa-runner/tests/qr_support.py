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


FAKE_ROBOT = str(Path(__file__).resolve().parent / "fake_robot.py")


def fake_robot(mode):
    """A ``RunOptions.robot_launcher`` that runs the Robot test double in ``mode`` instead of ``-m robot``."""
    return (FAKE_ROBOT, mode)


def process_table():
    """``{pid: (ppid, pgid, command)}`` of every process, from ``ps`` (what a process check can see; nothing here kills anything). ``-ww``: without it a ``ps`` that writes to a pipe may cut
    the command at the terminal width, and a long interpreter path then hides the module name the checks look for (this is what made the first CI run of these tests fail)."""
    import subprocess
    out = subprocess.run(["ps", "-A", "-ww", "-o", "pid=,ppid=,pgid=,command="], capture_output=True, text=True, timeout=30).stdout
    table = {}
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4 and parts[0].isdigit() and parts[1].isdigit() and parts[2].isdigit():
            table[int(parts[0])] = (int(parts[1]), int(parts[2]), parts[3])
    return table


def descendants(root: int, table=None):
    """The pids that descend from ``root`` by parent links (``root`` excluded)."""
    table = table or process_table()
    found, frontier = set(), {root}
    while frontier:
        nxt = {pid for pid, (ppid, _, _) in table.items() if ppid in frontier and pid not in found}
        found |= nxt
        frontier = nxt
    return found


def group_members(pgids, table=None):
    table = table or process_table()
    return {pid for pid, (_, pgid, _) in table.items() if pgid in pgids}


def wait_for(predicate, timeout=60.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.1)
    return predicate()
