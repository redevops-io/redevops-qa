# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Runs the REAL browser lane after recording its own process id (the process becomes the lane by exec, so the id is the lane's process group): lets a test check
that the whole group, browser included, is gone when the supervisor has ended the lane."""
import os
import sys

pidfile, input_path = sys.argv[1], sys.argv[2]
with open(pidfile, "w") as fh:
    fh.write(str(os.getpid()))
os.execv(sys.executable, [sys.executable, "-s", "-m", "qa_runner.lane_browser", input_path])
