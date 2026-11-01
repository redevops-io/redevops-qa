# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The REAL browser lane (real Chromium, real gateway) held open after its steps: the harness asks the target for its health once more before it closes the session, and
here that answer takes ten minutes. It makes the lane alive, with a browser running, for as long as a test needs to kill its parent."""
import sys
import time

import qa_runner.lane_browser as lb

original = lb.AppChecks.environment_healthy


def slow(self, phase):
    if phase == "after":
        time.sleep(600)
    return original(self, phase)


lb.AppChecks.environment_healthy = slow
sys.exit(lb.main(sys.argv[1:]))
