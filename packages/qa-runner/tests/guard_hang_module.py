# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Stands in for the ``robot`` module under ``robot_guard.main(..., module="guard_hang_module")``: it starts a stray child that ignores SIGTERM, then hangs."""
import signal
import subprocess
import sys
import time

if __name__ == "__main__":
    subprocess.Popen([sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(600)  # guard-stray"])
    time.sleep(600)
