# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``python -I robot_guard.py ROBOT_ARGS...``: Robot Framework's own command line, plus a watch on the parent.

The Robot lane runs the engine as a child of the runner under the kit supervisor, which ends it on a deadline or a cancel. When the runner itself is killed without a chance to
clean up (SIGKILL, an out-of-memory kill) nothing of the supervisor is left to do that, and the engine and anything it started would run on as orphans. This script is what the
adapter starts instead of ``-m robot``: it loads the watchdog by path (the isolated interpreter has no import path for this package; nothing here imports it), arms it, and then
runs ``robot`` exactly as ``python -m robot`` would. POSIX only, like the supervisor."""
from __future__ import annotations

import importlib.util
import os
import runpy
import sys
from pathlib import Path


def _watchdog():
    spec = importlib.util.spec_from_file_location("qa_runner_watchdog", Path(__file__).with_name("watchdog.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv, module: str = "robot") -> None:
    parent = os.getppid()
    if parent == 1:
        sys.exit(1)                                         # the runner is already gone: do not start an engine nobody supervises
    wd = _watchdog()
    wd.start(parent, wd.kill_own_group)
    sys.argv = [module, *argv]
    runpy.run_module(module, run_name="__main__", alter_sys=True)


if __name__ == "__main__":
    main(sys.argv[1:])
