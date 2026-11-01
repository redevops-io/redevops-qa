# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A child that outlives its parent is a leak: when the orchestrator is killed without a chance to clean up (SIGKILL, a crash of the host process), nothing else would end the
lane child, its browser or its engine. The lane child watches its parent and ends itself and its process group when the parent is gone. POSIX only, like the supervisor."""
from __future__ import annotations

import os
import signal
import threading
import time
from typing import Callable, Optional


def start(parent_pid: int, on_parent_gone: Callable[[], None], *, interval_s: float = 0.25) -> threading.Thread:
    def loop() -> None:
        while True:
            time.sleep(interval_s)
            if os.getppid() != parent_pid:
                on_parent_gone()
                return
    thread = threading.Thread(target=loop, name="qa-parent-watchdog", daemon=True)
    thread.start()
    return thread


def kill_own_group() -> None:
    """End this process and everything it started that is still in its process group (the browser, for the browser lane)."""
    try:
        os.killpg(os.getpgrp(), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        os._exit(1)


def kill_after(grace_s: float) -> Callable[[], None]:
    def later() -> None:
        time.sleep(grace_s)
        kill_own_group()
    return later
