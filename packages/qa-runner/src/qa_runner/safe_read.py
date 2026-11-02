# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The one way this package reads a file it did not write itself (a plan, a lock, a lane's output, a log of the target): ``qa_adapter_kit.boundedread`` (one descriptor, regular files only, byte and
time caps, no symbolic link at any component under a root), and the run's evidence budget on top of it. See the kit module for the rules.

What the deadline guarantees: this read happens IN THIS PROCESS, so the deadline is checked between chunks. It bounds a slow or growing file, never a single system call that blocks in the kernel (a
temporary directory on a hung mount): that case is not interrupted here. The guarantee that a read cannot hold the process holds only for the isolated path (``isolated.py``: a child that is killed at
the deadline), which is what reads every path a user supplies."""
from __future__ import annotations

from typing import Optional

from qa_adapter_kit.boundedread import CHUNK, UnsafeRead, read_regular  # noqa: F401  (re-exported: this is where the runner imports them from)


class Budget:
    """A total byte budget for what the orchestrator keeps of a run (the lanes' output and logs together). A file that does not fit is NOT read and NOT kept, and its name is recorded: the evidence
    collected so far stays, the result says it is incomplete (the run is never VERIFIED), and nothing is deleted. ``total`` comes from ``REDEVOPS_QA_MAX_EVIDENCE_BYTES`` (default 128 MiB: half the cap of a bundle)."""

    def __init__(self, total: int, root: Optional[str] = None):
        self.total, self.used, self.dropped = total, 0, []
        self.root = root                                         # the run's temporary directory: no component below it may be a symbolic link

    @property
    def remaining(self) -> int:
        return max(0, self.total - self.used)

    def keep(self, name: str, data: bytes) -> bool:
        """Account for bytes already in memory (a log tail, a record built here): ``False`` and recorded when they do not fit."""
        if len(data) > self.remaining:
            self.dropped.append(name)
            return False
        self.used += len(data)
        return True

    def read(self, path: str, limit: int, name: str) -> "Optional[bytes]":
        """The bytes of the regular file at ``path`` if it fits the budget and ``limit``; ``None`` for a missing or unusable file, ``None`` and recorded for one that is too large for what is left."""
        try:
            data = read_regular(str(path), max_bytes=min(limit, self.remaining), deadline_s=10.0, follow_symlinks=False, root=self.root)
        except UnsafeRead as exc:
            if exc.code == "TOO_LARGE":
                self.dropped.append(name)
            return None
        self.used += len(data)
        return data
