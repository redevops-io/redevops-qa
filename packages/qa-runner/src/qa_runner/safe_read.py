# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The one way this package reads a file it did not write itself (a plan, a lock, a lane's output, a log of the target).

Every such read is bounded in bytes and in time, whatever the path points at: ONE descriptor is opened without blocking (``O_NONBLOCK``, so a FIFO with no writer does not hang the open),
``fstat``-ed, refused unless it is a regular file (a FIFO, a device, a socket, a directory: nothing is read from them, ``/dev/zero`` included), refused when it is larger than the cap, and then read
in chunks with a running total that stops at the cap plus one byte (a file that grows while it is read ends the read) and a monotonic deadline (a slow mount cannot hold the process). There is no
``is_file`` followed by ``read_bytes``: the check and the read are on the same descriptor, so nothing can be swapped between them."""
from __future__ import annotations

import errno
import os
import stat
import time
from typing import Optional

CHUNK = 64 * 1024


class UnsafeRead(Exception):
    """``code``: NOT_A_REGULAR_FILE, TOO_LARGE, TIMEOUT, UNREADABLE (the message never repeats file content)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def read_regular(path: str, *, max_bytes: int, deadline_s: float = 10.0, follow_symlinks: bool = True) -> bytes:
    """The bytes of the regular file at ``path``, at most ``max_bytes``. A symbolic link is followed once, before the open, when ``follow_symlinks`` (a plan given by a user); the open itself
    never follows one (``O_NOFOLLOW``), so a link swapped in afterwards is refused."""
    target = os.path.realpath(path) if follow_symlinks else str(path)
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags)
    except OSError as exc:
        raise UnsafeRead("UNREADABLE" if not _is_symlink_refusal(exc) else "NOT_A_REGULAR_FILE", exc.strerror or type(exc).__name__) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafeRead("NOT_A_REGULAR_FILE", "not a regular file")
        if info.st_size > max_bytes:
            raise UnsafeRead("TOO_LARGE", f"larger than {max_bytes} bytes")
        end = time.monotonic() + deadline_s
        chunks, total = [], 0
        while True:
            if time.monotonic() > end:
                raise UnsafeRead("TIMEOUT", f"not read within {deadline_s:g} seconds")
            try:
                block = os.read(fd, min(CHUNK, max_bytes + 1 - total))
            except BlockingIOError:
                time.sleep(0.01)
                continue
            except OSError as exc:
                raise UnsafeRead("UNREADABLE", exc.strerror or type(exc).__name__) from None
            if not block:
                return b"".join(chunks)
            total += len(block)
            if total > max_bytes:
                raise UnsafeRead("TOO_LARGE", f"larger than {max_bytes} bytes")
            chunks.append(block)
    finally:
        os.close(fd)


def _is_symlink_refusal(exc: OSError) -> bool:
    return exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", -1))


class Budget:
    """A total byte budget for what the orchestrator keeps of a run (the lanes' output and logs together). A file that does not fit is NOT read and NOT kept, and its name is recorded: the evidence
    collected so far stays, the result says it is incomplete (the run is never VERIFIED), and nothing is deleted. ``total`` comes from ``REDEVOPS_QA_MAX_EVIDENCE_BYTES`` (default 128 MiB: half the cap of a bundle)."""

    def __init__(self, total: int):
        self.total, self.used, self.dropped = total, 0, []

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
            data = read_regular(str(path), max_bytes=min(limit, self.remaining), deadline_s=10.0, follow_symlinks=False)
        except UnsafeRead as exc:
            if exc.code == "TOO_LARGE":
                self.dropped.append(name)
            return None
        self.used += len(data)
        return data
