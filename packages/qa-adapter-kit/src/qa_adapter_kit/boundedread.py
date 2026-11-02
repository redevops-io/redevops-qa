# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The one way the adapters and the runner read a file they did not write themselves (a report an engine wrote, a lane's output, a plan, a log of the target).

Every such read is bounded in bytes and in time, whatever the path points at: ONE descriptor is opened without blocking (``O_NONBLOCK``, so a FIFO with no writer does not hang the open),
``fstat``-ed, refused unless it is a regular file (a FIFO, a device, a socket, a directory: nothing is read from them), refused when it is larger than the cap, and then read in chunks with a
running total that stops at the cap plus one byte (a file that grows while it is read ends the read) and a monotonic deadline. There is no ``is_file`` followed by ``read_bytes``: the check and the
read are on the same descriptor, so nothing can be swapped between them.

With ``root``, the path must lie under ``root`` and EVERY component below it is opened with ``O_NOFOLLOW`` relative to the directory descriptor of the one before: a symbolic link at any level (a
``blobs`` directory replaced by a link) is refused, not followed. Standard library only."""
from __future__ import annotations

import errno
import os
import stat
import time
from typing import List, Optional

CHUNK = 64 * 1024


class UnsafeRead(Exception):
    """``code``: NOT_A_REGULAR_FILE, TOO_LARGE, TIMEOUT, UNREADABLE (the message never repeats file content)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _is_symlink_refusal(exc: OSError) -> bool:
    return exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", -1), errno.ENOTDIR)


def _open_under(root: str, path: str, flags: int) -> int:
    """Open ``path`` (under ``root``) component by component, never following a symbolic link at any of them."""
    base = os.path.abspath(root)
    full = os.path.abspath(path)
    if full != base and not full.startswith(base.rstrip(os.sep) + os.sep):
        raise UnsafeRead("NOT_A_REGULAR_FILE", "the path is not under its root")
    parts: List[str] = [p for p in os.path.relpath(full, base).split(os.sep) if p not in ("", ".")]
    if not parts or ".." in parts:
        raise UnsafeRead("NOT_A_REGULAR_FILE", "the path is not a file under its root")
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(base, os.O_RDONLY | directory | getattr(os, "O_CLOEXEC", 0))
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
            os.close(fd)
            fd = nxt
        last = os.open(parts[-1], flags | nofollow, dir_fd=fd)
        return last
    finally:
        os.close(fd)


def read_regular(path: str, *, max_bytes: int, deadline_s: float = 10.0, follow_symlinks: bool = True, root: Optional[str] = None) -> bytes:
    """The bytes of the regular file at ``path``, at most ``max_bytes``. A symbolic link is followed once, before the open, when ``follow_symlinks`` (a plan given by a user); the open itself never
    follows one (``O_NOFOLLOW``). With ``root`` no component below it may be a symbolic link."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        if root is not None:
            fd = _open_under(root, path, flags)
        else:
            target = os.path.realpath(path) if follow_symlinks else str(path)
            fd = os.open(target, flags | getattr(os, "O_NOFOLLOW", 0))
    except UnsafeRead:
        raise
    except OSError as exc:
        raise UnsafeRead("NOT_A_REGULAR_FILE" if _is_symlink_refusal(exc) else "UNREADABLE", exc.strerror or type(exc).__name__) from None
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
