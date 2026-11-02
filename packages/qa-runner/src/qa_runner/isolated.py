# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Reads of user-supplied paths (a plan or lock, a bundle to verify, report or inspect) in a child process that this process can kill.

Why a child: a thread cannot be stopped while it is blocked inside a read of a stalled mount, and a signal handler cannot run until the read returns. A child can be sent SIGKILL: the parent bounds the
read by elapsed time, by bytes (it stops taking bytes from the pipe at the cap and kills the child), and by a cancel (SIGINT, SIGTERM and SIGHUP end the wait and the child). The child does the
reading and enforces the same caps itself (``read_worker``); the parent only ever holds what came through the pipe, so what it verifies afterwards is ONE immutable copy, not the files.

What is tested and what is only inferred is in the README ("Bounded reads"): the kill of a child that never answers, the byte cap on the pipe, the cancel paths and the refusals are tested; that a
SIGKILLed child blocked in uninterruptible kernel I/O (a hard-hung mount) ends at once is NOT something this process can guarantee, so the parent does not wait for it (it waits a short grace and returns),
and the child stays until the kernel gives the I/O back."""
from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from qa_evidence.constants import DEFAULT_LIMITS
from qa_evidence.sources import SnapshotSource, SourceEntry

from . import limits as env_limits
from .procs import child_env

WORKER = [sys.executable, "-s", "-m", "qa_runner.read_worker"]      # tests replace this to model a worker that never answers
DEFAULT_READ_SECONDS: Optional[float] = None          # tests set these; otherwise REDEVOPS_QA_READ_TIMEOUT / REDEVOPS_QA_BUNDLE_READ_TIMEOUT (strictly parsed, ``limits``), default 30 / 120 s
DEFAULT_BUNDLE_SECONDS: Optional[float] = None


def read_seconds() -> float:
    return DEFAULT_READ_SECONDS if DEFAULT_READ_SECONDS is not None else env_limits.env_seconds("REDEVOPS_QA_READ_TIMEOUT", 30.0)


def bundle_seconds() -> float:
    return DEFAULT_BUNDLE_SECONDS if DEFAULT_BUNDLE_SECONDS is not None else env_limits.env_seconds("REDEVOPS_QA_BUNDLE_READ_TIMEOUT", 120.0)


class IsolatedReadError(Exception):
    """``code``: TIMEOUT, TOO_LARGE, CANCELLED, WORKER_FAILED, plus the worker's own (NOT_A_REGULAR_FILE, UNREADABLE...)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class _Cancelled(BaseException):
    pass


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=2.0)                      # a short grace: a child in uninterruptible I/O may not end; it is not waited for any longer
    except subprocess.TimeoutExpired:
        pass


def _run(args: Sequence[str], *, deadline_s: float, max_stdout: int, argv: Optional[Sequence[str]] = None) -> bytes:
    env = child_env(tempfile.gettempdir())
    end = time.monotonic() + deadline_s
    proc = subprocess.Popen(list(argv or WORKER) + list(args), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, cwd=tempfile.gettempdir(),
                            start_new_session=True, close_fds=True)
    previous: Dict[int, Any] = {}

    def cancel(signum, frame):
        raise _Cancelled()
    try:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            try:
                previous[sig] = signal.signal(sig, cancel)
            except ValueError:                       # not the main thread: no handler, the deadline and the caps still apply
                break
        fd = proc.stdout.fileno()
        os.set_blocking(fd, False)
        chunks: List[bytes] = []
        total = 0
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise IsolatedReadError("TIMEOUT", f"not read within {deadline_s:g} seconds")
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.2))
            if not ready:
                continue
            try:
                block = os.read(fd, 65536)
            except BlockingIOError:
                continue
            if not block:
                break
            total += len(block)
            if total > max_stdout:
                raise IsolatedReadError("TOO_LARGE", f"more than {max_stdout} bytes")
            chunks.append(block)
        proc.wait(timeout=max(0.1, min(5.0, end - time.monotonic())))
        return b"".join(chunks)
    except _Cancelled:
        raise IsolatedReadError("CANCELLED", "cancelled while reading") from None
    except subprocess.TimeoutExpired:
        raise IsolatedReadError("TIMEOUT", f"not read within {deadline_s:g} seconds") from None
    finally:
        if proc.poll() is None:
            _kill(proc)
        try:
            proc.stdout.close()
        except OSError:
            pass
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def read_file(path: str, *, max_bytes: int, deadline_s: Optional[float] = None, argv: Optional[Sequence[str]] = None) -> bytes:
    """The bytes of the regular file at ``path`` (at most ``max_bytes``), read by a child that is killed at the deadline."""
    out = _run(["file", os.path.abspath(path), str(max_bytes)], deadline_s=read_seconds() if deadline_s is None else deadline_s, max_stdout=max_bytes + 4096, argv=argv)
    head, _, body = out.partition(b"\n")
    try:
        doc = json.loads(head.decode("utf-8"))
    except ValueError:
        raise IsolatedReadError("WORKER_FAILED", "the reading child gave no answer") from None
    if not doc.get("ok"):
        raise IsolatedReadError(str(doc.get("code", "WORKER_FAILED")), str(doc.get("message", ""))[:200])
    if doc.get("len") != len(body) or len(body) > max_bytes:
        raise IsolatedReadError("WORKER_FAILED", "the reading child's answer is not what it declared")
    return body


def snapshot_bundle(location: str, *, deadline_s: Optional[float] = None, argv: Optional[Sequence[str]] = None) -> SnapshotSource:
    """ONE immutable snapshot of a bundle directory or archive, taken by a child that is killed at the deadline. Everything the verifier, ``report`` and ``inspect`` look at afterwards comes from it."""
    limits = DEFAULT_LIMITS
    cap = limits.max_total_bytes + limits.max_file_bytes + 1 + (limits.max_files + 8) * 512 + 4 * 1024 * 1024
    out = _run(["bundle", os.path.abspath(location)], deadline_s=bundle_seconds() if deadline_s is None else deadline_s, max_stdout=cap, argv=argv)
    pos = out.find(b"\n")
    try:
        head = json.loads(out[:pos].decode("utf-8")) if pos >= 0 else None
    except ValueError:
        head = None
    if not isinstance(head, dict):
        raise IsolatedReadError("WORKER_FAILED", "the reading child gave no answer")
    if not head.get("ok"):
        raise IsolatedReadError(str(head.get("code", "WORKER_FAILED")), str(head.get("message", ""))[:200])
    pos += 1
    data: Dict[str, bytes] = {}
    extra: List[Tuple[str, str, str]] = []
    while True:
        end = out.find(b"\n", pos)
        if end < 0:
            raise IsolatedReadError("WORKER_FAILED", "the reading child's stream ended early")
        try:
            rec = json.loads(out[pos:end].decode("utf-8"))
        except ValueError:
            raise IsolatedReadError("WORKER_FAILED", "the reading child's stream is malformed") from None
        pos = end + 1
        if rec.get("end"):
            extra = [tuple(map(str, p)) for p in rec.get("problems", [])]
            break
        n = rec.get("len")
        if not isinstance(n, int) or n < 0 or pos + n > len(out) or not isinstance(rec.get("path"), str):
            raise IsolatedReadError("WORKER_FAILED", "the reading child's stream is malformed")
        data[rec["path"]] = out[pos:pos + n]
        pos += n
    problems = [tuple(map(str, p)) for p in head.get("problems", [])] + extra
    entries = [SourceEntry(str(p), int(s)) for p, s in head.get("entries", [])]
    return SnapshotSource(str(head.get("kind", "snapshot")), entries, problems, data)
