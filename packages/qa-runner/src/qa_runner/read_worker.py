# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The child of ``isolated``: it does the reading that could block in the kernel, so that the parent can kill it. ``python -s -m qa_runner.read_worker file PATH MAX_BYTES`` writes one regular
file (a header line, then the bytes, at most MAX_BYTES of them); ``... bundle LOCATION`` writes a bundle directory or archive as a stream (a header with the listing, one record per file, an end
record). It enforces the byte caps itself and never writes more than the parent said it would accept. It reads nothing but the path it was given.

A worker never outlives the parent that started it (retest R2-8): a thread ends it when its parent is gone (``getppid()`` changes, like the lane children in ``watchdog``) and when the deadline
the parent gave, plus a short margin, has passed, so a parent that is killed (SIGKILL, a crash) or that cannot reach the worker leaves no blocked reader behind."""
from __future__ import annotations

import json
import os
import sys
import threading
import time

PARENT_ENV = "REDEVOPS_QA_READ_PARENT"
MARGIN_S = 5.0                                      # the worker's own deadline is just above the parent's, so the parent's TIMEOUT is the one that is reported

from .safe_read import UnsafeRead, read_regular


def _limit_memory() -> None:
    try:
        import resource
        cap = 3 * 1024 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
    except (ImportError, ValueError, OSError, AttributeError):
        pass


def _watch(parent: int, until: float, *, interval_s: float = 0.25) -> threading.Thread:
    """End this process when the parent is gone or the time is up. ``os._exit`` is used on purpose: the main thread may be blocked in a system call (an open on a FIFO) and cannot be asked."""
    def loop() -> None:
        while True:
            if os.getppid() != parent or time.monotonic() > until:
                os._exit(3)
            time.sleep(interval_s)
    thread = threading.Thread(target=loop, name="qa-read-watchdog", daemon=True)
    thread.start()
    return thread


def _parent() -> int:
    try:
        return int(os.environ.get(PARENT_ENV, ""))
    except ValueError:
        return os.getppid()


def _line(out, doc) -> None:
    out.write(json.dumps(doc, sort_keys=True).encode("utf-8") + b"\n")


def _file(path: str, max_bytes: int, deadline_s: float) -> int:
    out = sys.stdout.buffer
    try:
        data = read_regular(path, max_bytes=max_bytes, deadline_s=deadline_s, follow_symlinks=True)
    except UnsafeRead as exc:
        _line(out, {"ok": False, "code": exc.code, "message": str(exc)[:200]})
        out.flush()
        return 0
    _line(out, {"ok": True, "len": len(data)})
    out.write(data)
    out.flush()
    return 0


def _bundle(location: str) -> int:
    from qa_evidence.constants import DEFAULT_LIMITS
    from qa_evidence.sources import SourceError, open_source
    out = sys.stdout.buffer
    limits = DEFAULT_LIMITS
    try:
        source = open_source(location, limits)
    except (SourceError, OSError) as exc:
        _line(out, {"ok": False, "code": "UNREADABLE", "message": str(exc)[:200]})
        out.flush()
        return 0
    try:
        _line(out, {"ok": True, "kind": source.kind, "problems": [list(p) for p in source.problems], "entries": [[e.path, e.size] for e in source.entries]})
        budget = limits.max_total_bytes + limits.max_file_bytes + 1
        extra = []
        for entry in source.entries:
            if budget <= 0:
                extra.append(["NOT_READ", entry.path, "the total size cap was reached before this file was read"])
                continue
            try:
                blob = source.read_all(entry.path, limits.max_file_bytes)
            except (OSError, KeyError) as exc:
                extra.append(["UNREADABLE", entry.path, f"the file could not be read ({type(exc).__name__})"])
                continue
            budget -= len(blob)
            _line(out, {"path": entry.path, "len": len(blob)})
            out.write(blob)
        _line(out, {"end": True, "problems": extra})
        out.flush()
    finally:
        source.close()
    return 0


def _seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        return 0.0
    return value if 0 < value < 86400 else 0.0


def main(argv) -> int:
    _limit_memory()
    argv = list(argv)
    seconds = 3600.0
    if (argv[:1] == ["file"] and len(argv) == 4) or (argv[:1] == ["bundle"] and len(argv) == 3):
        seconds = _seconds(argv.pop()) or 3600.0
    _watch(_parent(), time.monotonic() + seconds + MARGIN_S)
    if len(argv) == 3 and argv[0] == "file" and argv[2].isdigit():
        return _file(argv[1], int(argv[2]), seconds)
    if len(argv) == 2 and argv[0] == "bundle":
        return _bundle(argv[1])
    print("usage: read_worker file PATH MAX_BYTES [SECONDS] | bundle LOCATION [SECONDS]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
