# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The child of ``isolated``: it does the reading that could block in the kernel, so that the parent can kill it. ``python -s -m qa_runner.read_worker file PATH MAX_BYTES`` writes one regular
file (a header line, then the bytes, at most MAX_BYTES of them); ``... bundle LOCATION`` writes a bundle directory or archive as a stream (a header with the listing, one record per file, an end
record). It enforces the byte caps itself and never writes more than the parent said it would accept. It reads nothing but the path it was given."""
from __future__ import annotations

import json
import sys

from .safe_read import UnsafeRead, read_regular


def _limit_memory() -> None:
    try:
        import resource
        cap = 3 * 1024 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
    except (ImportError, ValueError, OSError, AttributeError):
        pass


def _line(out, doc) -> None:
    out.write(json.dumps(doc, sort_keys=True).encode("utf-8") + b"\n")


def _file(path: str, max_bytes: int) -> int:
    out = sys.stdout.buffer
    try:
        data = read_regular(path, max_bytes=max_bytes, deadline_s=3600.0, follow_symlinks=True)
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


def main(argv) -> int:
    _limit_memory()
    if len(argv) == 3 and argv[0] == "file" and argv[2].isdigit():
        return _file(argv[1], int(argv[2]))
    if len(argv) == 2 and argv[0] == "bundle":
        return _bundle(argv[1])
    print("usage: read_worker file PATH MAX_BYTES | bundle LOCATION", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
