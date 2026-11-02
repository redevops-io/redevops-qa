# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Where a bundle's files come from: a directory, a canonical archive, or memory. Listing never reads file data; reading is bounded.

Directories are walked with ``lstat`` (an empty directory is a finding, because the archive form cannot hold one) and never followed through a symbolic link or a Windows reparse point (a junction); anything that is
not a regular file or a directory is a finding. Files are opened with ``O_NOFOLLOW`` where the platform has it and checked to be regular
after opening.
"""
from __future__ import annotations

import os
import stat
from typing import BinaryIO, Dict, Iterator, List, Mapping, NamedTuple, Optional, Tuple

from .constants import DEFAULT_LIMITS, Limits
from .tarfmt import ArchiveEntry, scan_tar

CHUNK = 1 << 20
MAX_DIR_DEPTH = 16
_REPARSE = 0x400


class SourceEntry(NamedTuple):
    path: str
    size: int


class SourceError(Exception):
    """The bundle location cannot be opened at all."""


class Source:
    kind = "abstract"

    def __init__(self):
        self.entries: List[SourceEntry] = []
        self.problems: List[Tuple[str, str, str]] = []

    def read_chunks(self, path: str, limit: int) -> Iterator[bytes]:        # pragma: no cover - interface
        raise NotImplementedError

    def read_all(self, path: str, limit: int) -> bytes:
        return b"".join(self.read_chunks(path, limit))

    def close(self) -> None:
        return None


class MemorySource(Source):
    kind = "memory"

    def __init__(self, files: Mapping[str, bytes]):
        super().__init__()
        self._files = dict(files)
        self.entries = [SourceEntry(p, len(d)) for p, d in sorted(self._files.items())]

    def read_chunks(self, path, limit):
        data = self._files[path][:limit + 1]
        for i in range(0, len(data), CHUNK):
            yield data[i:i + CHUNK]


class SnapshotSource(Source):
    """An immutable copy of another source, taken once: its listing, its problems and the bytes of every file it could read (at most ``limits.max_file_bytes + 1`` of each, and in total at most
    ``limits.max_total_bytes + max_file_bytes + 1``). Everything that verifies, inspects or recomputes from a snapshot sees the same bytes, whatever happens to the files afterwards.
    A file that was not read (over the total cap) raises ``OSError`` when it is asked for."""
    kind = "snapshot"

    def __init__(self, kind: str, entries: List[SourceEntry], problems: List[Tuple[str, str, str]], data: Mapping[str, bytes]):
        super().__init__()
        self.kind = kind
        self.entries, self.problems = list(entries), list(problems)
        self._data = dict(data)

    @property
    def files(self) -> Dict[str, bytes]:
        return dict(self._data)

    def read_chunks(self, path, limit):
        if path not in self._data:
            raise OSError("the file was not read into the snapshot")
        data = self._data[path][:limit + 1]
        for i in range(0, len(data), CHUNK):
            yield data[i:i + CHUNK]


def take_snapshot(source: Source, limits: Limits = DEFAULT_LIMITS) -> SnapshotSource:
    """Read ``source`` once, in full, into a ``SnapshotSource`` (the problems of the listing are kept; a file that cannot be read becomes a problem, never a crash)."""
    data: Dict[str, bytes] = {}
    problems = list(source.problems)
    budget = limits.max_total_bytes + limits.max_file_bytes + 1
    for entry in source.entries:
        if budget <= 0:
            problems.append(("NOT_READ", entry.path, "the total size cap was reached before this file was read"))
            continue
        try:
            blob = source.read_all(entry.path, limits.max_file_bytes)
        except (OSError, KeyError) as exc:
            problems.append(("UNREADABLE", entry.path, f"the file could not be read ({type(exc).__name__})"))
            continue
        data[entry.path] = blob
        budget -= len(blob)
    return SnapshotSource(source.kind, source.entries, problems, data)


class DirSource(Source):
    kind = "directory"

    def __init__(self, root: str, limits: Limits = DEFAULT_LIMITS):
        super().__init__()
        self.root = root
        self._limits = limits
        self._walk(root, "", 0)
        self.entries.sort()

    def _walk(self, directory: str, prefix: str, depth: int) -> None:
        if depth > MAX_DIR_DEPTH:
            self.problems.append(("PATH_TOO_DEEP", prefix.rstrip("/"), f"directories are nested deeper than {MAX_DIR_DEPTH}"))
            return
        try:
            with os.scandir(directory) as it:
                children = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            self.problems.append(("UNREADABLE", prefix.rstrip("/"), f"cannot list directory: {exc.strerror}"))
            return
        if not children:
            self.problems.append(("EMPTY_DIRECTORY", prefix.rstrip("/"), "an empty directory has no counterpart in the archive form"))
        for child in children:
            rel = prefix + child.name
            if len(self.entries) > self._limits.max_files:
                self.problems.append(("TOO_MANY_FILES", "", f"more than {self._limits.max_files} files"))
                return
            try:
                st = child.stat(follow_symlinks=False)
            except OSError as exc:
                self.problems.append(("UNREADABLE", rel, f"cannot stat: {exc.strerror}"))
                continue
            if stat.S_ISLNK(st.st_mode):
                self.problems.append(("SYMLINK_REFUSED", rel, "symbolic links are refused"))
            elif getattr(st, "st_file_attributes", 0) & _REPARSE:
                self.problems.append(("JUNCTION_REFUSED", rel, "reparse points (junctions, links) are refused"))
            elif stat.S_ISDIR(st.st_mode):
                self._walk(child.path, rel + "/", depth + 1)
            elif stat.S_ISREG(st.st_mode):
                self.entries.append(SourceEntry(rel, st.st_size))
            else:
                self.problems.append(("SPECIAL_FILE", rel, "only regular files are allowed (no device, socket or pipe)"))

    def read_chunks(self, path, limit):
        full = os.path.join(self.root, *path.split("/"))
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(full, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("not a regular file")
            remaining = limit + 1
            while remaining > 0:
                chunk = os.read(fd, min(CHUNK, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk
        finally:
            os.close(fd)


class TarSource(Source):
    kind = "archive"

    def __init__(self, path: str, limits: Limits = DEFAULT_LIMITS):
        super().__init__()
        self.path = path
        self._fh: Optional[BinaryIO] = None
        total = os.stat(path).st_size
        ceiling = limits.max_total_bytes + (limits.max_files + 4) * 1024 + 10240
        if total > ceiling:
            self.problems.append(("ARCHIVE_TOO_LARGE", "", f"the archive is {total} bytes; the cap is {ceiling}"))
            return
        self._fh = open(path, "rb")
        entries, problems = scan_tar(self._fh, total, limits)
        self.problems.extend(problems)
        self._index: Dict[str, ArchiveEntry] = {}
        for e in entries:
            self._index.setdefault(e.path, e)
        self.entries = [SourceEntry(e.path, e.size) for e in entries]

    def read_chunks(self, path, limit):
        entry = self._index[path]
        assert self._fh is not None
        self._fh.seek(entry.offset)
        remaining = min(entry.size, limit + 1)
        while remaining > 0:
            chunk = self._fh.read(min(CHUNK, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            yield chunk

    def close(self):
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def open_source(location: str, limits: Limits = DEFAULT_LIMITS) -> Source:
    """Open a bundle directory or archive file. Raises ``SourceError`` when the location is not usable at all."""
    try:
        st = os.lstat(location)
    except OSError as exc:
        raise SourceError(f"cannot open {location}: {exc.strerror}") from None
    if stat.S_ISLNK(st.st_mode):
        raise SourceError("the bundle location itself is a symbolic link")
    if stat.S_ISDIR(st.st_mode):
        return DirSource(location, limits)
    if stat.S_ISREG(st.st_mode):
        return TarSource(location, limits)
    raise SourceError("the bundle location is neither a directory nor a regular file")
