# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The single-file archive form: a canonical, uncompressed POSIX ustar archive written and read by this module only.

Every header is generated, not copied: mode 0644, uid and gid 0, no user or group name, modification time 0, regular file, no link,
no prefix, name of at most 100 bytes. Entries are sorted by path (code point order, which is UTF-8 byte order) and the archive is
padded to a multiple of 10240 bytes, as ``tar`` does. Reading re-generates the canonical header of every entry and compares it byte for
byte with what is on disk, so a symbolic link, a hard link, a device, an extended (pax or GNU) header, a different time, owner or mode,
a directory member, a different order and trailing data all show up as one finding: the archive is not the canonical form. Standard
tools read the archive (``tar -tf``, ``tarfile``); only this reader trusts it. There is no compression, so the bytes do not depend on a
compressor version.
"""
from __future__ import annotations

from typing import BinaryIO, List, Mapping, NamedTuple, Tuple

from .constants import DEFAULT_LIMITS, Limits

BLOCK = 512
RECORD = 10240


class ArchiveEntry(NamedTuple):
    path: str
    size: int
    offset: int


def _octal(value: int, width: int) -> bytes:
    return ("%0*o" % (width - 1, value)).encode("ascii") + b"\x00"


def encode_header(name: str, size: int) -> bytes:
    raw = name.encode("utf-8")
    if not raw or len(raw) > 100 or b"\x00" in raw:
        raise ValueError(f"unusable archive name {name!r}")
    if size < 0 or size >= 8 ** 11:
        raise ValueError("size out of range")
    head = bytearray(BLOCK)
    head[0:len(raw)] = raw
    head[100:108] = b"0000644\x00"
    head[108:116] = b"0000000\x00"
    head[116:124] = b"0000000\x00"
    head[124:136] = _octal(size, 12)
    head[136:148] = b"00000000000\x00"
    head[148:156] = b" " * 8
    head[156:157] = b"0"
    head[257:263] = b"ustar\x00"
    head[263:265] = b"00"
    head[329:337] = b"0000000\x00"
    head[337:345] = b"0000000\x00"
    checksum = sum(head)
    head[148:156] = ("%06o" % checksum).encode("ascii") + b"\x00 "
    return bytes(head)


def write_tar(files: Mapping[str, bytes]) -> bytes:
    """The canonical archive of ``files`` (path to bytes), entries sorted by path."""
    out = bytearray()
    for name in sorted(files):
        data = files[name]
        out += encode_header(name, len(data))
        out += data
        out += b"\x00" * (-len(data) % BLOCK)
    out += b"\x00" * (2 * BLOCK)
    out += b"\x00" * (-len(out) % RECORD)
    return bytes(out)


def _parse_size(field: bytes):
    if len(field) != 12 or field[11:12] != b"\x00" or not field[:11].isdigit() or any(c > 0x37 for c in field[:11]):
        return None
    return int(field[:11].decode("ascii"), 8)


def scan_tar(fh: BinaryIO, total: int, limits: Limits = DEFAULT_LIMITS) -> Tuple[List[ArchiveEntry], List[Tuple[str, str, str]]]:
    """Walk the archive headers. Returns the entries and problems as (code, path, message). Never reads entry data."""
    entries: List[ArchiveEntry] = []
    problems: List[Tuple[str, str, str]] = []
    pos = 0
    ended = False
    previous = None
    while pos < total:
        fh.seek(pos)
        block = fh.read(BLOCK)
        if len(block) < BLOCK:
            problems.append(("ARCHIVE_TRUNCATED", "", "the archive ends inside a header block"))
            return entries, problems
        if block == b"\x00" * BLOCK:
            fh.seek(pos + BLOCK)
            second = fh.read(BLOCK)
            if second != b"\x00" * BLOCK:
                problems.append(("ARCHIVE_NONCANONICAL", "", "the end-of-archive marker is not two zero blocks"))
                return entries, problems
            end = pos + 2 * BLOCK
            padded = end + (-end % RECORD)
            if total != padded:
                problems.append(("ARCHIVE_NONCANONICAL", "", "data or padding follows the end-of-archive marker"))
            else:
                fh.seek(end)
                rest = fh.read(total - end)
                if rest.strip(b"\x00"):
                    problems.append(("ARCHIVE_NONCANONICAL", "", "data follows the end-of-archive marker"))
            ended = True
            break
        raw_name = block[0:100].split(b"\x00", 1)[0]
        size = _parse_size(block[124:136])
        try:
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            problems.append(("ARCHIVE_NONCANONICAL", "", "an entry name is not valid UTF-8"))
            return entries, problems
        if size is None or not raw_name or block != encode_header(name, size):
            problems.append(("ARCHIVE_NONCANONICAL", name, "the entry header is not the canonical regular-file header (type, owner, time, mode, links, extended headers)"))
            return entries, problems
        if previous is not None and name == previous:
            problems.append(("DUPLICATE_PATH", name, "the archive holds two entries with this name"))
        elif previous is not None and name < previous:
            problems.append(("ARCHIVE_ORDER", name, "entries are not sorted by path"))
        previous = name
        data_start = pos + BLOCK
        if data_start + size > total:
            problems.append(("ARCHIVE_TRUNCATED", name, "the entry data extends past the end of the archive"))
            return entries, problems
        entries.append(ArchiveEntry(name, size, data_start))
        if len(entries) > limits.max_files:
            problems.append(("TOO_MANY_FILES", "", f"more than {limits.max_files} entries"))
            return entries, problems
        pos = data_start + size + (-size % BLOCK)
    if not ended:
        problems.append(("ARCHIVE_NONCANONICAL", "", "the end-of-archive marker is missing"))
    return entries, problems
