#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Neutral-wording guard: fail when a tracked file (its path or its text) carries a term from a deny-list.

The deny-list holds terms that describe how work around this repository is organised rather than what the repository does
(internal programme names, benchmark-handling jargon, names of repositories that are not published). It is stored only as SHA-256
digests of normalised phrases, so this file does not contain the terms it forbids.

How a term is found: the text is normalised (Unicode NFKC, lower case), cut into tokens (runs of ASCII letters and digits, so
``Some-Term``, ``some_term`` and ``some term`` give the same tokens) and every run of 1 to ``MAX_WORDS`` consecutive tokens is
hashed as the tokens joined by one space. A line break between two tokens does not hide a phrase. A hit is reported as
``path:line: deny-list entry <first 12 hex digits>``; the term itself is never printed.

Allow-list: ``tools/neutral_wording_allow.txt``. One entry per line, ``<path glob> <12 hex digits of the entry> <reason>``; the
reason is required, blank lines and lines starting with ``#`` are ignored. An entry silences exactly that deny-list entry in the
files its glob matches. An entry that silences nothing is itself a failure (``stale``), so the list cannot outlive its need.

Usage: ``python tools/check_neutral_wording.py [ROOT]`` (exit status 1 on any hit or stale entry).
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Set, Tuple

#: SHA-256 (hex) of each normalised phrase: lower-case tokens joined by one space. To add a term, add the digest of its phrase.
DENY_DIGESTS = frozenset({
    "02177e160ea7b4ebbc61424a616c6c584cea83e322e99c33f6544024ddbba4d2",
    "2b10959f132a5f564cd6dc03ab2867eec56e0a02c9450219091d1489576ba294",
    "2b8c33ee1ad4fbed8ebe53c755c493fdfbc8c2b416ab36250f7c2005b1eb1700",
    "30c512a03284e28ede83ca8faca15fdbf5f66af404087d7b14a06b0206c188da",
    "5721674bd38302f0556fb2ddeefa80dd35330087c271a8bb2e8228c98abdb52c",
    "5c12f274931dc1dd2f4052ea4623e4e462de10f4279e31d4201388cada455d01",
    "5eed15bb2b8cb35c07ebffd92491fa040b99f683ae77239cba78dee840555072",
    "61cd7e0130a4cce43d0cc98dcc80c894d31778dfbdcc8824e20848d13c2ec20f",
    "65127d42d8413630fbb90d17acd6017f85e976199fa1e8ba72fcc0f79f9fc846",
    "67e6ee84f91feb3a627a7ddf062ebfd89acdb428d3f492030c53c8372c373c85",
    "681314dd42bb7e307d7e953a96120f3da30e913bf4c40e4731ca5f5e7100e0dc",
    "6d578e84b99864e84b31fe4cb6fd9e1079acf89a57de820cfe36508b9096c351",
    "74a16930bd873fff0019f49cd0c7214388485db1d2df485d3f7299110db170e7",
    "815e0c49532226c1986b8096cdfa0c348d787a82401930097202c9c0c4201d91",
    "8763d6d7d632cc1152a7fbd565197c429bf5222b4cbca4c11f315b0f83d8074c",
    "8c0e6dd06de96fa88c8e427c2643e70040d43ba209489f26ceef9348109e81b1",
    "9574fe033031d9211da4deb495d926a2f8283642d011dea325fe167b457fc03b",
    "96f2a5c4575a09decd35e89aabe0e95c9151294273de50bc94fff566f10f8653",
    "ae4b170edbc6e89562da754f3e1c69cb4008fc15be9eeaa315b253a9fd623e91",
    "b57863b39ec8634b322adfe335472684374aee3c4a59224ee6cb2734bd41a96b",
    "becc733dd04ac2dd7cd6c657fb30741ed931ffe8754afebccdcd24714e2ba09f",
    "c242e07b963fadb83148692de8470a99422cf02e55e45db13d9f2b00a5e274a0",
    "ce047bfc9f5e72a2c4407550ae5e441b01dcad724d117f9a17bf5d7925a156ec",
    "cfdd69fc3feb828e697089d40d76d59611c5bbe0e0c001fbfce9ed40ce916b2c",
    "d5b1076ae59ef797a9240be443065a2fdafe5e13d354e3efecb573f82b8a114e",
    "d8a1e6aa519acffd61a09c1df06e7403648837bb7314b5272472cb5d44048838",
    "de50d9cebc14057bd4ecdcfab0005f9e693d3656ed2609b6788436c5210b14bd",
    "df16c1c51be8437dd9b3608a3acac00ab25f1395a91265780f3793926b9c47fe",
    "e06456b38f7d95eb28aced8bc281d60add0380f562eb99c17905e19c7e86bbca",
    "ebb47c501ab0917ac8194a6a3fff89dc5a9039a2400e64361f26a7ea862c4d89",
    "ed0bd5db23add5771d0c9f6802e0cfe9fc403a136fa15375d63b47371fe0317b",
    "ee630a85703b596b1c0466955c9b29fa2750b6f72f2190ad1ec727996bc6b0ff",
    "f5edcf1f3f205d249fba116b03f67fa3fa0ffc92411c80fceaf750af20343dd6",
    "f71ea0d087f173c94f5edbe01761d6ef511bf673c0c4743a7f94f3b6a6f6902b",
})
MAX_WORDS = 4
MAX_FILE_BYTES = 4 * 1024 * 1024
ALLOWLIST = Path(__file__).with_name("neutral_wording_allow.txt")
SKIP_PARTS = frozenset({".git", ".pinned", "__pycache__", "node_modules"})
_TOKEN = re.compile(r"[a-z0-9]+")


class Hit(NamedTuple):
    path: str
    line: int          # 0 when the term is in the path itself
    digest: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: deny-list entry {self.digest[:12]}"


class AllowEntry(NamedTuple):
    glob: str
    prefix: str
    reason: str
    lineno: int


def _tokens(text: str) -> List[Tuple[str, int]]:
    """``(token, line number)`` for every token of ``text``."""
    out: List[Tuple[str, int]] = []
    for n, line in enumerate(unicodedata.normalize("NFKC", text).lower().splitlines(), 1):
        out.extend((t, n) for t in _TOKEN.findall(line))
    return out


def find_terms(text: str, deny: Iterable[str] = DENY_DIGESTS) -> List[Tuple[int, str]]:
    """``(line, digest)`` of every deny-listed phrase in ``text``; the line is the one the phrase starts on."""
    deny = frozenset(deny)
    toks = _tokens(text)
    found: List[Tuple[int, str]] = []
    for i in range(len(toks)):
        for n in range(1, MAX_WORDS + 1):
            if i + n > len(toks):
                break
            d = hashlib.sha256(" ".join(t for t, _ in toks[i:i + n]).encode("utf-8")).hexdigest()
            if d in deny:
                found.append((toks[i][1], d))
    return found


def tracked_files(root: Path) -> List[str]:
    """Relative paths of the files git tracks under ``root`` (every file below ``root`` when it is not a git checkout)."""
    try:
        r = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, timeout=60, check=True)
        names = [n.decode("utf-8", "surrogateescape") for n in r.stdout.split(b"\0") if n]
    except (OSError, subprocess.SubprocessError):
        names = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]
    return sorted(n for n in names if not SKIP_PARTS & set(Path(n).parts) and (root / n).is_file())


def load_allowlist(path: Path = ALLOWLIST) -> List[AllowEntry]:
    entries: List[AllowEntry] = []
    if not path.exists():
        return entries
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3 or not re.fullmatch(r"[0-9a-f]{12}", parts[1]) or not parts[2].strip():
            raise ValueError(f"{path.name}:{n}: an entry is '<path glob> <12 hex digits> <reason>' and the reason is required")
        entries.append(AllowEntry(parts[0], parts[1], parts[2].strip(), n))
    return entries


def scan(root: Path, files: Optional[Sequence[str]] = None, allow: Sequence[AllowEntry] = (), deny: Iterable[str] = DENY_DIGESTS
         ) -> Tuple[List[Hit], List[AllowEntry]]:
    """``(hits, stale allow-list entries)`` for the files (default: the tracked files) under ``root``."""
    deny = frozenset(deny)
    names = list(files) if files is not None else tracked_files(root)
    used: Set[int] = set()
    hits: List[Hit] = []

    def keep(path: str, digest: str) -> bool:
        ok = True
        for k, e in enumerate(allow):
            if fnmatch.fnmatchcase(path, e.glob) and digest.startswith(e.prefix):
                used.add(k)
                ok = False
        return ok

    for name in names:
        for _line, d in find_terms(name.replace("/", " ").replace(".", " "), deny):
            if keep(name, d):
                hits.append(Hit(name, 0, d))
        p = root / name
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        if b"\0" in data:
            continue
        for line, d in find_terms(data.decode("utf-8", "replace"), deny):
            if keep(name, d):
                hits.append(Hit(name, line, d))
    stale = [e for k, e in enumerate(allow) if k not in used]
    return hits, stale


def main(argv: Sequence[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[1]
    hits, stale = scan(root, allow=load_allowlist())
    for h in hits:
        print(h)
    for e in stale:
        print(f"{ALLOWLIST.name}:{e.lineno}: stale allow-list entry (it silences nothing)")
    if hits or stale:
        print(f"neutral wording: {len(hits)} hit(s), {len(stale)} stale allow-list entr(y/ies)")
        return 1
    print(f"OK neutral wording: {len(tracked_files(root))} tracked files, {len(DENY_DIGESTS)} deny-list entries")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
