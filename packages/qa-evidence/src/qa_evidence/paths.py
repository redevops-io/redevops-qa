# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Bundle path rules. A path is relative, uses ``/`` only and is ASCII: every component is made of ``A-Z a-z 0-9 . _ @ + = , -``.

ASCII only is deliberate. The accept/reject decision then never depends on the Unicode database of the interpreter that runs it (a
character that is unassigned in one Python version and assigned in the next would otherwise make one bundle verify on one host and fail
on another), and Unicode normalisation (NFC), case folding and confusable names stop being a question: an ASCII path is already NFC. The
character set is also what refuses a backslash, a colon (drive letters, alternate streams), a space, a wildcard and every control,
format or separator character.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .constants import DEFAULT_LIMITS, Limits

_ASCII_OK = re.compile(r"[A-Za-z0-9._@+=,-]+")
_RESERVED = frozenset({"con", "prn", "aux", "nul", "conin$", "conout$", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))})


def _component_problem(comp: str, limits: Limits) -> Optional[Tuple[str, str]]:
    if comp in ("", ".", ".."):
        return ("PATH_TRAVERSAL" if comp == ".." else "PATH_UNSAFE", f"component {comp!r} is not allowed")
    if len(comp.encode("utf-8", "replace")) > limits.max_component_bytes:
        return ("PATH_TOO_LONG", f"a path component is longer than {limits.max_component_bytes} bytes")
    if comp.endswith(".") or comp.startswith("."):
        return ("PATH_UNSAFE", "a component may not start or end with a dot")
    if comp.split(".")[0].lower() in _RESERVED:
        return ("PATH_UNSAFE", "a component is a reserved device name")
    if not _ASCII_OK.fullmatch(comp):
        if not comp.isascii():
            return ("PATH_NOT_ASCII", "a path may only contain ASCII letters, digits and . _ @ + = , -")
        return ("PATH_UNSAFE", "a path may only contain ASCII letters, digits and . _ @ + = , -")
    return None


def path_problems(path: object, limits: Limits = DEFAULT_LIMITS) -> List[Tuple[str, str]]:
    """Every rule the path breaks, as (code, message). An empty list means the path is acceptable."""
    if not isinstance(path, str):
        return [("PATH_UNSAFE", "a path must be a string")]
    if path == "":
        return [("PATH_UNSAFE", "empty path")]
    problems: List[Tuple[str, str]] = []
    if len(path.encode("utf-8", "replace")) > limits.max_path_bytes:
        problems.append(("PATH_TOO_LONG", f"path is longer than {limits.max_path_bytes} bytes"))
    if path.startswith("/"):
        problems.append(("PATH_ABSOLUTE", "path is absolute"))
    for comp in path.split("/"):
        found = _component_problem(comp, limits)
        if found is not None:
            problems.append(found)
    seen = set()
    unique = []
    for item in problems:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def fold_key(path: str) -> str:
    """The key under which two paths collide on a case-insensitive file system. Only ASCII letters fold."""
    return "".join(c.lower() if c < "\x80" else c for c in path)
