# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Bundle path rules. A path is relative, uses ``/`` only, is NFC, and every component passes the character rules below. The character
rules are what refuse a backslash, a colon (drive letters, alternate streams), a space, a wildcard and any control or format character."""
from __future__ import annotations

import re
import unicodedata
from typing import List, Optional, Tuple

from .constants import DEFAULT_LIMITS, Limits

_ASCII_OK = re.compile(r"^[A-Za-z0-9._@+=,-]+$")
_RESERVED = frozenset({"con", "prn", "aux", "nul", "conin$", "conout$", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))})


def _component_problem(comp: str, limits: Limits) -> Optional[Tuple[str, str]]:
    if comp in ("", ".", ".."):
        return ("PATH_TRAVERSAL" if comp == ".." else "PATH_UNSAFE", f"component {comp!r} is not allowed")
    if len(comp.encode("utf-8")) > limits.max_component_bytes:
        return ("PATH_TOO_LONG", f"a path component is longer than {limits.max_component_bytes} bytes")
    if comp.endswith(".") or comp.startswith("."):
        return ("PATH_UNSAFE", "a component may not start or end with a dot")
    if comp.split(".")[0].lower() in _RESERVED:
        return ("PATH_UNSAFE", "a component is a reserved device name")
    if not _ASCII_OK.match(comp):
        for ch in comp:
            if ord(ch) < 128:
                if not _ASCII_OK.match(ch):
                    return ("PATH_UNSAFE", f"character U+{ord(ch):04X} is not allowed in a path")
            else:
                cat = unicodedata.category(ch)
                if cat[0] not in ("L", "N", "M"):
                    return ("PATH_UNSAFE", f"character U+{ord(ch):04X} ({cat}) is not allowed in a path")
    return None


def path_problems(path: object, limits: Limits = DEFAULT_LIMITS) -> List[Tuple[str, str]]:
    """Every rule the path breaks, as (code, message). An empty list means the path is acceptable."""
    if not isinstance(path, str):
        return [("PATH_UNSAFE", "a path must be a string")]
    if path == "":
        return [("PATH_UNSAFE", "empty path")]
    try:
        encoded = path.encode("utf-8")
    except UnicodeEncodeError:
        return [("PATH_UNSAFE", "a path holds a lone surrogate")]
    problems: List[Tuple[str, str]] = []
    if len(encoded) > limits.max_path_bytes:
        problems.append(("PATH_TOO_LONG", f"path is longer than {limits.max_path_bytes} bytes"))
    if "\x00" in path:
        problems.append(("PATH_UNSAFE", "path holds a NUL byte"))
    if path.startswith("/"):
        problems.append(("PATH_ABSOLUTE", "path is absolute"))
    if unicodedata.normalize("NFC", path) != path:
        problems.append(("PATH_NOT_NFC", "path is not in Unicode normalisation form NFC"))
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
    """The key under which two paths collide on a case-insensitive or normalisation-insensitive file system."""
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", path).casefold())
