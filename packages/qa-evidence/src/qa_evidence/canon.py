# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Canonical JSON, a strict loader, digests and text sanitising.

Canonical form: UTF-8, ASCII-only escapes, keys sorted, two-space indent, one trailing newline, no floats. The loader refuses what the
canonical form cannot represent or what is ambiguous: duplicate keys, floats, NaN and Infinity, a byte-order mark, lone surrogates and
nesting deeper than the cap. A manifest or report whose bytes are not exactly the canonical form of their own content is refused by the
verifier, so there is one byte sequence per document.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

from .constants import DEFAULT_LIMITS, Limits


class CanonError(ValueError):
    """A document cannot be read strictly. ``code`` is a stable identifier."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _pairs(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise CanonError("DUPLICATE_KEY", f"duplicate key {key!r}")
        seen[key] = value
    return seen


def _no_float(text):
    raise CanonError("FLOAT_REFUSED", f"numbers must be integers (got {text!r})")


def _no_constant(text):
    raise CanonError("CONSTANT_REFUSED", f"{text} is not allowed")


def _check_value(value: Any, depth: int, limits: Limits, counter: list) -> None:
    counter[0] += 1
    if counter[0] > limits.max_items:
        raise CanonError("TOO_MANY_ITEMS", f"more than {limits.max_items} JSON values")
    if depth > limits.max_json_depth:
        raise CanonError("TOO_DEEP", f"nesting deeper than {limits.max_json_depth}")
    if isinstance(value, str):
        if len(value) > limits.max_string_chars:
            raise CanonError("STRING_TOO_LONG", f"a string is longer than {limits.max_string_chars} characters")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise CanonError("BAD_UNICODE", "a string holds a lone surrogate") from None
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_value(key, depth + 1, limits, counter)
            _check_value(item, depth + 1, limits, counter)
    elif isinstance(value, list):
        for item in value:
            _check_value(item, depth + 1, limits, counter)


def loads_strict(data: bytes, limits: Limits = DEFAULT_LIMITS) -> Any:
    """Parse JSON bytes strictly (see the module text). Raises ``CanonError``."""
    if len(data) > limits.max_json_bytes:
        raise CanonError("JSON_TOO_LARGE", f"{len(data)} bytes exceeds the cap of {limits.max_json_bytes}")
    if data.startswith(b"\xef\xbb\xbf"):
        raise CanonError("BOM_REFUSED", "a byte-order mark is not allowed")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise CanonError("NOT_UTF8", "the document is not valid UTF-8") from None
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_constant)
    except CanonError:
        raise
    except RecursionError:
        raise CanonError("TOO_DEEP", "nesting is too deep") from None
    except ValueError as exc:
        raise CanonError("NOT_JSON", f"not valid JSON: {exc}") from None
    _check_value(value, 0, limits, [0])
    return value


def dumps_canonical(value: Any) -> bytes:
    """The canonical bytes of a JSON-compatible value (no floats)."""
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, separators=(",", ": "), allow_nan=False) + "\n").encode("ascii")


def is_canonical(data: bytes, value: Any) -> bool:
    return dumps_canonical(value) == data


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_of(value: Any) -> str:
    """Digest of the canonical bytes of a JSON value (used for the assertion-set and evidence-set digests)."""
    return sha256_bytes(dumps_canonical(value))


_STRIP = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def safe_text(value: Any, limit: int = 2000) -> str:
    """Render any value as one line of printable text: control, format (bidi, zero-width), separator and unassigned characters become
    visible ``\\uXXXX`` escapes, so a hostile string cannot move a cursor, hide text or reorder it in a terminal or a page."""
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, ensure_ascii=True)
    out = []
    for ch in text[:limit]:
        if unicodedata.category(ch) in _STRIP or ch in "  ":
            out.append("\\u%04x" % ord(ch) if ord(ch) < 0x10000 else "\\U%08x" % ord(ch))
        else:
            out.append(ch)
    if len(text) > limit:
        out.append("...")
    return "".join(out)
