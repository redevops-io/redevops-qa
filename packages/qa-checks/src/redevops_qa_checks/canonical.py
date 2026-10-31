# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Plain-JSON helpers: strict canonical bytes and ``sha256:<64 hex>`` digests.

The check library's own serialisation (program source bundles, content digests, evidence bytes). Floats, non-string keys and
non-JSON types are refused, so a value that hashes here also canonicalises under the harness ``canon-v1`` rules (the adapter
computes the ``rcv1`` reference with the harness module). Sets are not accepted: order must come from the data.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Mapping
from typing import Any

from .errors import OutputRefused

MAX_DEPTH = 64


def _plain(value: Any, depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        raise OutputRefused("value is nested too deeply")
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is str:
        return unicodedata.normalize("NFC", value)
    if type(value) is float:
        raise OutputRefused("floats are not allowed in an observed value; use integers or decimal strings")
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            if type(key) is not str:
                raise OutputRefused(f"object keys must be strings, got {type(key).__name__}")
            nkey = unicodedata.normalize("NFC", key)
            if nkey in out:
                raise OutputRefused(f"duplicate key after normalisation: {nkey!r}")
            out[nkey] = _plain(item, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [_plain(v, depth + 1) for v in value]
    raise OutputRefused(f"type {type(value).__name__} is not plain JSON")


def to_plain(value: Any) -> Any:
    """Deep copy into plain ``dict`` / ``list`` / ``str`` / ``int`` / ``bool`` / ``None`` (refuses anything else)."""
    return _plain(value)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(_plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def json_digest(value: Any) -> str:
    return sha256_ref(canonical_bytes(value))
