# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``canon-v1:<hex>`` <-> ``rcv1:<hex>``.

The two hash spellings carry the same 64 lowercase hex digits for equal payloads; only the algorithm prefix differs.
This module is the single place the prefix is mapped. It never computes a digest: each side computes its own, and the
bridge compares them (``HashDisagreement`` on any difference).
"""
from __future__ import annotations

import re
from typing import Any

from .errors import HashFormatError

NEUTRAL_PREFIX = "canon-v1:"
CONTRACTS_PREFIX = "rcv1:"
_HEX = r"[0-9a-f]{64}"
_NEUTRAL = re.compile(re.escape(NEUTRAL_PREFIX) + _HEX)
_CONTRACTS = re.compile(re.escape(CONTRACTS_PREFIX) + _HEX)


def is_neutral_hash(value: Any) -> bool:
    return isinstance(value, str) and _NEUTRAL.fullmatch(value) is not None


def is_contracts_hash(value: Any) -> bool:
    return isinstance(value, str) and _CONTRACTS.fullmatch(value) is not None


def to_contracts_hash(neutral_hash: str) -> str:
    """``canon-v1:<hex>`` -> ``rcv1:<hex>``. Anything else is refused (an already-mapped value is not accepted)."""
    if not is_neutral_hash(neutral_hash):
        raise HashFormatError("not a canon-v1:<64 lowercase hex> hash")
    return CONTRACTS_PREFIX + neutral_hash[len(NEUTRAL_PREFIX):]


def to_neutral_hash(contracts_hash: str) -> str:
    """``rcv1:<hex>`` -> ``canon-v1:<hex>``."""
    if not is_contracts_hash(contracts_hash):
        raise HashFormatError("not an rcv1:<64 lowercase hex> hash")
    return NEUTRAL_PREFIX + contracts_hash[len(CONTRACTS_PREFIX):]


def digest_of(hash_text: str) -> str:
    """The 64 hex digits of either spelling."""
    if is_neutral_hash(hash_text):
        return hash_text[len(NEUTRAL_PREFIX):]
    if is_contracts_hash(hash_text):
        return hash_text[len(CONTRACTS_PREFIX):]
    raise HashFormatError("not a canon-v1: or rcv1: hash (64 lowercase hex digits required)")


def same_digest(a: str, b: str) -> bool:
    """True when both hashes carry the same digest. Malformed input is refused, never reported as unequal."""
    return digest_of(a) == digest_of(b)
