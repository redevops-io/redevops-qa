# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Failure type and the per-run evidence registry of the conformance suite."""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class ConformanceFailure(AssertionError):
    """A conformance item failed. ``code`` is stable; ``details`` is plain data with the concrete mismatch (the two
    hashes, the two member lists, the two codes)."""

    def __init__(self, code: str, message: str, /, **details: Any) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details: Dict[str, Any] = details


def fail(code: str, message: str, /, **details: Any) -> None:
    raise ConformanceFailure(code, message, **details)


class Evidence:
    """What a run records besides pytest outcomes: per-vector hash results and the schema id table."""

    def __init__(self) -> None:
        self.vectors: Dict[tuple, Dict[str, Any]] = {}
        self.schemas: Optional[List[Dict[str, Any]]] = None
        self.schema_info: Dict[str, Any] = {}
        self.not_applicable: Dict[tuple, Dict[str, Any]] = {}

    def vector(self, vector_id: str, source: str, canon_v1_hash: str, rcv1_hash: str, golden_hash: str,
               equal: bool) -> None:
        self.vectors[(source, vector_id)] = {"vector_id": vector_id, "source": source, "canon_v1_hash": canon_v1_hash,
                                             "rcv1_hash": rcv1_hash, "golden_hash": golden_hash, "equal": bool(equal)}

    def sorted_vectors(self) -> List[Dict[str, Any]]:
        return [self.vectors[k] for k in sorted(self.vectors)]


EVIDENCE = Evidence()


def reset_evidence() -> None:
    global EVIDENCE
    EVIDENCE.vectors.clear()
    EVIDENCE.schemas = None
    EVIDENCE.schema_info = {}
    EVIDENCE.not_applicable.clear()
