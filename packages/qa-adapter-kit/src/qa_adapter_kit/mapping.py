# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""From native results to canonical assertions, without ever promoting a native PASS to an oracle PASS.

A framework's PASS says the framework's own check passed. It is evidence for a canonical assertion only when the request maps
that native test to the assertion explicitly *and* the test itself declares the same assertion id. A required assertion with no
such mapping is UNVERIFIED. Even a mapped native PASS leaves the canonical status UNVERIFIED until an independent verifier, not
the adapter, issues an ``OracleVerdict`` for exactly that evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from .errors import ModelError
from .models import AdapterResult, NativeAssertion, aggregate_status, digest
from .status import Status

_NATIVE_ORDER = (Status.ERROR, Status.FAIL, Status.UNKNOWN, Status.SKIP)


@dataclass(frozen=True)
class CanonicalEvidence:
    """What the native results say about one canonical assertion. ``native_status`` is native authority; ``oracle_status`` is
    constant: only ``canonical_status`` with a verdict can ever produce a PASS."""

    assertion_id: str
    run_id: str
    adapter_id: str
    native_ids: Tuple[str, ...]
    native_status: Status                 # PASS, FAIL, ERROR, SKIP, UNKNOWN as the framework reported, or UNVERIFIED when unmapped
    reasons: Tuple[str, ...] = ()
    oracle_status: Status = Status.UNVERIFIED
    basis: str = "native"

    def __post_init__(self) -> None:
        if self.oracle_status is not Status.UNVERIFIED or self.basis != "native":
            raise ModelError("evidence is native and unverified; only an OracleVerdict can change a canonical status")

    def digest(self) -> str:
        return digest({"assertion_id": self.assertion_id, "run_id": self.run_id, "adapter_id": self.adapter_id,
                       "native_ids": sorted(self.native_ids), "native_status": self.native_status})


@dataclass(frozen=True)
class MappingReport:
    evidence: Tuple[CanonicalEvidence, ...]
    unmapped_native: Tuple[str, ...]
    refused: Tuple[Tuple[str, str], ...]      # (native id, reason)


def map_to_canonical(result: AdapterResult, required_assertions: Sequence[str], mapping: Mapping[str, str]) -> MappingReport:
    """One ``CanonicalEvidence`` per required assertion. Nothing outside the required list gets evidence."""
    natives: Dict[str, NativeAssertion] = {a.native_id: a for a in result.native_assertions}
    refused: List[Tuple[str, str]] = []
    grouped: Dict[str, List[NativeAssertion]] = {}
    for native_id, canonical in mapping.items():
        native = natives.get(native_id)
        if native is None:
            refused.append((native_id, "the mapping names a native test the run did not report"))
        elif canonical not in required_assertions:
            refused.append((native_id, f"{canonical} is not a required assertion"))
        elif canonical not in native.declared_assertion_ids:
            refused.append((native_id, f"the test does not declare assertion id {canonical}"))
        else:
            grouped.setdefault(canonical, []).append(native)
    evidence = []
    for assertion_id in required_assertions:
        members = grouped.get(assertion_id)
        if not members:
            reasons = tuple(r for n, r in refused if mapping.get(n) == assertion_id) or ("no native test is mapped to this assertion",)
            evidence.append(CanonicalEvidence(assertion_id, result.run_id, result.adapter_id, (), Status.UNVERIFIED, reasons))
            continue
        evidence.append(CanonicalEvidence(assertion_id, result.run_id, result.adapter_id, tuple(m.native_id for m in members),
                                          aggregate_status(tuple(members)), ()))
    unmapped = tuple(sorted(set(natives) - {m.native_id for ms in grouped.values() for m in ms}))
    return MappingReport(tuple(evidence), unmapped, tuple(refused))


@dataclass(frozen=True)
class OracleVerdict:
    """A verdict from an independent verifier about one piece of evidence. The adapter cannot create one that is accepted: the
    verifier id must differ from the adapter's, and the verdict must cite the digest of the exact evidence it judged."""

    assertion_id: str
    verifier_id: str
    status: Status
    evidence_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.status, Status) or self.status is Status.UNVERIFIED:
            raise ModelError("a verdict is PASS, FAIL, ERROR, SKIP or UNKNOWN")
        if not self.verifier_id:
            raise ModelError("a verdict names its verifier")


def canonical_status(evidence: CanonicalEvidence, verdict: Optional[OracleVerdict] = None) -> Status:
    """UNVERIFIED unless an acceptable verdict exists. Native FAIL and ERROR are not upgraded either: they remain visible through
    ``evidence.native_status`` and the canonical status stays UNVERIFIED until a verifier rules."""
    if verdict is None:
        return Status.UNVERIFIED
    if verdict.assertion_id != evidence.assertion_id:
        raise ModelError("the verdict is about a different assertion")
    if verdict.evidence_digest != evidence.digest():
        raise ModelError("the verdict was issued for different evidence")
    if verdict.verifier_id == evidence.adapter_id or verdict.verifier_id.startswith(evidence.adapter_id):
        raise ModelError("an adapter cannot verify its own result")
    if not evidence.native_ids:
        raise ModelError("there is no native evidence for the verdict to judge")
    return verdict.status
