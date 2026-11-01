# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Result objects of bundle verification. All of them convert to plain JSON (no floats) with ``to_json``."""
from __future__ import annotations

from typing import Any, Dict, List, NamedTuple, Optional

from .constants import (ANCHOR_ABSENT_NOTICE, ANCHOR_DECLARED_NOTICE, ANCHOR_MISMATCH_NOTICE, ANCHOR_VERIFIED_NOTICE, PLAN_ABSENT_NOTICE,
                        PLAN_INVALID_NOTICE, PLAN_MISMATCH_NOTICE, PLAN_VERIFIED_NOTICE)

ANCHOR_STATES = ("absent", "declared", "verified", "mismatch", "invalid")
PLAN_STATES = ("absent", "verified", "mismatch", "invalid")


class Finding(NamedTuple):
    code: str
    path: str
    message: str

    def to_json(self) -> Dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


class AnchorResult(NamedTuple):
    """The outcome of the external-anchor check.

    ``absent``    no anchor data and no supplied value: integrity against deliberate re-forging is NOT established.
    ``declared``  the bundle carries anchor.json (type, reference, digest) that matches the manifest, but no external value was supplied:
                  the sidecar can be rewritten with the bundle, so this is NOT established either.
    ``verified``  a supplied value equals the recomputed manifest digest. That is a MATCH with the supplied value; the tool does not know
                  where the value came from, and a digest taken from the bundle itself always matches.
    ``mismatch``  the supplied value, or the digest named in anchor.json, differs from the recomputed manifest digest.
    ``invalid``   the supplied value or anchor.json is malformed.
    """

    state: str
    anchor_type: Optional[str]
    reference: Optional[str]
    supplied: Optional[str]
    declared: Optional[str]
    recomputed: Optional[str]

    @property
    def matches(self) -> bool:
        """True only when a supplied value equals the recomputed manifest digest. Not a statement that the value can be trusted."""
        return self.state == "verified"

    @property
    def notice(self) -> str:
        return {"absent": ANCHOR_ABSENT_NOTICE, "declared": ANCHOR_DECLARED_NOTICE, "verified": ANCHOR_VERIFIED_NOTICE,
                "mismatch": ANCHOR_MISMATCH_NOTICE, "invalid": "the anchor value or anchor.json is malformed: integrity against deliberate re-forging NOT established"}[self.state]

    def to_json(self) -> Dict[str, Any]:
        return {"state": self.state, "matches_supplied_value": self.matches, "type": self.anchor_type, "reference": self.reference,
                "supplied_digest": self.supplied, "declared_digest": self.declared, "recomputed_manifest_digest": self.recomputed,
                "notice": self.notice}


class PlanResult(NamedTuple):
    """Whether the frozen assertion set was compared with a plan digest supplied from outside the bundle (``absent``: it was not)."""

    state: str
    supplied: Optional[str]
    declared: Optional[str]

    @property
    def matches(self) -> bool:
        return self.state == "verified"

    @property
    def notice(self) -> str:
        return {"absent": PLAN_ABSENT_NOTICE, "verified": PLAN_VERIFIED_NOTICE, "mismatch": PLAN_MISMATCH_NOTICE, "invalid": PLAN_INVALID_NOTICE}[self.state]

    def to_json(self) -> Dict[str, Any]:
        return {"state": self.state, "matches_supplied_value": self.matches, "supplied_digest": self.supplied, "declared_digest": self.declared,
                "notice": self.notice}


class VerifyResult(NamedTuple):
    findings: List[Finding]
    anchor: AnchorResult
    manifest_digest: Optional[str]
    informational: List[Dict[str, str]]
    notes: List[Dict[str, str]]
    file_count: int
    form: str
    complete: bool                                  # the manifest AND the report were read, parsed as objects and schema-valid
    plan: Optional[PlanResult] = None

    @property
    def internally_consistent(self) -> bool:
        return self.complete and not self.findings

    @property
    def ok(self) -> bool:
        return self.complete and not self.findings

    @property
    def assurance(self) -> str:
        if not self.ok:
            return "failed"
        return "matches-supplied-anchor" if self.anchor.matches else "internal-consistency-only"

    @property
    def assurance_notice(self) -> str:
        if self.findings:
            return "verification FAILED: " + "; ".join(sorted({f.code for f in self.findings}))
        if not self.complete:
            return "verification FAILED: the manifest and the report were not both read and validated"
        return self.anchor.notice

    def to_json(self) -> Dict[str, Any]:
        return {"schema": "qa-evidence/verify-result", "schema_version": "1.0", "form": self.form, "ok": self.ok, "complete": self.complete,
                "internally_consistent": self.internally_consistent, "assurance": self.assurance, "assurance_notice": self.assurance_notice,
                "anchor": self.anchor.to_json(), "plan": self.plan.to_json() if self.plan is not None else None,
                "manifest_digest": self.manifest_digest, "file_count": self.file_count,
                "findings": [f.to_json() for f in self.findings], "informational_fields": list(self.informational), "notes": list(self.notes)}
