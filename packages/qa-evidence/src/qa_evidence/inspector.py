# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``inspect_bundle``: verify a bundle and summarise it for people. The summary is built only from the report as stored; a verdict is
never recomputed here, and the native result and the verdict are kept in separate keys."""
from __future__ import annotations

from typing import Any, Dict, List, NamedTuple, Optional

from .constants import DEFAULT_LIMITS, Limits
from .model import VerifyResult
from .report import engine_verifier_disagreements
from .sources import open_source
from .verify import Documents, verify_source


class Inspection(NamedTuple):
    verification: VerifyResult
    summary: Optional[Dict[str, Any]]
    content_trusted: bool
    files: List[Dict[str, Any]]

    def to_json(self) -> Dict[str, Any]:
        return {"schema": "qa-evidence/inspection", "schema_version": "1.0", "verification": self.verification.to_json(),
                "content_trusted": self.content_trusted, "summary": self.summary, "files": self.files}


def _disagreements(report) -> List[Dict[str, Any]]:
    return engine_verifier_disagreements(report)


def summarise(manifest: Optional[Dict[str, Any]], report: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if report is None:
        return None
    lanes = []
    for lane in report["lanes"]:
        counts = {"VERIFIED": 0, "FAILED": 0, "INCONCLUSIVE": 0, "UNACCOUNTED": 0}
        for r in report["accounting"]["results"]:
            if r["lane_id"] == lane["lane_id"]:
                counts[r["verdict"]["state"]] += 1
        lanes.append({"lane_id": lane["lane_id"], "run_id": lane["run_id"], "engine": dict(lane["engine"]),
                      "native": {"status": lane["native"]["status"], "raw_status": lane["native"]["raw_status"],
                                 "exit_code": lane["native"]["exit_code"], "counts": lane["native"].get("counts"),
                                 "artifacts": [dict(a) for a in lane["native"]["artifacts"]]},
                      "independent_verdicts": counts})
    acc = report["accounting"]
    return {
        "run_id": report["run_id"], "started_at": report["started_at"], "finished_at": report["finished_at"], "plan_digest": report["plan_digest"],
        "environment": dict(report["environment"]), "tools": dict(manifest["tools"]) if manifest else None,
        "lanes": lanes,
        "independent_verdict": {"outcome": report["verdict"]["outcome"], "reason_code": report["verdict"]["reason_code"],
                                "provenance": report["verdict"]["provenance"]},
        "accounting": {k: acc[k] for k in ("frozen", "verified", "failed", "inconclusive", "unaccounted")},
        "assertions": [{"assertion_id": r["assertion_id"], "lane_id": r["lane_id"], "native_status": r["native_status"],
                        "verdict": r["verdict"]} for r in acc["results"]],
        "engine_verifier_disagreements": _disagreements(report),
        "redaction": report["redaction"], "limitations": report["limitations"],
    }


def inspect_bundle(location: str, *, anchor: Optional[str] = None, plan_digest: Optional[str] = None, limits: Limits = DEFAULT_LIMITS) -> Inspection:
    """Verify and summarise. ``content_trusted`` is true only when verification found nothing; otherwise the summary is shown for
    diagnosis and must not be relied on. Raises ``SourceError`` when the location cannot be opened."""
    source = open_source(location, limits)
    try:
        result, docs = verify_source(source, anchor=anchor, plan_digest=plan_digest, limits=limits)
    finally:
        source.close()
    files = []
    if docs.manifest is not None:
        files = [dict(f) for f in docs.manifest["files"]]
    return Inspection(result, summarise(docs.manifest, docs.report), result.ok, files)
