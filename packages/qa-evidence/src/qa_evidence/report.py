# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Run report: assembly helpers and the semantic checks that a schema cannot express.

The report keeps two kinds of result apart. ``lanes[].native`` (and ``native_status`` on a result) is what an engine reported, in the
``NATIVE_*`` vocabulary. ``accounting.results[].verdict`` and ``verdict`` are produced by the independent verifier, in the
``VERIFIED / FAILED / INCONCLUSIVE / UNACCOUNTED`` vocabulary, each with provenance (verifier, version, assertion digest, evidence digest).
Nothing here converts one into the other.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .canon import digest_of, dumps_canonical
from .constants import (COMPLETING_STATUSES, LIMITATION_TEXTS, REASON_CODES, REQUIRED_LIMITATION_IDS, REPORT_SCHEMA, RUN_REASONS,
                        SCHEMA_VERSION)

Problem = Tuple[str, str, str]


def assertion_rows(assertions: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """The frozen assertions as sorted rows: the content of assertion-lock.json."""
    return sorted(({"assertion_id": a["assertion_id"], "digest": a["digest"], "lane_id": a["lane_id"]} for a in assertions),
                  key=lambda r: (r["assertion_id"], r["lane_id"], r["digest"]))


def assertion_lock_bytes(assertions: Iterable[Mapping[str, Any]]) -> bytes:
    """Bytes of assertion-lock.json. Its sha256 is the assertion-set digest (and, in this format version, the plan digest)."""
    return dumps_canonical(assertion_rows(assertions))


def assertion_set_digest(assertions: Iterable[Mapping[str, Any]]) -> str:
    """Digest of the frozen assertion list: canonical JSON of the entries sorted by (assertion_id, lane_id, digest)."""
    return digest_of(assertion_rows(assertions))


def evidence_set_digest(results: Iterable[Mapping[str, Any]]) -> str:
    """Digest of what each verdict was based on: canonical JSON of [assertion_id, evidence digest or null] sorted by assertion id."""
    rows = []
    for r in results:
        prov = r["verdict"]["provenance"]
        ev = None if prov is None or prov.get("evidence") is None else prov["evidence"]["digest"]
        rows.append([r["assertion_id"], ev])
    return digest_of(sorted(rows, key=lambda row: (row[0], row[1] or "")))


def compute_outcome(states: Sequence[str], frozen: int, lane_statuses: Sequence[str] = ()) -> str:
    """The run-level outcome from per-assertion verdict states and the lanes' native statuses.

    Any FAILED fails. Anything not VERIFIED (or nothing frozen) is inconclusive. A lane whose engine did not run to completion (error,
    timeout, unavailable, skipped) also makes the run inconclusive, whatever its assertions say; only NATIVE_PASS and NATIVE_FAIL count as
    completed (a NATIVE_FAIL lane whose assertions are all verified is shown as an engine/verifier disagreement)."""
    if "FAILED" in states:
        return "FAILED"
    if frozen == 0 or any(s != "VERIFIED" for s in states) or len(states) != frozen:
        return "INCONCLUSIVE"
    if any(s not in COMPLETING_STATUSES for s in lane_statuses):
        return "INCONCLUSIVE"
    return "VERIFIED"


def run_reason(outcome: str, states: Sequence[str], frozen: int, lane_statuses: Sequence[str] = ()) -> str:
    """The one reason code the run-level verdict must carry."""
    if outcome == "INCONCLUSIVE" and frozen > 0 and len(states) == frozen and all(s == "VERIFIED" for s in states):
        return "ENGINE_DID_NOT_COMPLETE"
    return RUN_REASONS[outcome][0]


def standard_limitations() -> List[Dict[str, str]]:
    return [{"id": k, "text": LIMITATION_TEXTS[k]} for k in REQUIRED_LIMITATION_IDS]


def assemble_report(*, run_id: str, started_at: str, finished_at: str, plan_digest: str, environment: Mapping[str, Any],
                    lanes: Sequence[Mapping[str, Any]], frozen: Sequence[Mapping[str, Any]], results: Sequence[Mapping[str, Any]],
                    verifier: Mapping[str, str], redaction: Optional[Mapping[str, Any]] = None,
                    extra_limitations: Sequence[Mapping[str, str]] = (), extensions: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Build a report whose digests, counts and outcome are computed, not asserted.

    ``frozen`` is a list of ``{assertion_id, lane_id, digest}``. ``results`` is a list of ``{assertion_id, native_status, state, reason_code,
    evidence}`` where ``evidence`` is ``{path, digest}`` or None; a frozen assertion with no result is recorded as UNACCOUNTED. Lane
    entries are passed through as given (``lane_id, run_id, engine, native``)."""
    by_id = {r["assertion_id"]: r for r in results}
    entries = []
    for a in sorted(frozen, key=lambda a: a["assertion_id"]):
        r = by_id.get(a["assertion_id"])
        if r is None:
            entries.append({"assertion_id": a["assertion_id"], "lane_id": a["lane_id"], "native_status": None,
                            "verdict": {"state": "UNACCOUNTED", "reason_code": "NO_RESULT_RECORDED", "provenance": None}})
            continue
        provenance = {"verifier": dict(verifier), "assertion_digest": a["digest"], "evidence": dict(r["evidence"]) if r.get("evidence") else None}
        entries.append({"assertion_id": a["assertion_id"], "lane_id": a["lane_id"], "native_status": r.get("native_status"),
                        "verdict": {"state": r["state"], "reason_code": r["reason_code"], "provenance": provenance}})
    states = [e["verdict"]["state"] for e in entries]
    statuses = [x["native"]["status"] for x in lanes]
    outcome = compute_outcome(states, len(frozen), statuses)
    a_digest = assertion_set_digest(frozen)
    if plan_digest is None:
        raise ValueError("plan_digest is required: the digest of the frozen plan (in this format version, the assertion-set digest)")
    report: Dict[str, Any] = {
        "schema": REPORT_SCHEMA, "schema_version": SCHEMA_VERSION, "run_id": run_id, "started_at": started_at, "finished_at": finished_at,
        "plan_digest": plan_digest, "environment": dict(environment), "lanes": [dict(x) for x in lanes],
        "assertion_set": {"digest": a_digest, "assertions": sorted((dict(a) for a in frozen), key=lambda a: a["assertion_id"])},
        "accounting": {"frozen": len(frozen), "verified": states.count("VERIFIED"), "failed": states.count("FAILED"),
                       "inconclusive": states.count("INCONCLUSIVE"), "unaccounted": states.count("UNACCOUNTED"), "results": entries},
        "verdict": {"outcome": outcome, "reason_code": run_reason(outcome, states, len(frozen), statuses),
                    "provenance": {"verifier": dict(verifier), "plan_digest": plan_digest, "assertion_set_digest": a_digest,
                                   "evidence_set_digest": evidence_set_digest(entries)}},
        "redaction": dict(redaction) if redaction is not None else {"applied": False, "rules": [], "notes": []},
        "limitations": standard_limitations() + [dict(x) for x in extra_limitations],
    }
    if extensions:
        report["extensions"] = dict(extensions)
    return report


def _native_problems(lane: Mapping[str, Any]) -> List[str]:
    native = lane["native"]
    out = []
    counts, code = native.get("counts"), native["exit_code"]
    if native["status"] == "NATIVE_PASS":
        if counts is not None and (counts["failed"] or counts["errored"]):
            out.append("a passing lane reports failed or errored tests")
        if code not in (0, None):
            out.append(f"a passing lane has exit code {code}")
    elif native["status"] == "NATIVE_FAIL":
        if code == 0:
            out.append("a failing lane has exit code 0")
        if counts is not None and not (counts["failed"] or counts["errored"]):
            out.append("a failing lane reports no failed or errored test")
    return out


def check_report(report: Mapping[str, Any]) -> List[Problem]:
    """Semantic checks over a report that already passed the schema. Returns (code, pointer, message)."""
    out: List[Problem] = []
    lanes = report["lanes"]
    lane_ids = [x["lane_id"] for x in lanes]
    run_ids = [x["run_id"] for x in lanes]
    folded_lanes = [x.lower() for x in lane_ids]
    for i, x in enumerate(lanes):
        if lane_ids.count(x["lane_id"]) > 1:
            out.append(("DUPLICATE_LANE_ID", f"/lanes/{i}/lane_id", f"lane id {x['lane_id']!r} is used more than once"))
        elif folded_lanes.count(x["lane_id"].lower()) > 1:
            out.append(("DUPLICATE_ID_CASE", f"/lanes/{i}/lane_id", f"lane id {x['lane_id']!r} differs from another lane id only in case"))
        if run_ids.count(x["run_id"]) > 1:
            out.append(("DUPLICATE_RUN_ID", f"/lanes/{i}/run_id", f"lane run id {x['run_id']!r} is used more than once"))
        if x["run_id"] != f"{report['run_id']}.{x['lane_id']}":
            out.append(("LANE_RUN_ID_MISMATCH", f"/lanes/{i}/run_id", f"a lane run id must be <run id>.<lane id>, here {report['run_id']}.{x['lane_id']}"))
        for message in _native_problems(x):
            out.append(("NATIVE_STATUS_INCONSISTENT", f"/lanes/{i}/native", message))
        paths = [a["path"] for a in x["native"]["artifacts"]]
        for j, a in enumerate(x["native"]["artifacts"]):
            if paths.count(a["path"]) > 1:
                out.append(("DUPLICATE_ARTIFACT", f"/lanes/{i}/native/artifacts/{j}", f"artifact {a['path']!r} is listed twice in a lane"))
            if not a["path"].startswith(f"lanes/{x['lane_id']}/native/"):
                out.append(("NATIVE_ARTIFACT_LOCATION", f"/lanes/{i}/native/artifacts/{j}",
                            f"a native artifact of this lane must be under lanes/{x['lane_id']}/native/"))
    if report["started_at"] > report["finished_at"]:
        out.append(("TIME_ORDER", "/finished_at", "finished_at is before started_at"))
    if not report["redaction"]["applied"] and report["redaction"]["rules"]:
        out.append(("REDACTION_INCONSISTENT", "/redaction", "redaction is declared not applied but rules are listed"))

    frozen = report["assertion_set"]["assertions"]
    frozen_by_id: Dict[str, Mapping[str, Any]] = {}
    folded_ids = [a["assertion_id"].lower() for a in frozen]
    for i, a in enumerate(frozen):
        if a["assertion_id"] in frozen_by_id:
            out.append(("DUPLICATE_ASSERTION_ID", f"/assertion_set/assertions/{i}", f"assertion id {a['assertion_id']!r} is frozen twice"))
        elif folded_ids.count(a["assertion_id"].lower()) > 1:
            out.append(("DUPLICATE_ID_CASE", f"/assertion_set/assertions/{i}", f"assertion id {a['assertion_id']!r} differs from another only in case"))
        frozen_by_id[a["assertion_id"]] = a
        if a["lane_id"] not in lane_ids:
            out.append(("UNKNOWN_LANE", f"/assertion_set/assertions/{i}/lane_id", f"lane {a['lane_id']!r} is not a lane of this run"))
    for i, x in enumerate(lanes):
        if not any(a["lane_id"] == x["lane_id"] for a in frozen):
            out.append(("LANE_WITHOUT_ASSERTIONS", f"/lanes/{i}", f"lane {x['lane_id']!r} has no frozen assertion: a lane that accounts for nothing cannot be part of a verified run"))
    if assertion_set_digest(frozen) != report["assertion_set"]["digest"]:
        out.append(("ASSERTION_SET_DIGEST_MISMATCH", "/assertion_set/digest", "the digest does not match the frozen assertion list"))
    if report["plan_digest"] != report["assertion_set"]["digest"]:
        out.append(("PLAN_DIGEST_MISMATCH", "/plan_digest", "in this format version the plan digest is the digest of the frozen assertion set (assertion-lock.json)"))

    acc = report["accounting"]
    results = acc["results"]
    seen: Dict[str, int] = {}
    for i, r in enumerate(results):
        aid = r["assertion_id"]
        seen[aid] = seen.get(aid, 0) + 1
        if seen[aid] == 2:
            out.append(("ACCOUNTING_DUPLICATE", f"/accounting/results/{i}", f"assertion {aid!r} is accounted more than once"))
        if aid not in frozen_by_id:
            out.append(("ACCOUNTING_UNKNOWN", f"/accounting/results/{i}", f"assertion {aid!r} is not in the frozen set"))
            continue
        if frozen_by_id[aid]["lane_id"] != r["lane_id"]:
            out.append(("ACCOUNTING_LANE_MISMATCH", f"/accounting/results/{i}/lane_id", "the result names another lane than the frozen assertion"))
        v = r["verdict"]
        prov = v["provenance"]
        if v["reason_code"] not in REASON_CODES[v["state"]]:
            out.append(("REASON_CODE_STATE_MISMATCH", f"/accounting/results/{i}/verdict/reason_code",
                        f"the reason code {v['reason_code']!r} is not one of {list(REASON_CODES[v['state']])} for a {v['state']} verdict"))
        if v["state"] == "UNACCOUNTED":
            if prov is not None:
                out.append(("PROVENANCE_RULE", f"/accounting/results/{i}/verdict", "an UNACCOUNTED assertion was judged by nobody and has no provenance"))
            continue
        if prov is None:
            out.append(("PROVENANCE_RULE", f"/accounting/results/{i}/verdict", f"a {v['state']} verdict must carry provenance"))
            continue
        if v["state"] == "VERIFIED" and prov["evidence"] is None:
            out.append(("PROVENANCE_RULE", f"/accounting/results/{i}/verdict", "a VERIFIED verdict must name the evidence it was computed from"))
        if prov["assertion_digest"] != frozen_by_id[aid]["digest"]:
            out.append(("VERDICT_ASSERTION_DIGEST_MISMATCH", f"/accounting/results/{i}/verdict/provenance/assertion_digest",
                        "the verdict was not computed over the frozen assertion digest"))
        if prov["verifier"] != report["verdict"]["provenance"]["verifier"]:
            out.append(("VERIFIER_MISMATCH", f"/accounting/results/{i}/verdict/provenance/verifier", "the verifier differs from the run-level verdict's verifier"))
    for aid in frozen_by_id:
        if aid not in seen:
            out.append(("ACCOUNTING_MISSING", "/accounting/results", f"frozen assertion {aid!r} has no result (record it as UNACCOUNTED)"))
    states = [r["verdict"]["state"] for r in results]
    expect = {"frozen": len(frozen), "verified": states.count("VERIFIED"), "failed": states.count("FAILED"),
              "inconclusive": states.count("INCONCLUSIVE"), "unaccounted": states.count("UNACCOUNTED")}
    for key, value in expect.items():
        if acc[key] != value:
            out.append(("ACCOUNTING_COUNT_MISMATCH", f"/accounting/{key}", f"declared {acc[key]}, counted {value}"))

    verdict = report["verdict"]
    statuses = [x["native"]["status"] for x in lanes]
    outcome = compute_outcome(states, len(frozen), statuses)
    if verdict["outcome"] != outcome:
        out.append(("VERDICT_OUTCOME_MISMATCH", "/verdict/outcome", f"the outcome is not what the accounting and the lanes give ({outcome})"))
    if verdict["reason_code"] != run_reason(verdict["outcome"], states, len(frozen), statuses):
        out.append(("REASON_CODE_STATE_MISMATCH", "/verdict/reason_code",
                    f"the reason code {verdict['reason_code']!r} is not the one for the outcome {verdict['outcome']!r}"))
    if verdict["provenance"]["assertion_set_digest"] != report["assertion_set"]["digest"]:
        out.append(("VERDICT_ASSERTION_DIGEST_MISMATCH", "/verdict/provenance/assertion_set_digest", "the verdict is not bound to this assertion set"))
    if verdict["provenance"]["plan_digest"] != report["plan_digest"]:
        out.append(("PLAN_DIGEST_MISMATCH", "/verdict/provenance/plan_digest", "the verdict is not bound to this plan digest"))
    try:
        if verdict["provenance"]["evidence_set_digest"] != evidence_set_digest(results):
            out.append(("EVIDENCE_SET_DIGEST_MISMATCH", "/verdict/provenance/evidence_set_digest", "the verdict is not bound to the evidence the results name"))
    except (KeyError, TypeError):
        out.append(("EVIDENCE_SET_DIGEST_MISMATCH", "/verdict/provenance/evidence_set_digest", "the results cannot be digested"))

    ids = [x["id"] for x in report["limitations"]]
    for need in REQUIRED_LIMITATION_IDS:
        if need not in ids:
            out.append(("LIMITATION_MISSING", "/limitations", f"the required limitation {need!r} is missing"))
    for i, x in enumerate(report["limitations"]):
        if ids.count(x["id"]) > 1:
            out.append(("LIMITATION_DUPLICATE", f"/limitations/{i}", f"limitation id {x['id']!r} is used twice"))
        if x["id"] in LIMITATION_TEXTS and x["text"] != LIMITATION_TEXTS[x["id"]]:
            out.append(("LIMITATION_ALTERED", f"/limitations/{i}/text", f"the text of the required limitation {x['id']!r} was changed"))
    return out
