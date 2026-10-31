# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Two reporting views over the results of one run: the full view and the Playwright-only view.

Both are pure functions of the same ``RunData`` (the assertion results of a single run, immutable, with a digest). Neither takes an
adapter, runs anything, reads a file or writes one: a view is never a second run. The Playwright-only view is exactly the rows of
the full view whose ``executor`` is ``PLAYWRIGHT``; the totals reconcile (Playwright rows + script rows + rows with an executor
this version does not know = all rows) and ``reconciliation`` says so as data. An executor value that is not known is listed in
the full view as non-certifying and in no executor-specific view. Results of different assertion sets are refused: one run, one
assertion set, and nothing here pools two runs.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .canonical import canonical_bytes, sha256_ref, to_plain
from .errors import CheckError

KNOWN_EXECUTORS = ("PLAYWRIGHT", "SCRIPT")
VIEW_SCHEMA = "qa-checks/run-view/1"


class ViewRefused(CheckError):
    code = "VIEW_REFUSED"


def _plain_result(r: Any) -> Dict[str, Any]:
    data = r.to_json() if hasattr(r, "to_json") and callable(r.to_json) else r
    if not isinstance(data, Mapping):
        raise ViewRefused("a result is a mapping or a record with to_json")
    return to_plain(data)


@dataclass(frozen=True)
class RunData:
    """The results of one run, as plain rows sorted by ``assertion_id``, plus an optional manifest and executor map."""
    rows: Tuple[Mapping[str, Any], ...]
    assertion_set_hash: str
    declared: Tuple[str, ...] = ()
    executed: Tuple[str, ...] = ()
    skipped: Tuple[Mapping[str, str], ...] = ()
    declared_executors: Tuple[Tuple[str, str], ...] = ()

    @property
    def digest(self) -> str:
        return sha256_ref(canonical_bytes({"rows": list(self.rows), "set": self.assertion_set_hash, "declared": list(self.declared),
                                           "executed": list(self.executed), "skipped": list(self.skipped)}))


def run_data(results: Iterable[Any], *, manifest: Optional[Any] = None, assertions: Optional[Iterable[Any]] = None) -> RunData:
    """Build ``RunData`` from the results of one run. ``manifest`` is the run manifest (coverage lists); ``assertions`` the frozen
    assertion specs, used only to say which executor a declared-but-not-executed assertion has."""
    rows: List[Dict[str, Any]] = []
    seen = set()
    sets = set()
    for r in results:
        d = _plain_result(r)
        aid, ex = d.get("assertion_id"), d.get("executor")
        check = d.get("check") if isinstance(d.get("check"), Mapping) else {}
        verdict = check.get("verdict", d.get("verdict"))
        if type(aid) is not str or not aid or type(ex) is not str or type(verdict) is not str:
            raise ViewRefused("a result needs assertion_id, executor and a verdict")
        if aid in seen:
            raise ViewRefused("two results for one assertion in one run", assertion_id=aid)
        seen.add(aid)
        if d.get("assertion_set_hash") is not None:
            sets.add(d["assertion_set_hash"])
        rows.append({"assertion_id": aid, "executor": ex, "executor_known": ex in KNOWN_EXECUTORS, "verdict": verdict,
                     "reason_code": d.get("reason_code") if type(d.get("reason_code")) is str else "",
                     "requirement_ref": d.get("requirement_ref") if type(d.get("requirement_ref")) is str else "",
                     "evidence_refs": sorted(str(x) for x in (check.get("evidence_refs") or ())),
                     "actual_digest": d.get("actual_digest") if type(d.get("actual_digest")) is str else ""})
    if len(sets) > 1:
        raise ViewRefused("results of more than one assertion set are not one run", sets=len(sets))
    declared: Tuple[str, ...] = ()
    executed: Tuple[str, ...] = ()
    skipped: Tuple[Mapping[str, str], ...] = ()
    if manifest is not None:
        m = to_plain(manifest.to_json() if hasattr(manifest, "to_json") else manifest)
        declared = tuple(sorted(str(x) for x in m.get("assertions_declared") or ()))
        executed = tuple(sorted(str(x) for x in m.get("assertions_executed") or ()))
        skipped = tuple(sorted(({"assertion_id": str(x.get("assertion_id")), "reason_code": str(x.get("reason_code"))} for x in (m.get("assertions_skipped") or ())
                                if isinstance(x, Mapping)), key=lambda x: x["assertion_id"]))
        if m.get("assertion_set_hash") is not None:
            sets.add(m["assertion_set_hash"])
            if len(sets) > 1:
                raise ViewRefused("the manifest names another assertion set than the results")
    ex_map: Tuple[Tuple[str, str], ...] = ()
    if assertions is not None:
        pairs = []
        for a in assertions:
            d = _plain_result(a)
            if type(d.get("assertion_id")) is str and type(d.get("executor")) is str:
                pairs.append((d["assertion_id"], d["executor"]))
        ex_map = tuple(sorted(pairs))
    rows.sort(key=lambda r: r["assertion_id"])
    return RunData(rows=tuple(rows), assertion_set_hash=next(iter(sets), ""), declared=declared, executed=executed, skipped=skipped, declared_executors=ex_map)


def _totals(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    by_verdict: Dict[str, int] = {}
    by_executor: Dict[str, int] = {}
    for r in rows:
        by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + 1
        by_executor[r["executor"]] = by_executor.get(r["executor"], 0) + 1
    return {"total": len(rows), "by_verdict": {k: by_verdict[k] for k in sorted(by_verdict)}, "by_executor": {k: by_executor[k] for k in sorted(by_executor)}}


def _coverage(run: RunData, executor: Optional[str]) -> Dict[str, Any]:
    ex = dict(run.declared_executors)
    done = {r["assertion_id"] for r in run.rows}
    pick = (lambda aid: True) if executor is None else (lambda aid: ex.get(aid) == executor)
    declared = [a for a in run.declared if pick(a)]
    skipped = [s for s in run.skipped if pick(s["assertion_id"])]
    not_executed = [a for a in declared if a not in done]
    return {"manifest_present": bool(run.declared or run.executed or run.skipped), "declared": len(declared), "skipped": skipped,
            "declared_not_executed": not_executed, "executor_known_for_declared": bool(ex) if executor is not None else True}


def full_view(run: RunData) -> Dict[str, Any]:
    """Every result of the run, whatever its executor, with totals by verdict and by executor."""
    rows = [dict(r) for r in run.rows]
    return {"schema": VIEW_SCHEMA, "view": "full", "source_run_digest": run.digest, "assertion_set_hash": run.assertion_set_hash,
            "rows": rows, "totals": _totals(rows), "coverage": _coverage(run, None)}


def playwright_view(run: RunData) -> Dict[str, Any]:
    """Only the results whose executor is ``PLAYWRIGHT``: the subset of the full view, from the same run data."""
    rows = [dict(r) for r in run.rows if r["executor"] == "PLAYWRIGHT"]
    return {"schema": VIEW_SCHEMA, "view": "playwright-only", "source_run_digest": run.digest, "assertion_set_hash": run.assertion_set_hash,
            "rows": rows, "totals": _totals(rows), "coverage": _coverage(run, "PLAYWRIGHT")}


def script_view(run: RunData) -> Dict[str, Any]:
    rows = [dict(r) for r in run.rows if r["executor"] == "SCRIPT"]
    return {"schema": VIEW_SCHEMA, "view": "script-only", "source_run_digest": run.digest, "assertion_set_hash": run.assertion_set_hash,
            "rows": rows, "totals": _totals(rows), "coverage": _coverage(run, "SCRIPT")}


def reconciliation(run: RunData) -> Dict[str, Any]:
    """The two views checked against each other: same source run, the Playwright rows are a subset of the full rows, and the totals add up."""
    full, pw, sc = full_view(run), playwright_view(run), script_view(run)
    unknown = [r for r in full["rows"] if not r["executor_known"]]
    full_ids = {r["assertion_id"] for r in full["rows"]}
    problems: List[str] = []
    if not (full["source_run_digest"] == pw["source_run_digest"] == sc["source_run_digest"]):
        problems.append("views come from different run data")
    if not {r["assertion_id"] for r in pw["rows"]} <= full_ids:
        problems.append("a Playwright row is not in the full view")
    for r in pw["rows"]:
        if r not in full["rows"]:
            problems.append(f"row differs between views: {r['assertion_id']}")
    if pw["totals"]["total"] + sc["totals"]["total"] + len(unknown) != full["totals"]["total"]:
        problems.append("totals do not add up")
    manifest_gap: List[str] = []
    if run.executed and sorted(run.executed) != sorted(full_ids):
        manifest_gap = sorted(set(run.executed) ^ full_ids)
        problems.append("the manifest's executed set differs from the results")
    return {"reconciles": not problems, "problems": problems, "full_total": full["totals"]["total"], "playwright_total": pw["totals"]["total"],
            "script_total": sc["totals"]["total"], "unknown_executor_total": len(unknown), "manifest_executed_differs_on": manifest_gap,
            "source_run_digest": run.digest}


def assert_reconciles(run: RunData) -> None:
    r = reconciliation(run)
    if not r["reconciles"]:
        raise ViewRefused("the views do not reconcile: " + "; ".join(r["problems"]))
