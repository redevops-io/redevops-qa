# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The divergence report: every failing conformance item, by check and name, with the concrete mismatch.

Failures are grouped into the divergences already known between the contracts text and the harness neutral module
(``KNOWN``) and everything else (``additional``). The grouping reads only the failure code, the item name and the failure
details, so a harness that has been aligned makes the matching group empty and the report says so.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from .items import CHECKS

KNOWN = {
    "K1": "action value digest: the harness digest of an action value differs from the normative value digest",
    "K2": "order of object sets: the harness sorts every object set by canonical text, contracts sort fixtures, "
          "step_results and assertion_results by their element key",
    "K3": "integrity refusal vocabulary: contracts define distinct refusal codes where the harness raises "
          "ASSERTION_HASH_MISMATCH (or has no code at all)",
    "K4": "recovery reason: the harness has no FaultRecovery.reason_code (nor the RecoveryReason vocabulary)",
}
K2_FIELDS = {"fixtures", "step_results", "assertion_results", "items", "gates", "resource_claims"}
PENDING = "P1"
PENDING_TEXT = ("harness vector files not yet aligned with the contracts vector files (a contracts golden change needs "
                "a matching harness vector change, ADR A.2.5 item 6)")


def classify(f: Dict[str, Any]) -> str:
    code, item, details = f["code"], f["item"], f.get("details", {})
    if code == "VALUE_DIGEST_DEFINITION":
        return "K1"
    if code == "SET_ORDER_DIVERGENCE":
        leaves = {path.rsplit(".", 1)[-1].split("[")[0] for path in details.get("differing_fields", [])}
        if details.get("differing_fields") is not None and leaves and leaves <= K2_FIELDS:
            return "K2"
        return "additional"
    if code == "INTEGRITY_CODE_VOCABULARY" or item.startswith("classification:") or (
            item == "error-vocabulary" and "ASSERTION" in json.dumps(details)):
        return "K3"
    if code == "REASON_CODE_PARITY":
        return "K4"
    if code == "FIELD_PARITY" and details.get("schema") == "FaultRecovery":
        diff = details.get("differences", {})
        if all(set(v.get("contracts_only", [])) <= {"reason_code"} and not v.get("neutral_only") for v in diff.values()):
            return "K4"
    if code == "VECTOR_SET_DRIFT":
        return PENDING
    return "additional"


def build_report(summary: Dict[str, Any], receipt: Dict[str, Any]) -> Dict[str, Any]:
    failures = []
    for t in summary["tests"]:
        if t["outcome"] != "failed":
            continue
        item = t["nodeid"].split("::", 1)[-1]
        item = item[item.index("[") + 1:-1] if "[" in item else item
        f = {"check": t["check"], "check_name": CHECKS.get(t["check"], t["check"]), "item": item, "code": t["code"],
             "message": t["message"], "details": t["details"]}
        f["group"] = classify(f)
        failures.append(f)
    groups: Dict[str, List[Dict[str, Any]]] = {k: [] for k in [*KNOWN, PENDING, "additional"]}
    for f in failures:
        groups[f["group"]].append(f)
    return {"report_schema": "redevops-qa/divergence-report", "report_version": "1",
            "result": receipt["result"], "receipt_hash": receipt["receipt_hash"], "pin_set": receipt["subjects"]["pin_set"],
            "subjects": {k: receipt["subjects"][k] for k in ("contracts", "harness_qa")},
            "collected_tests": receipt["collected_tests"], "failed_tests": receipt["failed_tests"],
            "groups": {k: {"description": KNOWN.get(k, PENDING_TEXT if k == PENDING else "failures outside the known set"),
                           "count": len(v), "failures": v} for k, v in groups.items()},
            "not_applicable": receipt.get("not_applicable", []),
            "checks": [{"check_id": c["check_id"], "name": c["name"], "status": c["status"], "failed": c["failed"],
                        "failure_codes": c["failure_codes"]} for c in receipt["checks"]]}


def _fmt(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def render_markdown(report: Dict[str, Any]) -> str:
    out = [f"# Divergence report ({report['pin_set']})", "",
           f"Receipt `{report['receipt_hash']}`, result **{report['result']}**, {report['collected_tests']} tests, "
           f"{report['failed_tests']} failed.", "",
           f"contracts: `{report['subjects']['contracts']['commit']}`; harness QA: `{report['subjects']['harness_qa']['commit']}`", "",
           "## Checks", ""]
    out.append("| check | name | status | failed | failure codes |")
    out.append("|---|---|---|---|---|")
    for c in report["checks"]:
        out.append(f"| {c['check_id']} | {c['name']} | {c['status']} | {c['failed']} | {', '.join(c['failure_codes'])} |")
    if report.get("not_applicable"):
        out += ["", "## Not applicable at this pin set", ""]
        for e in report["not_applicable"]:
            out.append(f"- {e['check_id']} `{e['item_id']}`: {e['reason']} (introduced in contracts `{e['introduced_in']}`; "
                       f"the item itself gives {e['real_item_result']})")
    for key, group in report["groups"].items():
        out += ["", f"## {key}: {group['description']}", "", f"{group['count']} failing item(s)."]
        for f in group["failures"]:
            out += ["", f"### {f['check']} {f['check_name']} / `{f['item']}` ({f['code']})", "", f["message"], ""]
            for k, v in sorted(f["details"].items()):
                out.append(f"- {k}: `{_fmt(v)}`")
    return "\n".join(out) + "\n"
