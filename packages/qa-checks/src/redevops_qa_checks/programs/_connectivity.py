# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The connectivity-matrix evaluator: pure functions from observed probe results (data in) to matrix rows (observations out).

Nothing here says whether a result is wanted. Each row sets the probe's own result beside its control probe's result so a reader
can see whether a blocked probe was blocked while the control reached the same target, and says which kind of evidence it is."""
from __future__ import annotations

from ._cluster import section
from ._common import as_list, as_map, text

RESULTS = ("connected", "refused", "timeout", "unreachable", "error", "unsupported", "not_finished", "not_run")


def _declared(data):
    return {text(d.get("id")): d for d in section(data, "declared")}


def evaluate_matrix(data):
    """One row per declared probe from the probe and control results the traffic collector gathered."""
    declared = _declared(data)
    by = {}
    for p in section(data, "probe"):
        by[(text(p.get("id")), text(p.get("role")))] = p
    rows = []
    for pid in sorted(declared):
        d = declared[pid]
        probe, control = by.get((pid, "probe")), by.get((pid, "control"))
        result = text(as_map(probe).get("result")) if probe else "not_run"
        c_result = text(as_map(control).get("result")) if control else ""
        rows.append({"id": pid, "evidence": "traffic", "range_class": text(d.get("range_class")),
                     "source_namespace": text(d.get("source_namespace")), "target_kind": text(d.get("target_kind")),
                     "target_ip": text(d.get("target_ip")), "port": d.get("port"), "protocol": text(d.get("protocol")),
                     "synthetic_network": text(d.get("synthetic_network")), "result": result if result in RESULTS else "error",
                     "has_control": d.get("has_control") is True, "control_result": c_result if c_result in RESULTS else ("" if not c_result else "error"),
                     "control_reached_target": (c_result == "connected") if control else None})
    return rows


def matrix_counts(rows):
    counts = {"probes": len(rows)}
    for r in RESULTS:
        counts[r] = sum(1 for x in rows if x["result"] == r)
    counts["with_control"] = sum(1 for x in rows if x["has_control"])
    counts["controls_reached_target"] = sum(1 for x in rows if x["control_reached_target"] is True)
    counts["controls_did_not_reach_target"] = sum(1 for x in rows if x["control_reached_target"] is False)
    counts["synthetic_subnet_targets"] = sum(1 for x in rows if x["synthetic_network"])
    return counts


def evaluate_policy_state(data):
    declared = _declared(data)
    rows = []
    for s in sorted(section(data, "policy_state"), key=lambda x: text(x.get("id"))):
        d = declared.get(text(s.get("id")), {})
        deny = [{"policy": text(as_map(x).get("policy")), "namespace": text(as_map(x).get("namespace")), "via": text(as_map(x).get("via")),
                 "value": text(as_map(x).get("value"))} for x in as_list(s.get("egress_deny_matches"))]
        allow = [{"policy": text(as_map(x).get("policy")), "namespace": text(as_map(x).get("namespace")), "via": text(as_map(x).get("via")),
                  "value": text(as_map(x).get("value"))} for x in as_list(s.get("egress_allow_matches"))]
        rows.append({"id": text(s.get("id")), "evidence": "policy-state", "range_class": text(d.get("range_class")),
                     "source_namespace": text(s.get("source_namespace")), "target_ip": text(s.get("target_ip")), "port": s.get("port"),
                     "egress_deny_matches": deny, "egress_allow_matches": allow,
                     "selecting_policies": [text(x) for x in as_list(s.get("selecting_policies"))],
                     "default_deny_egress_selecting": s.get("default_deny_egress_selecting") is True,
                     "selector_understood": s.get("selector_understood") is True})
    return rows


def policy_counts(rows):
    return {"probes": len(rows), "with_egress_deny_match": sum(1 for r in rows if r["egress_deny_matches"]),
            "with_egress_allow_match": sum(1 for r in rows if r["egress_allow_matches"]),
            "selected_by_default_deny_egress": sum(1 for r in rows if r["default_deny_egress_selecting"]),
            "no_selecting_policy": sum(1 for r in rows if not r["selecting_policies"]),
            "selector_not_understood": sum(1 for r in rows if not r["selector_understood"])}
