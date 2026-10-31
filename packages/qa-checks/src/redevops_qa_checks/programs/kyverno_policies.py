# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Kyverno policy objects present in the input: kind, name, action, background flag, rule names and rule types."""
from __future__ import annotations

from ._common import as_list, as_map, error_rows, text, counts_only

PROGRAM_ID = "manifest.kyverno-policies"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Kyverno policy presence and shape (kind, validation action, rule types, matched kinds)"
SUPPORT = ("programs/_common.py",)

KINDS = ("ClusterPolicy", "Policy", "ValidatingPolicy", "MutatingPolicy", "ImageValidatingPolicy", "GeneratingPolicy",
         "ClusterCleanupPolicy", "CleanupPolicy", "PolicyException")
GROUPS = ("kyverno.io/", "policies.kyverno.io/")


def _types(rule):
    out = []
    for key, name in (("validate", "validate"), ("mutate", "mutate"), ("generate", "generate"), ("verifyImages", "verifyImages")):
        if key in rule:
            out.append(name)
    return out


def _match_kinds(rule):
    block = as_map(rule.get("match"))
    parts = [block] + [as_map(x) for x in as_list(block.get("any"))] + [as_map(x) for x in as_list(block.get("all"))]
    kinds = []
    for part in parts:
        kinds += [text(k) for k in as_list(as_map(part.get("resources")).get("kinds"))]
    return sorted(set(kinds))


def run(data):
    rows = []
    for m in data.manifests:
        if m.kind not in KINDS or not m.api_version.startswith(GROUPS):
            continue
        spec = as_map(m.doc.get("spec"))
        rules = []
        for r in as_list(spec.get("rules")):
            rm = as_map(r)
            action = text(as_map(rm.get("validate")).get("failureAction"))
            rules.append({"name": text(rm.get("name")), "types": _types(rm), "match_kinds": _match_kinds(rm), "failure_action": action})
        rows.append({"source": m.source, "api_version": m.api_version, "kind": m.kind, "namespace": m.namespace, "name": m.name,
                     "validation_failure_action": text(spec.get("validationFailureAction")),
                     "background": spec.get("background"), "admission": spec.get("admission"),
                     "rule_count": len(rules), "rules": sorted(rules, key=lambda r: r["name"])})
    rows.sort(key=lambda r: (r["kind"], r["namespace"], r["name"], r["source"]))
    by_kind = {}
    for r in rows:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
    return {"policies": rows, "counts_by_kind": [{"kind": k, "count": by_kind[k]} for k in sorted(by_kind)],
            "counts": {"policies": len(rows),
                       "enforce": sum(1 for r in rows if r["validation_failure_action"].lower() == "enforce"),
                       "audit": sum(1 for r in rows if r["validation_failure_action"].lower() == "audit"),
                       "verify_images_rules": sum(1 for r in rows for x in r["rules"] if "verifyImages" in x["types"])},
            "input_errors": error_rows(data)}


def run_counts(data):
    return counts_only(run(data))
