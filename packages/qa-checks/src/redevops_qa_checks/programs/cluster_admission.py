# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Admission outcomes in the disposable cluster: which layer (webhook policy, Pod Security, quota, limit range) answered for each
object, with the policy names, the Pod Security level and checks, and any warnings."""
from __future__ import annotations

from ._cluster import lane, section, strs
from ._common import counts_only, text

PROGRAM_ID = "cluster.admission"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Admission layer, policy names, Pod Security level and checks, quota and warnings per object in one node lane"
SUPPORT = ("programs/_common.py", "programs/_cluster.py")
FRAMEWORK = ("tierk/argv.py", "tierk/drivers.py", "tierk/collectors.py")
TIER = "K"
COLLECTOR = "dry-run"


def run(data):
    rows = []
    for d in section(data, "dry_run"):
        rows.append({"index": d.get("index"), "kind": text(d.get("kind")), "namespace": text(d.get("namespace")), "name": text(d.get("name")),
                     "response": text(d.get("response")), "layer": text(d.get("layer")), "policies": strs(d.get("policies")),
                     "pod_security_level": text(d.get("pod_security_level")), "pod_security_checks": strs(d.get("pod_security_checks")),
                     "quota_name": text(d.get("quota_name")), "warnings": strs(d.get("warnings"))})
    rows.sort(key=lambda r: (r["index"] if type(r["index"]) is int else -1))
    by = lambda layer: sum(1 for r in rows if r["response"] == "rejected" and r["layer"] == layer)
    return {"lane": lane(data), "objects": rows,
            "counts": {"objects": len(rows), "kyverno_denials": by("kyverno"), "other_webhook_denials": by("admission_webhook"),
                       "pod_security_denials": by("pod_security"), "quota_denials": by("resource_quota"),
                       "limit_range_denials": by("limit_range"), "warnings": sum(len(r["warnings"]) for r in rows)},
            "input_errors": []}


def run_counts(data):
    out = run(data)
    return {"lane": out["lane"], "counts": out["counts"], "input_error_count": 0}
