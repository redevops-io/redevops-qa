# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Kyverno policy readiness, ResourceQuota status and LimitRange presence as reported by the disposable cluster."""
from __future__ import annotations

from ._cluster import lane, section
from ._common import as_list, as_map, text

PROGRAM_ID = "cluster.policy-status"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Kyverno policy readiness, quota hard and used values, limit range types in one node lane"
SUPPORT = ("programs/_common.py", "programs/_cluster.py")
FRAMEWORK = ("tierk/argv.py", "tierk/drivers.py", "tierk/collectors.py")
TIER = "K"
COLLECTOR = "policy-status"


def run(data):
    policies = [{"name": text(p.get("name")), "ready": p.get("ready"),
                 "conditions": [{"type": text(as_map(c).get("type")), "status": text(as_map(c).get("status")), "reason": text(as_map(c).get("reason"))}
                                for c in as_list(p.get("conditions"))]} for p in section(data, "policy")]
    quotas = [{"namespace": text(q.get("namespace")), "name": text(q.get("name")), "hard": [list(x) for x in as_list(q.get("hard"))],
               "used": [list(x) for x in as_list(q.get("used"))]} for q in section(data, "quota")]
    ranges = [{"namespace": text(l.get("namespace")), "name": text(l.get("name")), "types": [text(t) for t in as_list(l.get("types"))]}
              for l in section(data, "limit_range")]
    return {"lane": lane(data), "policies": policies, "quotas": quotas, "limit_ranges": ranges,
            "counts": {"policies": len(policies), "policies_ready": sum(1 for p in policies if p["ready"] is True),
                       "policies_not_ready": sum(1 for p in policies if p["ready"] is not True), "quotas": len(quotas),
                       "limit_ranges": len(ranges)},
            "input_errors": []}


def run_counts(data):
    out = run(data)
    return {"lane": out["lane"], "counts": out["counts"], "input_error_count": 0}
