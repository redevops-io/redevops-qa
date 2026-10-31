# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Server-side dry-run of rendered manifests in the disposable cluster: what the API server answered for each object."""
from __future__ import annotations

from ._cluster import lane, section, strs
from ._common import as_map, counts_only, text

PROGRAM_ID = "cluster.dry-run"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Server-side dry-run answer per object (accepted or rejected, error class, layer) in one node lane"
SUPPORT = ("programs/_common.py", "programs/_cluster.py")
FRAMEWORK = ("tierk/argv.py", "tierk/drivers.py", "tierk/collectors.py")
TIER = "K"
COLLECTOR = "dry-run"

_CLASSES = ("kind_not_known", "schema_invalid", "schema_unknown_field", "admission_denied", "pod_security_violation", "quota_exceeded",
            "limit_range_violation", "namespace_not_found", "forbidden_other", "other")


def run(data):
    rows = []
    for d in section(data, "dry_run"):
        rows.append({"index": d.get("index"), "api_version": text(d.get("api_version")), "kind": text(d.get("kind")),
                     "namespace": text(d.get("namespace")), "name": text(d.get("name")), "response": text(d.get("response")),
                     "error_class": text(d.get("error_class")), "layer": text(d.get("layer")), "warnings": strs(d.get("warnings")),
                     "message": text(d.get("message"))})
    rows.sort(key=lambda r: (r["index"] if type(r["index"]) is int else -1))
    counts = {"objects": len(rows), "accepted": sum(1 for r in rows if r["response"] == "accepted"),
              "rejected": sum(1 for r in rows if r["response"] == "rejected"),
              "with_warnings": sum(1 for r in rows if r["warnings"])}
    for c in _CLASSES:
        counts[c] = sum(1 for r in rows if r["error_class"] == c)
    return {"lane": lane(data), "objects": rows, "counts": counts, "input_errors": []}


def run_counts(data):
    out = run(data)
    return {"lane": out["lane"], "counts": out["counts"], "input_error_count": 0}
