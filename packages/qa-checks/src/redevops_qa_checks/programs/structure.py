# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Structural facts about the loaded documents: identity fields present, duplicate identities, kinds seen, files that did not
load. Full schema validation needs the cluster's CRDs and is a disposable-cluster check (server-side dry-run)."""
from __future__ import annotations

from ._common import error_rows, counts_only

PROGRAM_ID = "manifest.structure"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Identity fields, duplicate object identities, kinds present, load errors"
SUPPORT = ("programs/_common.py",)


def run(data):
    docs = []
    seen = {}
    for m in data.manifests:
        has = {"api_version": m.api_version != "", "kind": m.kind != "", "name": m.name != ""}
        docs.append({"source": m.source, "index": m.index, "api_version": m.api_version, "kind": m.kind, "name": m.name,
                     "namespace": m.namespace, "has_api_version": has["api_version"], "has_kind": has["kind"], "has_name": has["name"]})
        key = m.identity()
        seen[key] = seen.get(key, 0) + 1
    dups = [{"api_version": k[0], "kind": k[1], "namespace": k[2], "name": k[3], "count": n}
            for k, n in sorted(seen.items()) if n > 1 and k[1] != "" and k[3] != ""]
    kinds = {}
    for d in docs:
        kinds[d["kind"]] = kinds.get(d["kind"], 0) + 1
    return {"documents": docs, "duplicate_identities": dups,
            "kinds": [{"kind": k, "count": kinds[k]} for k in sorted(kinds)],
            "counts": {"documents": len(docs), "references": len(data.references), "files": len(data.files),
                       "load_errors": len(data.load_errors),
                       "missing_identity": sum(1 for d in docs if not (d["has_api_version"] and d["has_kind"] and d["has_name"]))},
            "input_errors": error_rows(data)}


def run_counts(data):
    return counts_only(run(data))
