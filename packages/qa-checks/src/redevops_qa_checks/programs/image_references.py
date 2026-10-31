# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Image references of every container: tag, digest, implicit latest. Observations only."""
from __future__ import annotations

from ._common import all_containers, error_rows, parse_image, row_key, text, counts_only

PROGRAM_ID = "manifest.image-references"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Per-container image reference parts (registry, repository, tag, digest) and counts"
SUPPORT = ("programs/_common.py",)


def run(data):
    rows = []
    for w, _spec, _meta, _rep, role, c in all_containers(data):
        row = dict(w)
        row["role"] = role
        row["container"] = text(c.get("name"))
        row.update(parse_image(c.get("image")))
        row["image_missing"] = text(c.get("image")) == ""
        rows.append(row)
    rows.sort(key=row_key)
    return {
        "containers": rows,
        "counts": {
            "containers": len(rows),
            "with_digest": sum(1 for r in rows if r["has_digest"]),
            "tag_only": sum(1 for r in rows if r["has_tag"] and not r["has_digest"]),
            "latest_tag": sum(1 for r in rows if r["tag_is_latest"]),
            "untagged_unpinned": sum(1 for r in rows if r["untagged_unpinned"] and not r["image_missing"]),
            "image_missing": sum(1 for r in rows if r["image_missing"]),
        },
        "input_errors": error_rows(data),
    }


def run_counts(data):
    return counts_only(run(data))
