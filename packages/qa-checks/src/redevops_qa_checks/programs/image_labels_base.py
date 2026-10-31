# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Labels, manifest annotations, reference names, and the base image the image declares it was built on."""
from __future__ import annotations

from ._common import as_list, counts_only, text
from ._image import documents, identity

PROGRAM_ID = "image.labels-and-base"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Image labels, annotations, reference names and declared base image digest"
SUPPORT = ("programs/_common.py", "programs/_image.py")
FRAMEWORK = ("image_store.py",)

_SOURCE = "org.opencontainers.image.source"
_REVISION = "org.opencontainers.image.revision"


def run(data):
    rows = []
    for d in documents(data):
        row = identity(d)
        labels = [[text(k), text(v)] for k, v in (as_list(x) for x in as_list(d.get("labels")))]
        anns = [[text(k), text(v)] for k, v in (as_list(x) for x in as_list(d.get("annotations")))]
        names = {k for k, _ in labels} | {k for k, _ in anns}
        row.update({"config_present": d.get("config_present") is True, "labels": labels, "annotations": anns,
                    "ref_names": [text(x) for x in as_list(d.get("ref_names"))], "created": text(d.get("created")),
                    "base_digest": text(d.get("base_digest")), "base_name": text(d.get("base_name")),
                    "has_source_label": _SOURCE in names, "has_revision_label": _REVISION in names})
        rows.append(row)
    return {"images": rows,
            "counts": {"images": len(rows), "with_base_digest": sum(1 for r in rows if r["base_digest"]),
                       "without_base_digest": sum(1 for r in rows if not r["base_digest"]),
                       "with_labels": sum(1 for r in rows if r["labels"]),
                       "with_source_label": sum(1 for r in rows if r["has_source_label"]),
                       "with_revision_label": sum(1 for r in rows if r["has_revision_label"])},
            "input_errors": []}


def run_counts(data):
    return counts_only(run(data))
