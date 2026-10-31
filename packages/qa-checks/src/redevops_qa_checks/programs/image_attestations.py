# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Whether an image has a software bill of materials or a provenance attestation among the files provided, and how it was found
(an OCI referrer, a build-tool attestation manifest in the same layout, or a document beside the image files)."""
from __future__ import annotations

from ._common import as_list, as_map, counts_only, text
from ._image import documents, identity

PROGRAM_ID = "image.attestations"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Presence of SBOM and provenance attestations for each image and how they were found"
SUPPORT = ("programs/_common.py", "programs/_image.py")
FRAMEWORK = ("image_store.py",)


def run(data):
    rows = []
    for d in documents(data):
        row = identity(d)
        atts = [{"kind": text(as_map(a).get("kind")), "predicate_type": text(as_map(a).get("predicate_type")), "via": text(as_map(a).get("via"))}
                for a in as_list(d.get("attestations"))]
        row.update({"attestations": atts, "sbom_present": any(a["kind"] == "sbom" for a in atts),
                    "provenance_present": any(a["kind"] == "provenance" for a in atts),
                    "sbom_via": sorted({a["via"] for a in atts if a["kind"] == "sbom"})})
        rows.append(row)
    imgs = [r for r in rows if r["kind"] in ("image", "inspect", "config")]
    return {"images": rows,
            "counts": {"images": len(imgs), "with_sbom": sum(1 for r in imgs if r["sbom_present"]),
                       "without_sbom": sum(1 for r in imgs if not r["sbom_present"]),
                       "with_provenance": sum(1 for r in imgs if r["provenance_present"])},
            "input_errors": []}


def run_counts(data):
    return counts_only(run(data))
