# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Layer structure of each image: counts, sizes, media types, descriptors present on disk, and the children of an index."""
from __future__ import annotations

from ._common import as_list, as_map, counts_only, text
from ._image import documents, identity

PROGRAM_ID = "image.layers"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Image layer count, sizes, diff ids, config digest, platform and index children"
SUPPORT = ("programs/_common.py", "programs/_image.py")
FRAMEWORK = ("image_store.py",)


def run(data):
    rows = []
    for d in documents(data):
        row = identity(d)
        layers = [as_map(x) for x in as_list(d.get("layers"))]
        sizes = [x.get("size") for x in layers]
        row.update({"media_type": text(d.get("media_type")), "config_digest": text(d.get("config_digest")),
                    "config_present": d.get("config_present") is True, "architecture": text(d.get("architecture")),
                    "os": text(d.get("os")), "variant": text(d.get("variant")),
                    "layer_count": d.get("layer_count") if type(d.get("layer_count")) is int else 0,
                    "diff_id_count": d.get("diff_id_count") if type(d.get("diff_id_count")) is int else 0,
                    "history_count": d.get("history_count") if type(d.get("history_count")) is int else 0,
                    "history_empty_layers": d.get("history_empty_layers") if type(d.get("history_empty_layers")) is int else 0,
                    "layer_size_total": sum(sizes) if layers and all(type(s) is int for s in sizes) else None,
                    "layer_media_types": sorted({text(x.get("media_type")) for x in layers}),
                    "layer_descriptors_on_disk": sum(1 for x in layers if x.get("present") is True),
                    "layer_descriptors_not_on_disk": sum(1 for x in layers if x.get("present") is False),
                    "children": [{"digest": text(as_map(c).get("digest")), "platform": text(as_map(c).get("platform")),
                                  "artifact_type": text(as_map(c).get("artifact_type")),
                                  "reference_type": text(as_map(c).get("reference_type"))} for c in as_list(d.get("manifests"))]})
        rows.append(row)
    imgs = [r for r in rows if r["kind"] != "index"]
    return {"images": rows,
            "counts": {"documents": len(rows), "indexes": len(rows) - len(imgs), "layers_total": sum(r["layer_count"] for r in imgs),
                       "single_layer_images": sum(1 for r in imgs if r["layer_count"] == 1),
                       "diff_id_count_differs": sum(1 for r in imgs if r["config_present"] and r["diff_id_count"] != r["layer_count"] and r["kind"] == "image"),
                       "layer_descriptors_not_on_disk": sum(r["layer_descriptors_not_on_disk"] for r in imgs)},
            "input_errors": []}


def run_counts(data):
    return counts_only(run(data))
