# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Image names used by workloads next to a declared image map (reference document kind ImageMap).

The map is declared context read from the case tree: ``spec.images`` is a list of ``{name, repository, tag?, digest?}``.
The program reports how each container's image relates to the map; it does not judge the relation.
"""
from __future__ import annotations

from ._common import all_containers, as_list, as_map, error_rows, parse_image, row_key, text, counts_only

PROGRAM_ID = "manifest.image-name-map"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Relation of each container image to a declared image map: matching entries, tag agreement, unused entries"
SUPPORT = ("programs/_common.py",)


def _last(repo):
    return repo.rsplit("/", 1)[-1]


def _agree(declared, observed):
    values = [v for v in declared if v]
    return None if not values else observed in values


def run(data):
    ref = data.reference("ImageMap")
    entries = []
    if ref is not None:
        for e in as_list(ref.spec.get("images")):
            m = as_map(e)
            entries.append({"name": text(m.get("name")), "repository": text(m.get("repository")), "tag": text(m.get("tag")),
                            "digest": text(m.get("digest"))})
    entries.sort(key=lambda e: (e["name"], e["repository"]))
    used = set()
    rows = []
    for w, _s, _m, _r, role, c in all_containers(data):
        p = parse_image(c.get("image"))
        exact = [e for e in entries if e["repository"] == p["repository"]]
        by_name = [e for e in entries if e["repository"] != p["repository"] and _last(e["repository"]) == _last(p["repository"])]
        for e in exact:
            used.add((e["name"], e["repository"]))
        row = dict(w)
        row.update({"role": role, "container": text(c.get("name")), "image": p["image"], "repository": p["repository"],
                    "tag": p["tag"], "digest": p["digest"],
                    "declared_names": sorted(e["name"] for e in exact),
                    "same_last_component_other_registry": sorted(e["name"] for e in by_name),
                    "in_map": bool(exact),
                    "declared_tag_equal": _agree([e["tag"] for e in exact], p["tag"]),
                    "declared_digest_equal": _agree([e["digest"] for e in exact], p["digest"])})
        rows.append(row)
    rows.sort(key=row_key)
    return {
        "map_present": ref is not None,
        "map_entries": entries,
        "containers": rows,
        "entries_not_used": [e for e in entries if (e["name"], e["repository"]) not in used],
        "counts": {"containers": len(rows), "in_map": sum(1 for r in rows if r["in_map"]),
                   "not_in_map": sum(1 for r in rows if not r["in_map"]),
                   "tag_disagreements": sum(1 for r in rows if r["declared_tag_equal"] is False),
                   "digest_disagreements": sum(1 for r in rows if r["declared_digest_equal"] is False),
                   "entries_not_used": len([e for e in entries if (e["name"], e["repository"]) not in used])},
        "input_errors": error_rows(data),
    }


def run_counts(data):
    return counts_only(run(data))
