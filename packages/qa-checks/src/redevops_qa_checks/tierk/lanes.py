# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Per-lane reporting. The primary lane and the control lane produce separate result sets; they are never merged.

There is no pooled count, no combined pass or fail, and no attribution of a difference between the lanes to the manifests: a
difference is listed as data (two value digests) and the attribution field says that none was made.
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

from ..canonical import canonical_bytes, sha256_ref, to_plain
from ..errors import CheckError


class LaneReports:
    def __init__(self) -> None:
        self._lanes: Dict[str, Dict[str, Any]] = {}

    def add(self, lane_id: str, kubernetes_version: str, check_ref: Mapping[str, str], value: Mapping[str, Any]) -> None:
        value = to_plain(value)
        lane = value.get("lane") if isinstance(value, Mapping) else None
        if not isinstance(lane, Mapping) or lane.get("id") != lane_id or lane.get("kubernetes_version") != kubernetes_version:
            raise CheckError("the result does not belong to the lane it is filed under", lane=lane_id)
        entry = self._lanes.setdefault(lane_id, {"lane": lane_id, "kubernetes_version": kubernetes_version, "results": {}})
        if entry["kubernetes_version"] != kubernetes_version:
            raise CheckError("a lane has one Kubernetes version", lane=lane_id)
        key = f"{check_ref['id']}@{check_ref['version']}"
        entry["results"][key] = {"check": key, "program_hash": check_ref["program_hash"], "value_sha256": sha256_ref(canonical_bytes(value)),
                                 "value": value}

    def as_data(self) -> Dict[str, Any]:
        lanes = []
        for lane_id in sorted(self._lanes):
            e = self._lanes[lane_id]
            lanes.append({"lane": e["lane"], "kubernetes_version": e["kubernetes_version"],
                          "results": [e["results"][k] for k in sorted(e["results"])]})
        return {"schema": "qa-checks/lane-reports/1", "lanes": lanes, "pooled": None}

    def lane_difference(self, left: str, right: str) -> Dict[str, Any]:
        a, b = self._lanes.get(left, {"results": {}}), self._lanes.get(right, {"results": {}})
        rows: List[Dict[str, Any]] = []
        for key in sorted(set(a["results"]) | set(b["results"])):
            ra, rb = a["results"].get(key), b["results"].get(key)
            rows.append({"check": key, f"{left}_present": ra is not None, f"{right}_present": rb is not None,
                         "equal": ra is not None and rb is not None and _strip(ra["value"]) == _strip(rb["value"])})
        return {"lanes": [left, right], "checks": rows, "attribution": "none"}


def _strip(value: Mapping[str, Any]) -> Any:
    """The value without its lane header, so two lanes can be compared for what the cluster answered."""
    return {k: v for k, v in value.items() if k != "lane"}
