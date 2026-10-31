# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Gateway and route status conditions as reported by the controller in the disposable cluster."""
from __future__ import annotations

from ._cluster import lane, section
from ._common import as_list, as_map, text

PROGRAM_ID = "cluster.gateway-status"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Gateway, listener and route parent status conditions in one node lane"
SUPPORT = ("programs/_common.py", "programs/_cluster.py")
FRAMEWORK = ("tierk/argv.py", "tierk/drivers.py", "tierk/collectors.py")
TIER = "K"
COLLECTOR = "gateway-status"


def _conds(v):
    return [{"type": text(as_map(c).get("type")), "status": text(as_map(c).get("status")), "reason": text(as_map(c).get("reason"))} for c in as_list(v)]


def _true(conds, kind):
    return any(c["type"] == kind and c["status"] == "True" for c in conds)


def run(data):
    gws = []
    for g in section(data, "gateway"):
        conds = _conds(g.get("conditions"))
        listeners = [{"name": text(as_map(l).get("name")), "attached_routes": as_map(l).get("attached_routes"),
                      "conditions": _conds(as_map(l).get("conditions"))} for l in as_list(g.get("listeners"))]
        gws.append({"namespace": text(g.get("namespace")), "name": text(g.get("name")), "conditions": conds, "listeners": listeners,
                    "address_count": g.get("address_count"), "accepted": _true(conds, "Accepted"), "programmed": _true(conds, "Programmed"),
                    "listeners_resolved": all(_true(l["conditions"], "ResolvedRefs") for l in listeners) if listeners else False})
    routes = []
    for r in section(data, "route"):
        parents = [{"gateway_namespace": text(as_map(p).get("gateway_namespace")), "gateway": text(as_map(p).get("gateway")),
                    "section_name": text(as_map(p).get("section_name")), "conditions": _conds(as_map(p).get("conditions")),
                    "accepted": _true(_conds(as_map(p).get("conditions")), "Accepted"),
                    "resolved_refs": _true(_conds(as_map(p).get("conditions")), "ResolvedRefs")} for p in as_list(r.get("parents"))]
        routes.append({"namespace": text(r.get("namespace")), "name": text(r.get("name")), "parents": parents})
    return {"lane": lane(data), "gateways": gws, "routes": routes,
            "counts": {"gateways": len(gws), "gateways_programmed": sum(1 for g in gws if g["programmed"]), "routes": len(routes),
                       "route_parents": sum(len(r["parents"]) for r in routes),
                       "route_parents_accepted": sum(1 for r in routes for p in r["parents"] if p["accepted"]),
                       "route_parents_not_accepted": sum(1 for r in routes for p in r["parents"] if not p["accepted"])},
            "input_errors": []}


def run_counts(data):
    out = run(data)
    return {"lane": out["lane"], "counts": out["counts"], "input_error_count": 0}
