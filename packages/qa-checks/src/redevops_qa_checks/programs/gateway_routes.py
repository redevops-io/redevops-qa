# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Gateway API listeners and routes: listener selectors and allowed kinds, route parent references resolved against the
Gateways and Namespaces in the input, per-rule matches (path, method, headers), filters and backends. Observations only; the
program does not decide whether a route attaches in a cluster, it reports what the manifests declare."""
from __future__ import annotations

from ._common import as_list, as_map, error_rows, selector_matches, text, counts_only

PROGRAM_ID = "manifest.gateway-routes"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Gateway listeners and route attachment (parentRefs, selectors, kinds), method and path matches, filters, backends"
SUPPORT = ("programs/_common.py",)

ROUTE_KINDS = ("HTTPRoute", "GRPCRoute", "TLSRoute", "TCPRoute", "UDPRoute")
_DEFAULT_KINDS = {"HTTP": ("HTTPRoute",), "HTTPS": ("HTTPRoute", "GRPCRoute"), "TLS": ("TLSRoute",), "TCP": ("TCPRoute",),
                  "UDP": ("UDPRoute",)}


def _host_intersects(a, b):
    if not a or not b:
        return True
    a, b = a.lower(), b.lower()
    if a == b:
        return True
    if a.startswith("*.") and (b.endswith(a[1:]) or (b.startswith("*.") and (a[1:].endswith(b[1:]) or b[1:].endswith(a[1:])))):
        return True
    if b.startswith("*.") and a.endswith(b[1:]):
        return True
    return False


def run(data):
    ns_labels = {m.name: as_map(m.labels) for m in data.by_kind("Namespace")}
    gateways = {}
    listener_rows = []
    for g in data.by_kind("Gateway"):
        ls = []
        for l in as_list(as_map(g.doc.get("spec")).get("listeners")):
            lm = as_map(l)
            ar = as_map(lm.get("allowedRoutes"))
            nsel = as_map(ar.get("namespaces"))
            kinds = [text(as_map(k).get("kind")) for k in as_list(ar.get("kinds"))]
            proto = text(lm.get("protocol"))
            ls.append({"name": text(lm.get("name")), "port": lm.get("port"), "protocol": proto, "hostname": text(lm.get("hostname")),
                       "tls_mode": text(as_map(lm.get("tls")).get("mode")),
                       "namespaces_from": text(nsel.get("from")) or "Same",
                       "selector": nsel.get("selector"),
                       "kinds": sorted(kinds) if kinds else list(_DEFAULT_KINDS.get(proto, ()))})
        gateways[(g.namespace, g.name)] = ls
        for l in ls:
            listener_rows.append({"source": g.source, "gateway_namespace": g.namespace, "gateway": g.name,
                                  "listener": l["name"], "port": l["port"], "protocol": l["protocol"], "hostname": l["hostname"],
                                  "tls_mode": l["tls_mode"], "namespaces_from": l["namespaces_from"],
                                  "selector_present": l["selector"] is not None,
                                  "selector_match_labels": sorted([k, v] for k, v in as_map(as_map(l["selector"]).get("matchLabels")).items()
                                                                  if type(v) is str),
                                  "selector_expression_count": len(as_list(as_map(l["selector"]).get("matchExpressions"))),
                                  "allowed_kinds": l["kinds"], "kinds_explicit": l["kinds"] != list(_DEFAULT_KINDS.get(l["protocol"], ()))})
    listener_rows.sort(key=lambda r: (r["gateway_namespace"], r["gateway"], r["listener"]))

    route_rows = []
    for m in data.manifests:
        if m.kind not in ROUTE_KINDS:
            continue
        spec = as_map(m.doc.get("spec"))
        hostnames = sorted(text(h) for h in as_list(spec.get("hostnames")))
        parents = []
        for p in as_list(spec.get("parentRefs")):
            pm = as_map(p)
            gns = text(pm.get("namespace")) or m.namespace
            gname = text(pm.get("name"))
            section = text(pm.get("sectionName"))
            port = pm.get("port")
            ls = gateways.get((gns, gname))
            cands = []
            if ls is not None:
                cands = [l for l in ls if (not section or l["name"] == section) and (port is None or l["port"] == port)]
            per = []
            for l in cands:
                frm = l["namespaces_from"]
                if frm == "All":
                    ns_ok = True
                elif frm == "Same":
                    ns_ok = (m.namespace == gns)
                elif frm == "Selector":
                    if m.namespace not in ns_labels:
                        ns_ok = None
                    else:
                        ns_ok = selector_matches(l["selector"], ns_labels[m.namespace])
                else:
                    ns_ok = None
                per.append({"listener": l["name"], "protocol": l["protocol"], "namespace_allowed": ns_ok,
                            "kind_allowed": m.kind in l["kinds"],
                            "hostname_intersects": any(_host_intersects(l["hostname"], h) for h in hostnames) if hostnames else True})
            parents.append({"gateway_namespace": gns, "gateway": gname, "section_name": section, "port": port,
                            "gateway_in_input": ls is not None, "listener_candidates": len(cands),
                            "listeners": sorted(per, key=lambda r: r["listener"])})
        rules = []
        for i, r in enumerate(as_list(spec.get("rules"))):
            rm = as_map(r)
            matches = []
            for mt in as_list(rm.get("matches")) or ({},):
                mm = as_map(mt)
                path = as_map(mm.get("path"))
                matches.append({"path_type": text(path.get("type")) or ("PathPrefix" if not mm else ""),
                                "path_value": text(path.get("value")) or ("/" if not mm else ""),
                                "method": text(mm.get("method")),
                                "header_matches": len(as_list(mm.get("headers"))), "query_matches": len(as_list(mm.get("queryParams")))})
            filters = []
            for f in as_list(rm.get("filters")):
                fm = as_map(f)
                ft = text(fm.get("type"))
                detail = ""
                if ft == "URLRewrite":
                    rw = as_map(fm.get("urlRewrite"))
                    pm2 = as_map(rw.get("path"))
                    detail = text(pm2.get("type")) + ":" + (text(pm2.get("replacePrefixMatch")) or text(pm2.get("replaceFullPath")))
                filters.append({"type": ft, "detail": detail})
            backends = [{"name": text(as_map(b).get("name")), "namespace": text(as_map(b).get("namespace")) or m.namespace,
                         "kind": text(as_map(b).get("kind")) or "Service", "port": as_map(b).get("port"),
                         "weight": as_map(b).get("weight")} for b in as_list(rm.get("backendRefs"))]
            rules.append({"index": i, "matches": matches, "filters": filters, "backends": backends,
                          "all_matches_have_method": all(mt["method"] != "" for mt in matches) if matches else False})
        route_rows.append({"source": m.source, "kind": m.kind, "namespace": m.namespace, "name": m.name, "hostnames": hostnames,
                           "parents": parents, "rules": rules,
                           "rules_without_method": sum(1 for r in rules if not r["all_matches_have_method"])})
    route_rows.sort(key=lambda r: (r["kind"], r["namespace"], r["name"], r["source"]))
    return {"listeners": listener_rows, "routes": route_rows,
            "counts": {"gateways": len(gateways), "listeners": len(listener_rows), "routes": len(route_rows),
                       "parents_gateway_not_in_input": sum(1 for r in route_rows for p in r["parents"] if not p["gateway_in_input"]),
                       "parents_without_listener": sum(1 for r in route_rows for p in r["parents"] if p["gateway_in_input"] and p["listener_candidates"] == 0),
                       "parents_namespace_not_allowed": sum(1 for r in route_rows for p in r["parents"] for l in p["listeners"] if l["namespace_allowed"] is False),
                       "rules": sum(len(r["rules"]) for r in route_rows),
                       "rules_without_method": sum(r["rules_without_method"] for r in route_rows)},
            "input_errors": error_rows(data)}


def run_counts(data):
    return counts_only(run(data))
