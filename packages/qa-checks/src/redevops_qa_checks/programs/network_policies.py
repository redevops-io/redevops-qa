# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""NetworkPolicy and Cilium network policy objects: default-deny shape per namespace and direction, the rules of every policy
(egress and ingress peers and ports) extracted as data. Observations only."""
from __future__ import annotations

from ._common import as_list, as_map, error_rows, port_rows, text, workload_specs, counts_only

PROGRAM_ID = "manifest.network-policies"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "NetworkPolicy and Cilium policy shape: default-deny presence, selectors, egress and ingress rule extraction"
SUPPORT = ("programs/_common.py",)

CILIUM = ("CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy")


def _peer(p):
    pm = as_map(p)
    ip = as_map(pm.get("ipBlock"))
    return {"ip_block": text(ip.get("cidr")), "except": sorted(text(x) for x in as_list(ip.get("except"))),
            "pod_selector": ("none" if "podSelector" not in pm else ("empty" if not as_map(pm.get("podSelector")) else "set")),
            "namespace_selector": ("none" if "namespaceSelector" not in pm else ("empty" if not as_map(pm.get("namespaceSelector")) else "set"))}


def _k8s(m):
    spec = as_map(m.doc.get("spec"))
    types = [text(t) for t in as_list(spec.get("policyTypes"))]
    if not types:
        types = ["Ingress"] + (["Egress"] if "egress" in spec else [])
    sel = as_map(spec.get("podSelector"))
    ingress = [{"from": [_peer(p) for p in as_list(as_map(r).get("from"))], "ports": port_rows(as_map(r).get("ports")),
                "from_any": "from" not in as_map(r)} for r in as_list(spec.get("ingress"))]
    egress = [{"to": [_peer(p) for p in as_list(as_map(r).get("to"))], "ports": port_rows(as_map(r).get("ports")),
               "to_any": "to" not in as_map(r)} for r in as_list(spec.get("egress"))]
    return {"engine": "kubernetes", "source": m.source, "kind": m.kind, "namespace": m.namespace, "name": m.name,
            "policy_types": sorted(types), "selects_all_pods": len(sel) == 0,
            "pod_selector_labels": sorted([k, v] for k, v in as_map(sel.get("matchLabels")).items() if type(v) is str),
            "ingress_rules": ingress, "egress_rules": egress,
            "deny_all_ingress": "Ingress" in types and len(sel) == 0 and len(ingress) == 0,
            "deny_all_egress": "Egress" in types and len(sel) == 0 and len(egress) == 0,
            "deny_rules": []}


def _cilium_peers(r, prefix):
    rm = as_map(r)
    return {"cidr": sorted(text(x) for x in as_list(rm.get(prefix + "CIDR"))),
            "entities": sorted(text(x) for x in as_list(rm.get(prefix + "Entities"))),
            "endpoints": len(as_list(rm.get(prefix + "Endpoints"))),
            "ports": [{"port": text(as_map(pp).get("port")), "protocol": text(as_map(pp).get("protocol")) or "ANY"}
                      for tp in as_list(rm.get("toPorts")) for pp in as_list(as_map(tp).get("ports"))]}


def _cilium(m):
    spec = as_map(m.doc.get("spec"))
    specs = [spec] + [as_map(s) for s in as_list(m.doc.get("specs"))]
    sel_empty = []
    ingress, egress, deny_in, deny_out = [], [], [], []
    for s in specs:
        sel = as_map(s.get("endpointSelector"))
        sel_empty.append(len(sel) == 0)
        ingress += [_cilium_peers(r, "from") for r in as_list(s.get("ingress"))]
        egress += [_cilium_peers(r, "to") for r in as_list(s.get("egress"))]
        deny_in += [_cilium_peers(r, "from") for r in as_list(s.get("ingressDeny"))]
        deny_out += [_cilium_peers(r, "to") for r in as_list(s.get("egressDeny"))]
    return {"engine": "cilium", "source": m.source, "kind": m.kind, "namespace": m.namespace, "name": m.name,
            "policy_types": [], "selects_all_pods": all(sel_empty) if sel_empty else False, "pod_selector_labels": [],
            "ingress_rules": ingress, "egress_rules": egress, "deny_all_ingress": False, "deny_all_egress": False,
            "deny_rules": [{"direction": "ingress", **r} for r in deny_in] + [{"direction": "egress", **r} for r in deny_out]}


def run(data):
    pols = [_k8s(m) for m in data.by_kind("NetworkPolicy")] + [_cilium(m) for m in data.manifests if m.kind in CILIUM]
    pols.sort(key=lambda r: (r["namespace"], r["kind"], r["name"], r["source"]))
    namespaces = set()
    for m in data.manifests:
        for w, _s, _m, _r in workload_specs(m):
            namespaces.add(w["namespace"])
        if m.kind == "Namespace":
            namespaces.add(m.name)
    rows = []
    for ns in sorted(namespaces):
        mine = [p for p in pols if p["namespace"] == ns and p["engine"] == "kubernetes"]
        rows.append({"namespace": ns,
                     "default_deny_ingress": any(p["deny_all_ingress"] for p in mine),
                     "default_deny_egress": any(p["deny_all_egress"] for p in mine),
                     "policy_count": len(mine),
                     "workload_count": sum(1 for m in data.manifests for w, _s, _m2, _r in workload_specs(m) if w["namespace"] == ns)})
    return {"policies": pols, "namespaces": rows,
            "counts": {"policies": len(pols), "kubernetes": sum(1 for p in pols if p["engine"] == "kubernetes"),
                       "cilium": sum(1 for p in pols if p["engine"] == "cilium"),
                       "namespaces": len(rows),
                       "namespaces_without_default_deny_ingress": sum(1 for r in rows if not r["default_deny_ingress"]),
                       "namespaces_without_default_deny_egress": sum(1 for r in rows if not r["default_deny_egress"]),
                       "deny_rules": sum(len(p["deny_rules"]) for p in pols)},
            "input_errors": error_rows(data)}


def run_counts(data):
    return counts_only(run(data))
