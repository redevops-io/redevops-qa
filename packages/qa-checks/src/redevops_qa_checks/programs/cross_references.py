# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Cross-references inside the input: workload selector against its own template labels, Service selectors against workload
pods and declared container ports, and objects a workload or route refers to (ConfigMap, Secret, PersistentVolumeClaim,
ServiceAccount, Service) against the objects present. Absence from the input is reported as ``present_in_input: false``;
objects created out of band are the reader's context."""
from __future__ import annotations

from ._common import (as_list, as_map, containers, error_rows, selector_matches, text, workload_specs, wl,
                      counts_only)

PROGRAM_ID = "manifest.cross-references"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Selectors, ports and referenced objects resolved inside the input"
SUPPORT = ("programs/_common.py",)


def _present(index, kind, ns, name):
    return (kind, ns, name) in index


def run(data):
    index = {(m.kind, m.namespace, m.name) for m in data.manifests}
    workloads = []
    for m in data.manifests:
        for w, spec, meta, _r in workload_specs(m):
            workloads.append((m, w, spec, meta))

    selectors = []
    for m, w, spec, meta in workloads:
        if m.kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
            sel = as_map(as_map(m.doc.get("spec")).get("selector"))
            tpl_labels = as_map(meta.get("labels"))
            selectors.append({**wl(w), "selector_present": bool(sel),
                              "selector_matches_template_labels": selector_matches(sel, tpl_labels) if sel else None})
    selectors.sort(key=lambda r: (r["source"], r["workload_kind"], r["namespace"], r["workload"]))

    services = []
    for m in data.by_kind("Service"):
        spec = as_map(m.doc.get("spec"))
        sel = as_map(spec.get("selector"))
        matched = []
        for wm, w, wspec, meta in workloads:
            if w["namespace"] == m.namespace and sel and all(as_map(meta.get("labels")).get(k) == v for k, v in sel.items()):
                matched.append((w, wspec))
        ports = []
        for p in as_list(spec.get("ports")):
            pm = as_map(p)
            target = pm.get("targetPort", pm.get("port"))
            declared = None
            if matched:
                decl_numbers, decl_names = [], []
                for _w, wspec in matched:
                    for _role, c in containers(wspec):
                        if _role != "main":
                            continue
                        for cp in as_list(c.get("ports")):
                            cpm = as_map(cp)
                            decl_numbers.append(cpm.get("containerPort"))
                            decl_names.append(text(cpm.get("name")))
                declared = (target in decl_numbers) or (target in decl_names)
            ports.append({"port": pm.get("port"), "target_port": target, "protocol": text(pm.get("protocol")) or "TCP",
                          "target_declared_by_matched_workloads": declared})
        services.append({"source": m.source, "namespace": m.namespace, "name": m.name, "type": text(spec.get("type")) or "ClusterIP",
                         "selector_present": bool(sel), "matched_workloads": sorted(f"{w['kind']}/{w['name']}" for w, _ in matched),
                         "ports": ports})
    services.sort(key=lambda r: (r["namespace"], r["name"], r["source"]))

    refs = []
    for m, w, spec, _meta in workloads:
        ns = w["namespace"]
        def add(kind, name, via, optional=None, *, _w=w, _ns=ns):
            if name:
                refs.append({**wl(_w), "ref_kind": kind, "ref_name": name, "via": via, "optional": optional,
                             "present_in_input": _present(index, kind, _ns, name)})
        for _role, c in containers(spec):
            for e in as_list(c.get("env")):
                vf = as_map(as_map(e).get("valueFrom"))
                for k, kind in (("secretKeyRef", "Secret"), ("configMapKeyRef", "ConfigMap")):
                    if k in vf:
                        add(kind, text(as_map(vf.get(k)).get("name")), "env", as_map(vf.get(k)).get("optional"))
            for f in as_list(c.get("envFrom")):
                fm = as_map(f)
                for k, kind in (("secretRef", "Secret"), ("configMapRef", "ConfigMap")):
                    if k in fm:
                        add(kind, text(as_map(fm.get(k)).get("name")), "envFrom", as_map(fm.get(k)).get("optional"))
        for v in as_list(spec.get("volumes")):
            vm = as_map(v)
            if "secret" in vm:
                add("Secret", text(as_map(vm.get("secret")).get("secretName")), "volume", as_map(vm.get("secret")).get("optional"))
            if "configMap" in vm:
                add("ConfigMap", text(as_map(vm.get("configMap")).get("name")), "volume", as_map(vm.get("configMap")).get("optional"))
            if "persistentVolumeClaim" in vm:
                add("PersistentVolumeClaim", text(as_map(vm.get("persistentVolumeClaim")).get("claimName")), "volume")
        add("ServiceAccount", text(spec.get("serviceAccountName")), "serviceAccountName")
    for m in data.manifests:
        if m.kind in ("HTTPRoute", "GRPCRoute", "TLSRoute", "TCPRoute", "UDPRoute"):
            for r in as_list(as_map(m.doc.get("spec")).get("rules")):
                for b in as_list(as_map(r).get("backendRefs")):
                    bm = as_map(b)
                    if (text(bm.get("kind")) or "Service") == "Service" and text(bm.get("name")):
                        ns = text(bm.get("namespace")) or m.namespace
                        refs.append({"source": m.source, "workload_kind": m.kind, "namespace": m.namespace, "workload": m.name,
                                     "ref_kind": "Service", "ref_name": text(bm.get("name")), "via": "backendRef", "optional": None,
                                     "present_in_input": _present(index, "Service", ns, text(bm.get("name")))})
    refs.sort(key=lambda r: (r["source"], r["workload_kind"], r["namespace"], r["workload"], r["ref_kind"], r["ref_name"], r["via"]))
    return {"workload_selectors": selectors, "services": services, "references": refs,
            "counts": {"references": len(refs), "references_not_in_input": sum(1 for r in refs if not r["present_in_input"]),
                       "services": len(services)},
            "input_errors": error_rows(data)}


def run_counts(data):
    return counts_only(run(data))
