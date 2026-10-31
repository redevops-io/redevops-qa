# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Pod Security related fields: effective securityContext per container, host namespaces and hostPath volumes, and the
Pod Security Admission labels of the namespaces present in the input."""
from __future__ import annotations

from ._common import (all_containers, as_list, as_map, error_rows, row_key, srt, text, workload_specs, wl,
                      counts_only)

PROGRAM_ID = "manifest.security-context"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Effective securityContext per container, host namespace use, hostPath volumes, namespace admission labels"
SUPPORT = ("programs/_common.py",)

_PSA = ("enforce", "audit", "warn")


def _first(*values):
    for v in values:
        if v is not None:
            return v
    return None


def run(data):
    ns_labels = {}
    ns_rows = []
    for m in data.by_kind("Namespace"):
        lab = as_map(m.labels)
        ns_labels[m.name] = lab
        ns_rows.append({"namespace": m.name, **{f"psa_{k}": lab.get(f"pod-security.kubernetes.io/{k}") for k in _PSA}})
    ns_rows.sort(key=lambda r: r["namespace"])

    cont = []
    for w, spec, _meta, _rep, role, c in all_containers(data):
        psc = as_map(spec.get("securityContext"))
        csc = as_map(c.get("securityContext"))
        caps = as_map(csc.get("capabilities"))
        seccomp_c = as_map(csc.get("seccompProfile"))
        seccomp_p = as_map(psc.get("seccompProfile"))
        row = dict(w)
        row.update({
            "role": role, "container": text(c.get("name")),
            "run_as_non_root": _first(csc.get("runAsNonRoot"), psc.get("runAsNonRoot")),
            "run_as_user": _first(csc.get("runAsUser"), psc.get("runAsUser")),
            "run_as_group": _first(csc.get("runAsGroup"), psc.get("runAsGroup")),
            "allow_privilege_escalation": csc.get("allowPrivilegeEscalation"),
            "privileged": csc.get("privileged"),
            "read_only_root_filesystem": csc.get("readOnlyRootFilesystem"),
            "capabilities_add": sorted(text(x) for x in as_list(caps.get("add"))),
            "capabilities_drop": sorted(text(x) for x in as_list(caps.get("drop"))),
            "seccomp_profile_type": _first(seccomp_c.get("type"), seccomp_p.get("type")),
            "host_ports": sorted(p.get("hostPort") for p in (as_map(x) for x in as_list(c.get("ports"))) if type(p.get("hostPort")) is int),
            "namespace_psa_enforce": as_map(ns_labels.get(w["namespace"])).get("pod-security.kubernetes.io/enforce")
            if w["namespace"] in ns_labels else None,
        })
        cont.append(row)
    cont.sort(key=row_key)

    pods = []
    for m in data.manifests:
        for w, spec, _meta, _rep in workload_specs(m):
            psc = as_map(spec.get("securityContext"))
            hp = []
            for v in as_list(spec.get("volumes")):
                vm = as_map(v)
                if "hostPath" in vm:
                    hpm = as_map(vm.get("hostPath"))
                    hp.append({"volume": text(vm.get("name")), "path": text(hpm.get("path")), "type": text(hpm.get("type"))})
            row = dict(wl(w))
            row.update({"host_network": spec.get("hostNetwork"), "host_pid": spec.get("hostPID"), "host_ipc": spec.get("hostIPC"),
                        "pod_run_as_non_root": psc.get("runAsNonRoot"), "pod_run_as_user": psc.get("runAsUser"),
                        "host_path_volumes": srt(hp, "volume", "path"),
                        "service_account_name": text(spec.get("serviceAccountName")),
                        "automount_service_account_token": spec.get("automountServiceAccountToken")})
            pods.append(row)
    pods.sort(key=lambda r: (r["source"], r["workload_kind"], r["namespace"], r["workload"]))
    return {
        "containers": cont,
        "pods": pods,
        "namespaces": ns_rows,
        "counts": {
            "containers": len(cont),
            "run_as_non_root_true": sum(1 for r in cont if r["run_as_non_root"] is True),
            "run_as_user_nonzero": sum(1 for r in cont if type(r["run_as_user"]) is int and r["run_as_user"] != 0),
            "privilege_escalation_not_false": sum(1 for r in cont if r["allow_privilege_escalation"] is not False),
            "privileged_true": sum(1 for r in cont if r["privileged"] is True),
            "host_network_true": sum(1 for r in pods if r["host_network"] is True),
            "host_path_volumes": sum(len(r["host_path_volumes"]) for r in pods),
            "seccomp_profile_unset": sum(1 for r in cont if r["seccomp_profile_type"] is None),
            "read_only_root_filesystem_true": sum(1 for r in cont if r["read_only_root_filesystem"] is True),
        },
        "input_errors": error_rows(data),
    }


def run_counts(data):
    return counts_only(run(data))
