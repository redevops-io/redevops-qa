# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Resource requests and limits per container, per-namespace sums, ResourceQuota and LimitRange objects, and the sums next to
a declared budget (reference document kind ResourceBudget, ``spec.namespaces`` a list of
``{namespace, requests_cpu, requests_memory, limits_cpu, limits_memory, pods}``). CPU is reported in millicores and memory in
bytes, as integers."""
from __future__ import annotations

from ._common import all_containers, as_list, as_map, error_rows, milli, row_key, text, whole, workload_specs, containers, wl, counts_only

PROGRAM_ID = "manifest.resources"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Container requests and limits, namespace sums, quota and limit-range objects, sums beside a declared budget"
SUPPORT = ("programs/_common.py",)

_DIMS = ("requests_cpu_milli", "requests_memory_bytes", "limits_cpu_milli", "limits_memory_bytes")


def _res(c, section):
    r = as_map(as_map(c.get("resources")).get(section))
    return {"cpu": r.get("cpu"), "memory": r.get("memory"), "ephemeral-storage": r.get("ephemeral-storage")}


def _pod_totals(spec):
    """Effective pod requests/limits: max(sum of main containers, largest init container) per resource."""
    out = {}
    for section, key in (("requests", "requests"), ("limits", "limits")):
        for res, conv, name in (("cpu", milli, "cpu_milli"), ("memory", whole, "memory_bytes")):
            main = 0
            init = 0
            unparsable = 0
            for role, c in containers(spec):
                v = _res(c, section)[res]
                if v is None:
                    continue
                n = conv(v)
                if n is None:
                    unparsable += 1
                    continue
                if role == "main":
                    main += n
                elif role == "init":
                    init = max(init, n)
            out[f"{key}_{name}"] = max(main, init)
            out["unparsable"] = out.get("unparsable", 0) + unparsable
    return out


def run(data):
    rows = []
    for w, _s, _m, replicas, role, c in all_containers(data):
        req, lim = _res(c, "requests"), _res(c, "limits")
        row = dict(w)
        row.update({"role": role, "container": text(c.get("name")), "replicas": replicas,
                    "requests_cpu_milli": milli(req["cpu"]) if req["cpu"] is not None else None,
                    "requests_memory_bytes": whole(req["memory"]) if req["memory"] is not None else None,
                    "limits_cpu_milli": milli(lim["cpu"]) if lim["cpu"] is not None else None,
                    "limits_memory_bytes": whole(lim["memory"]) if lim["memory"] is not None else None,
                    "requests_ephemeral_bytes": whole(req["ephemeral-storage"]) if req["ephemeral-storage"] is not None else None,
                    "limits_ephemeral_bytes": whole(lim["ephemeral-storage"]) if lim["ephemeral-storage"] is not None else None,
                    "quantity_unparsable": any(v is not None and (milli(v) if k == "cpu" else whole(v)) is None
                                               for sec in (req, lim) for k, v in sec.items())})
        rows.append(row)
    rows.sort(key=row_key)

    totals = {}
    for m in data.manifests:
        for w, spec, _meta, replicas in workload_specs(m):
            t = totals.setdefault(w["namespace"], {"namespace": w["namespace"], **{d: 0 for d in _DIMS}, "pods": 0,
                                                   "workloads_with_unknown_replicas": 0, "quantity_unparsable": 0})
            pod = _pod_totals(spec)
            n = replicas if type(replicas) is int else 1
            if type(replicas) is not int:
                t["workloads_with_unknown_replicas"] += 1
            for d in _DIMS:
                t[d] += pod[d] * n
            t["pods"] += n
            t["quantity_unparsable"] += pod["unparsable"]
    sums = [totals[k] for k in sorted(totals)]

    quotas = []
    for m in data.by_kind("ResourceQuota"):
        hard = as_map(as_map(m.doc.get("spec")).get("hard"))
        quotas.append({"source": m.source, "namespace": m.namespace, "name": m.name,
                       "hard": [{"resource": k, "quantity": hard[k] if type(hard[k]) in (str, int) else None}
                                for k in sorted(hard)],
                       "requests_cpu_milli": milli(hard.get("requests.cpu", hard.get("cpu"))) if ("requests.cpu" in hard or "cpu" in hard) else None,
                       "requests_memory_bytes": whole(hard.get("requests.memory", hard.get("memory"))) if ("requests.memory" in hard or "memory" in hard) else None,
                       "limits_cpu_milli": milli(hard.get("limits.cpu")) if "limits.cpu" in hard else None,
                       "limits_memory_bytes": whole(hard.get("limits.memory")) if "limits.memory" in hard else None,
                       "pods": hard.get("pods")})
    quotas.sort(key=lambda r: (r["namespace"], r["name"], r["source"]))

    limit_ranges = []
    for m in data.by_kind("LimitRange"):
        limit_ranges.append({"source": m.source, "namespace": m.namespace, "name": m.name,
                             "types": sorted(text(as_map(x).get("type")) for x in as_list(as_map(m.doc.get("spec")).get("limits")))})
    limit_ranges.sort(key=lambda r: (r["namespace"], r["name"], r["source"]))

    budget_ref = data.reference("ResourceBudget")
    budget = []
    if budget_ref is not None:
        by_ns = {s["namespace"]: s for s in sums}
        for e in as_list(budget_ref.spec.get("namespaces")):
            b = as_map(e)
            ns = text(b.get("namespace"))
            cur = by_ns.get(ns)
            declared = {"requests_cpu_milli": milli(b.get("requests_cpu")) if b.get("requests_cpu") is not None else None,
                        "requests_memory_bytes": whole(b.get("requests_memory")) if b.get("requests_memory") is not None else None,
                        "limits_cpu_milli": milli(b.get("limits_cpu")) if b.get("limits_cpu") is not None else None,
                        "limits_memory_bytes": whole(b.get("limits_memory")) if b.get("limits_memory") is not None else None,
                        "pods": b.get("pods") if type(b.get("pods")) is int else None}
            over = []
            if cur is not None:
                for d in _DIMS + ("pods",):
                    if declared[d] is not None and cur[d] > declared[d]:
                        over.append(d)
            budget.append({"namespace": ns, "declared": declared, "workloads_present": cur is not None,
                           "dimensions_over_budget": over})
        budget.sort(key=lambda r: r["namespace"])
    return {
        "containers": rows,
        "namespace_sums": sums,
        "resource_quotas": quotas,
        "limit_ranges": limit_ranges,
        "declared_budget_present": budget_ref is not None,
        "budget": budget,
        "counts": {"containers": len(rows),
                   "main_without_requests": sum(1 for r in rows if r["role"] == "main" and r["requests_cpu_milli"] is None and r["requests_memory_bytes"] is None),
                   "main_without_limits": sum(1 for r in rows if r["role"] == "main" and r["limits_cpu_milli"] is None and r["limits_memory_bytes"] is None)},
        "input_errors": error_rows(data),
    }


def run_counts(data):
    return counts_only(run(data))
