# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Environment variable names and where their values come from, secret and config references, and name-prefix matches
against a declared list (reference document kind EnvPolicy, ``spec.forbidden_prefixes``). Values are never returned: only
names, sources and referenced object names."""
from __future__ import annotations

from ._common import all_containers, as_list, as_map, error_rows, row_key, text, workload_specs, wl, counts_only

PROGRAM_ID = "manifest.env-and-secret-refs"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Env var names and sources (never values), envFrom and volume references, declared-prefix matches"
SUPPORT = ("programs/_common.py",)

_FROM = ("secretKeyRef", "configMapKeyRef", "fieldRef", "resourceFieldRef")


def run(data):
    pol = data.reference("EnvPolicy")
    prefixes = sorted(set(text(p) for p in as_list(pol.spec.get("forbidden_prefixes")) if text(p))) if pol is not None else []
    env_rows, from_rows, matches = [], [], []
    for w, _s, _m, _r, role, c in all_containers(data):
        base = dict(w)
        base["role"] = role
        base["container"] = text(c.get("name"))
        for e in as_list(c.get("env")):
            em = as_map(e)
            name = text(em.get("name"))
            vf = as_map(em.get("valueFrom"))
            src = "value" if "value" in em else "none"
            ref_name = ref_key = ""
            optional = None
            for k in _FROM:
                if k in vf:
                    src = k
                    r = as_map(vf.get(k))
                    ref_name = text(r.get("name")) or text(r.get("fieldPath")) or text(r.get("resource"))
                    ref_key = text(r.get("key"))
                    optional = r.get("optional")
            row = dict(base)
            row.update({"env_name": name, "source": src, "ref_name": ref_name, "ref_key": ref_key, "ref_optional": optional,
                        "has_literal_value": ("value" in em and text(em.get("value")) != "")})
            env_rows.append(row)
            for p in prefixes:
                if name.startswith(p):
                    matches.append({**base, "env_name": name, "prefix": p, "via": "env"})
        for f in as_list(c.get("envFrom")):
            fm = as_map(f)
            for k, kind in (("secretRef", "Secret"), ("configMapRef", "ConfigMap")):
                if k in fm:
                    row = dict(base)
                    row.update({"ref_kind": kind, "ref_name": text(as_map(fm.get(k)).get("name")), "prefix": text(fm.get("prefix")),
                                "ref_optional": as_map(fm.get(k)).get("optional")})
                    from_rows.append(row)
                    for p in prefixes:
                        if text(fm.get("prefix")).startswith(p):
                            matches.append({**base, "env_name": "", "prefix": p, "via": "envFrom-prefix"})
    env_rows.sort(key=lambda r: row_key(r) + (r["env_name"],))
    from_rows.sort(key=lambda r: row_key(r) + (r["ref_kind"], r["ref_name"]))
    matches.sort(key=lambda r: row_key(r) + (r["env_name"], r["prefix"], r["via"]))

    vols = []
    for m in data.manifests:
        for w, spec, _meta, _rep in workload_specs(m):
            for v in as_list(spec.get("volumes")):
                vm = as_map(v)
                if "secret" in vm:
                    vols.append({**wl(w), "volume": text(vm.get("name")), "ref_kind": "Secret",
                                 "ref_name": text(as_map(vm.get("secret")).get("secretName"))})
                if "configMap" in vm:
                    vols.append({**wl(w), "volume": text(vm.get("name")), "ref_kind": "ConfigMap",
                                 "ref_name": text(as_map(vm.get("configMap")).get("name"))})
    vols.sort(key=lambda r: (r["source"], r["workload_kind"], r["namespace"], r["workload"], r["volume"]))
    return {
        "declared_prefixes": prefixes,
        "env": env_rows,
        "env_from": from_rows,
        "volume_references": vols,
        "prefix_matches": matches,
        "counts": {"env": len(env_rows), "from_secret": sum(1 for r in env_rows if r["source"] == "secretKeyRef") +
                   sum(1 for r in from_rows if r["ref_kind"] == "Secret"),
                   "literal_values": sum(1 for r in env_rows if r["has_literal_value"]), "prefix_matches": len(matches)},
        "input_errors": error_rows(data),
    }


def run_counts(data):
    return counts_only(run(data))
