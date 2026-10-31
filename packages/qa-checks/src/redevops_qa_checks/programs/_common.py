# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Shared pure helpers for manifest check programs (part of the hashed source of every program that lists it)."""
from __future__ import annotations

import re
from fractions import Fraction

WORKLOAD_KINDS = ("Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob")
_TEMPLATED = ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job")


def text(value):
    return value if type(value) is str else ""


def as_map(value):
    return value if hasattr(value, "get") and hasattr(value, "items") else {}


def as_list(value):
    return value if type(value) is tuple else ()


def srt(rows, *keys):
    return sorted(rows, key=lambda r: tuple(str(r.get(k, "")) if type(r.get(k)) is not int else "%020d" % r.get(k) for k in keys))


def workload_specs(manifest):
    """[(workload, pod_spec, pod_metadata, replicas)] for a manifest; replicas is an int or None when unknown."""
    kind = manifest.kind
    doc = manifest.doc
    if kind == "Pod":
        return [(workload_id(manifest), as_map(doc.get("spec")), as_map(doc.get("metadata")), 1)]
    if kind == "CronJob":
        tpl = as_map(as_map(as_map(as_map(doc.get("spec")).get("jobTemplate")).get("spec")).get("template"))
        return [(workload_id(manifest), as_map(tpl.get("spec")), as_map(tpl.get("metadata")), None)]
    if kind in _TEMPLATED:
        spec = as_map(doc.get("spec"))
        tpl = as_map(spec.get("template"))
        replicas = spec.get("replicas")
        if kind in ("DaemonSet", "Job"):
            replicas = None
        elif replicas is None:
            replicas = 1
        elif type(replicas) is not int:
            replicas = None
        return [(workload_id(manifest), as_map(tpl.get("spec")), as_map(tpl.get("metadata")), replicas)]
    return []


def workload_id(manifest):
    return {"kind": manifest.kind, "namespace": manifest.namespace, "name": manifest.name, "source": manifest.source}


def containers(pod_spec):
    """[(role, container)] with role one of main, init, ephemeral, in declaration order."""
    out = []
    for role, key in (("main", "containers"), ("init", "initContainers"), ("ephemeral", "ephemeralContainers")):
        for c in as_list(pod_spec.get(key)):
            if hasattr(c, "get"):
                out.append((role, c))
    return out


def parse_image(ref):
    """Split an image reference into registry, repository, tag and digest (no network, no defaults applied)."""
    ref = text(ref)
    digest = ""
    name = ref
    if "@" in ref:
        name, digest = ref.split("@", 1)
    tag = ""
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = name.rsplit(":", 1)
    first = name.split("/", 1)[0] if "/" in name else ""
    registry = first if first and ("." in first or ":" in first or first == "localhost") else ""
    return {"image": ref, "registry": registry, "repository": name, "tag": tag, "digest": digest,
            "has_tag": bool(tag), "has_digest": bool(digest),
            "tag_is_latest": tag == "latest", "untagged_unpinned": (not tag) and (not digest)}


_Q = re.compile(r"^([+-]?)(\d+(?:\.\d*)?|\.\d+)(?:([eE])([+-]?\d+)|(n|u|m|k|M|G|T|P|E|Ki|Mi|Gi|Ti|Pi|Ei))?$")
_SUFFIX = {"n": Fraction(1, 10**9), "u": Fraction(1, 10**6), "m": Fraction(1, 1000), "": Fraction(1), "k": Fraction(10**3),
           "M": Fraction(10**6), "G": Fraction(10**9), "T": Fraction(10**12), "P": Fraction(10**15), "E": Fraction(10**18),
           "Ki": Fraction(2**10), "Mi": Fraction(2**20), "Gi": Fraction(2**30), "Ti": Fraction(2**40), "Pi": Fraction(2**50),
           "Ei": Fraction(2**60)}


def quantity(value):
    """A Kubernetes quantity as an exact Fraction, or None when it does not parse."""
    if type(value) is int:
        return Fraction(value)
    if type(value) is not str:
        return None
    m = _Q.match(value.strip())
    if not m:
        return None
    sign, num, e, exp, suf = m.groups()
    q = Fraction(num)
    if e is not None:
        if abs(int(exp)) > 40:
            return None
        q = q * (Fraction(10) ** int(exp))
    elif suf:
        q = q * _SUFFIX[suf]
    return -q if sign == "-" else q


def ceil_int(fr):
    n, d = fr.numerator, fr.denominator
    return -((-n) // d)


def milli(value):
    q = quantity(value)
    return None if q is None else ceil_int(q * 1000)


def whole(value):
    q = quantity(value)
    return None if q is None else ceil_int(q)


def selector_matches(selector, labels):
    """True when ``labels`` satisfy a matchLabels/matchExpressions selector; None when the selector is not understood.
    An empty selector selects everything (Kubernetes semantics for pod and namespace selectors)."""
    sel = as_map(selector)
    labels = as_map(labels)
    known = {"matchLabels", "matchExpressions"}
    if any(k not in known for k in sel):
        return None
    for k, v in as_map(sel.get("matchLabels")).items():
        if labels.get(k) != v:
            return False
    for expr in as_list(sel.get("matchExpressions")):
        e = as_map(expr)
        key, op, vals = text(e.get("key")), text(e.get("operator")), as_list(e.get("values"))
        if op == "In":
            if labels.get(key) not in vals or key not in labels:
                return False
        elif op == "NotIn":
            if key in labels and labels.get(key) in vals:
                return False
        elif op == "Exists":
            if key not in labels:
                return False
        elif op == "DoesNotExist":
            if key in labels:
                return False
        else:
            return None
    return True


def port_rows(ports):
    rows = []
    for p in as_list(ports):
        pm = as_map(p)
        rows.append({"port": pm.get("port") if pm.get("port") is not None else pm.get("containerPort"),
                     "end_port": pm.get("endPort"), "protocol": text(pm.get("protocol")) or "TCP"})
    return rows


def wl(workload):
    """Flat identity fields of a workload, for a result row."""
    return {"source": workload["source"], "workload_kind": workload["kind"], "namespace": workload["namespace"],
            "workload": workload["name"]}


def error_rows(data):
    return [{"source": e.source, "code": e.code} for e in sorted(data.load_errors, key=lambda e: (e.source, e.code, e.detail))]


def all_containers(data):
    """[(workload_fields, pod_spec, pod_metadata, replicas, role, container)] over every workload in the input."""
    out = []
    for m in data.manifests:
        for w, spec, meta, replicas in workload_specs(m):
            for role, c in containers(spec):
                out.append((wl(w), spec, meta, replicas, role, c))
    return out


def row_key(row):
    return (row.get("source", ""), row.get("workload_kind", ""), row.get("namespace", ""), row.get("workload", ""),
            row.get("role", ""), row.get("container", ""))


def counts_only(output):
    """The compact projection of a program result: its counts and the number of input errors."""
    return {"counts": output["counts"], "input_error_count": len(output["input_errors"])}
