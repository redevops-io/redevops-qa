# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Liveness, readiness and startup probe declarations per main container, and whether the probed port is a declared
container port."""
from __future__ import annotations

from ._common import all_containers, as_list, as_map, error_rows, row_key, text, counts_only

PROGRAM_ID = "manifest.probes"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Probe declarations per container: handler, path, port, timings, declared-port relation"
SUPPORT = ("programs/_common.py",)

_HANDLERS = ("httpGet", "tcpSocket", "exec", "grpc")


def _probe(c, key, ports):
    p = as_map(c.get(key))
    if not p:
        return {"present": False, "handler": "none", "path": "", "port": None, "scheme": "", "initial_delay_seconds": None,
                "period_seconds": None, "timeout_seconds": None, "failure_threshold": None, "success_threshold": None,
                "port_declared": None}
    handler = "none"
    port = None
    path = ""
    scheme = ""
    for h in _HANDLERS:
        if h in p:
            handler = h
            hm = as_map(p.get(h))
            port = hm.get("port")
            path = text(hm.get("path"))
            scheme = text(hm.get("scheme"))
    declared = None
    if port is not None and handler != "exec":
        declared = (port in ports["numbers"]) or (port in ports["names"])
    return {"present": True, "handler": handler, "path": path, "port": port, "scheme": scheme,
            "initial_delay_seconds": p.get("initialDelaySeconds"), "period_seconds": p.get("periodSeconds"),
            "timeout_seconds": p.get("timeoutSeconds"), "failure_threshold": p.get("failureThreshold"),
            "success_threshold": p.get("successThreshold"), "port_declared": declared}


def run(data):
    rows = []
    for w, _s, _m, _r, role, c in all_containers(data):
        if role != "main":
            continue
        decl = [as_map(p) for p in as_list(c.get("ports"))]
        ports = {"numbers": [p.get("containerPort") for p in decl if type(p.get("containerPort")) is int],
                 "names": [text(p.get("name")) for p in decl if text(p.get("name"))]}
        row = dict(w)
        row.update({"role": role, "container": text(c.get("name")), "declared_ports": sorted(ports["numbers"]),
                    "liveness": _probe(c, "livenessProbe", ports), "readiness": _probe(c, "readinessProbe", ports),
                    "startup": _probe(c, "startupProbe", ports)})
        rows.append(row)
    rows.sort(key=row_key)
    return {"containers": rows,
            "counts": {"containers": len(rows), "with_liveness": sum(1 for r in rows if r["liveness"]["present"]),
                       "with_readiness": sum(1 for r in rows if r["readiness"]["present"]),
                       "with_startup": sum(1 for r in rows if r["startup"]["present"])},
            "input_errors": error_rows(data)}


def run_counts(data):
    return counts_only(run(data))
