# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Connectivity collectors: the matrix of probes a check declares, run as fixed probe pods (traffic) or read from policy objects
(policy-state). Both go through a guarded session; the traffic collector is the only code that creates anything.

The matrix is a reference document (``kind: ConnectivityMatrix``, ``spec.probes``). Each probe names a source namespace (and the
labels of the source workload), a target (an IP literal, or a workload whose pod IP is read from the cluster and then used as a
literal), a TCP port, an optional control namespace, and a range class. Targets are fixed by the document, bounded in count, and
limited to the cluster's networks and the synthetic plan. Names are never probed. Metadata-address traffic proof and UDP are not
expressible and are refused.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ..errors import EnvironmentFault, LimitExceeded, PolicyBlocked, Unsupported
from .probes import MAX_TIMEOUT_S, probe_pod
from .subnets import SUBNET_PLAN, TargetPolicy

MAX_PROBES = 64
MAX_POLLS = 30
RANGE_CLASSES = ("workload", "gateway-proxy", "world", "lan-equivalent", "mail-port", "metadata-endpoint")
_ID = re.compile(r"[a-z0-9]([-a-z0-9]{0,38}[a-z0-9])?")
_KV = re.compile(r"[A-Za-z0-9._/-]{1,63}")
_VAL = re.compile(r"[A-Za-z0-9._-]{0,63}")
METADATA_NET = ipaddress.ip_network("169.254.0.0/16")


@dataclass(frozen=True)
class Probe:
    id: str
    range_class: str
    source_namespace: str
    source_labels: Tuple[Tuple[str, str], ...]
    target_ip: str
    target_workload: Optional[Tuple[str, Tuple[Tuple[str, str], ...]]]
    port: int
    protocol: str
    control_namespace: str
    control_labels: Tuple[Tuple[str, str], ...]
    timeout_s: int = 5


@dataclass
class ProbeContext:
    """What the traffic collector needs besides the session: where probes may point, how to wait, and where to record cleanup."""
    target_policy: TargetPolicy = field(default_factory=TargetPolicy)
    sleep: Callable[[float], None] = lambda s: None
    register_cleanup: Callable[[Callable[[], Sequence[str]]], None] = lambda fn: None


def _labels(v: Any, what: str) -> Tuple[Tuple[str, str], ...]:
    if v is None:
        return ()
    if not isinstance(v, Mapping) or len(v) > 8:
        raise PolicyBlocked(f"{what}: labels are a small mapping", guard_code="MATRIX_INVALID")
    out = []
    for k, x in v.items():
        if type(k) is not str or type(x) is not str or not _KV.fullmatch(k) or not _VAL.fullmatch(x):
            raise PolicyBlocked(f"{what}: a label is not a simple key and value", guard_code="MATRIX_INVALID")
        out.append((k, x))
    return tuple(sorted(out))


def _ns(v: Any, what: str) -> str:
    if type(v) is not str or not re.fullmatch(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?", v):
        raise PolicyBlocked(f"{what}: not a namespace name", guard_code="MATRIX_INVALID")
    return v


def parse_matrix(references: Sequence[Any], *, allow_metadata: bool = False) -> Tuple[Probe, ...]:
    """The declared probes. ``allow_metadata`` is for the policy-state check, which reads objects and sends no traffic."""
    refs = [r for r in references if r.kind == "ConnectivityMatrix"]
    if len(refs) != 1:
        raise PolicyBlocked("exactly one ConnectivityMatrix reference document is expected", guard_code="MATRIX_INVALID", found=len(refs))
    raw = refs[0].spec.get("probes")
    if not isinstance(raw, tuple) or not 1 <= len(raw) <= MAX_PROBES:
        raise LimitExceeded(f"between 1 and {MAX_PROBES} probes are expected")
    seen, out = set(), []
    for p in raw:
        if not isinstance(p, Mapping) or set(p) - {"id", "range_class", "source", "target", "control", "timeout_seconds"}:
            raise PolicyBlocked("a probe has id, range_class, source, target, control and timeout_seconds only", guard_code="MATRIX_INVALID")
        pid = p.get("id")
        if type(pid) is not str or not _ID.fullmatch(pid) or pid in seen:
            raise PolicyBlocked("probe ids are unique short names", guard_code="MATRIX_INVALID")
        seen.add(pid)
        rc = p.get("range_class")
        if rc not in RANGE_CLASSES:
            raise PolicyBlocked("unknown range class", guard_code="MATRIX_INVALID", probe=pid)
        src, tgt, ctl = p.get("source"), p.get("target"), p.get("control")
        if not isinstance(src, Mapping) or not isinstance(tgt, Mapping) or (ctl is not None and not isinstance(ctl, Mapping)):
            raise PolicyBlocked("source and target are objects", guard_code="MATRIX_INVALID", probe=pid)
        proto = tgt.get("protocol", "tcp")
        if proto != "tcp":
            raise Unsupported("traffic.udp-reachability is not expressible: only TCP probes exist", program="traffic.udp-reachability")
        port = tgt.get("port")
        if type(port) is not int or isinstance(port, bool) or not 1 <= port <= 65535:
            raise PolicyBlocked("the port is out of range", guard_code="MATRIX_INVALID", probe=pid)
        ip = tgt.get("ip", "")
        workload = None
        if ("ip" in tgt) == ("workload" in tgt):
            raise PolicyBlocked("a target is an ip or a workload", guard_code="MATRIX_INVALID", probe=pid)
        if "ip" in tgt:
            try:
                if type(ip) is not str:
                    raise ValueError
                addr = ipaddress.ip_address(ip)
            except (ValueError, TypeError):
                raise PolicyBlocked("a probe target is an IP literal, never a name", guard_code="TARGET_NOT_IP_LITERAL", probe=pid) from None
            ip = str(addr)
        else:
            w = tgt["workload"]
            if not isinstance(w, Mapping):
                raise PolicyBlocked("a workload target names a namespace and labels", guard_code="MATRIX_INVALID", probe=pid)
            workload = (_ns(w.get("namespace"), "target workload"), _labels(w.get("labels"), "target workload"))
            if not workload[1]:
                raise PolicyBlocked("a workload target needs labels", guard_code="MATRIX_INVALID", probe=pid)
        if not allow_metadata and (rc == "metadata-endpoint" or (ip and ipaddress.ip_address(ip) in METADATA_NET)):
            raise Unsupported("traffic.metadata-endpoint-proof is not expressible; the compiled policy entry is a policy-state check",
                              program="traffic.metadata-endpoint-proof")
        timeout = p.get("timeout_seconds", 5)
        if type(timeout) is not int or isinstance(timeout, bool) or not 1 <= timeout <= MAX_TIMEOUT_S:
            raise PolicyBlocked("the probe timeout is out of bounds", guard_code="MATRIX_INVALID", probe=pid)
        out.append(Probe(id=pid, range_class=rc, source_namespace=_ns(src.get("namespace"), "source"), source_labels=_labels(src.get("labels"), "source"),
                         target_ip=ip, target_workload=workload, port=port, protocol="tcp",
                         control_namespace=_ns(ctl.get("namespace"), "control") if ctl else "",
                         control_labels=_labels(ctl.get("labels"), "control") if ctl else (), timeout_s=timeout))
    return tuple(out)


def _selector(labels: Tuple[Tuple[str, str], ...]) -> str:
    return ",".join(f"{k}={v}" for k, v in labels)


def resolve_target(session: Any, probe: Probe) -> str:
    """The IP literal for a probe's target; a workload target is read from the cluster (first Running pod by name)."""
    if probe.target_ip:
        return probe.target_ip
    ns, labels = probe.target_workload  # type: ignore[misc]
    res = session.run(["get", "pod", "-n", ns, "-l", _selector(labels), "-o", "json"])
    if res.returncode != 0:
        return ""
    try:
        items = json.loads(res.stdout).get("items") or []
    except ValueError:
        raise EnvironmentFault("pod list is not JSON") from None
    ips = sorted((i["metadata"]["name"], i["status"]["podIP"]) for i in items
                 if isinstance(i, Mapping) and (i.get("status") or {}).get("phase") == "Running" and (i.get("status") or {}).get("podIP"))
    return ips[0][1] if ips else ""


def declared_row(probe: Probe, ip: str, policy: Optional[TargetPolicy]) -> Dict[str, Any]:
    return {"section": "declared", "id": probe.id, "range_class": probe.range_class, "source_namespace": probe.source_namespace,
            "target_kind": "ip" if probe.target_ip else "workload", "target_ip": ip, "port": probe.port, "protocol": probe.protocol,
            "has_control": bool(probe.control_namespace),
            "synthetic_network": (policy.is_synthetic(ip) if (policy is not None and ip) else "")}


# -- traffic -----------------------------------------------------------------------------------------------------------------------

def _run_one(session: Any, pod: Mapping[str, Any], ctx: ProbeContext, track: List[Tuple[str, str]]) -> Dict[str, Any]:
    name, ns = pod["metadata"]["name"], pod["metadata"]["namespace"]
    session.run(["apply", "-f", "-", "-n", ns], stdin=json.dumps(pod, sort_keys=True), timeout_s=60)
    track.append((name, ns))
    phase = ""
    for _ in range(MAX_POLLS):
        got = session.run(["get", "pod", name, "-n", ns, "-o", "json"])
        try:
            phase = (json.loads(got.stdout).get("status") or {}).get("phase", "") if got.returncode == 0 else ""
        except ValueError:
            phase = ""
        if phase in ("Succeeded", "Failed"):
            break
        ctx.sleep(1)
    result, errno = "not_finished", 0
    if phase in ("Succeeded", "Failed"):
        logs = session.run(["logs", name, "-n", ns])
        result = "error"
        lines = [l for l in logs.stdout.splitlines() if l.strip()]
        if logs.returncode == 0 and lines:
            try:
                doc = json.loads(lines[-1])
                if isinstance(doc, Mapping) and doc.get("result") in ("connected", "refused", "timeout", "unreachable", "error", "unsupported"):
                    result, errno = doc["result"], doc.get("errno") if type(doc.get("errno")) is int else 0
            except ValueError:
                pass
    deleted = session.run(["delete", "pod", name, "-n", ns, "--wait=true", "--timeout=60s"])
    if deleted.returncode == 0:
        track.remove((name, ns))
    return {"result": result, "errno": errno, "pod_phase": phase}


def collect_traffic(session: Any, data: Any, ctx: ProbeContext) -> List[Dict[str, Any]]:
    probes = parse_matrix(data.references)
    track: List[Tuple[str, str]] = []

    def cleanup() -> List[str]:
        left = []
        for name, ns in list(track):
            if session.run(["delete", "pod", name, "-n", ns, "--wait=true", "--timeout=60s"]).returncode == 0:
                track.remove((name, ns))
            else:
                left.append(f"{ns}:{name}")
        return left
    ctx.register_cleanup(cleanup)
    from .collectors import lane_document
    rows: List[Dict[str, Any]] = [lane_document(session)]
    for p in probes:
        ip = resolve_target(session, p)
        rows.append(declared_row(p, ip, ctx.target_policy))
        if not ip:
            rows.append({"section": "probe", "id": p.id, "role": "probe", "result": "not_run", "errno": 0, "pod_phase": "", "reason": "target-not-found"})
            continue
        ctx.target_policy.check(ip)                                   # raises unless the address is inside the allowed networks
        roles = [("probe", p.source_namespace, p.source_labels)]
        if p.control_namespace:
            roles.append(("control", p.control_namespace, p.control_labels))
        for role, ns, labels in roles:
            pod = probe_pod(ns, ip, p.port, timeout_s=p.timeout_s, role=role, labels=dict(labels))
            rows.append({"section": "probe", "id": p.id, "role": role, **_run_one(session, pod, ctx, track), "reason": ""})
    return rows


# -- policy state --------------------------------------------------------------------------------------------------------------------

def _match(selector: Any, labels: Mapping[str, str]) -> Optional[bool]:
    sel = selector if isinstance(selector, Mapping) else {}
    if set(sel) - {"matchLabels"}:
        return None
    return all(labels.get(k) == v for k, v in (sel.get("matchLabels") or {}).items())


def _port_ok(ports: Any, port: int) -> bool:
    if not ports:
        return True
    for tp in ports:
        for pp in (tp or {}).get("ports") or []:
            lo = str((pp or {}).get("port", ""))
            hi = (pp or {}).get("endPort")
            if lo.isdigit() and (int(lo) == port or (isinstance(hi, int) and int(lo) <= port <= hi)):
                return True
    return False


def _items(res: Any) -> List[Mapping[str, Any]]:
    if res.returncode != 0:
        raise EnvironmentFault("cannot read network policies", returncode=res.returncode)
    try:
        items = json.loads(res.stdout).get("items")
    except ValueError:
        raise EnvironmentFault("network policy list is not JSON") from None
    return [i for i in items if isinstance(i, Mapping)] if isinstance(items, list) else []


def policy_rows(probe: Probe, ip: str, k8s: Sequence[Mapping[str, Any]], cilium: Sequence[Mapping[str, Any]],
                clusterwide: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    addr = ipaddress.ip_address(ip)
    labels = dict(probe.source_labels)
    deny, allow, selecting = [], [], []
    understood = True
    default_deny = False
    for np in k8s:
        md, sp = np.get("metadata") or {}, np.get("spec") or {}
        if md.get("namespace") != probe.source_namespace:
            continue
        m = _match(sp.get("podSelector"), labels)
        if m is None:
            understood = False
            continue
        types = sp.get("policyTypes") or (["Ingress"] + (["Egress"] if "egress" in sp else []))
        if not m or "Egress" not in types:
            continue
        selecting.append(f"NetworkPolicy/{md.get('name')}")
        rules = sp.get("egress") or []
        if not rules:
            default_deny = True
        for r in rules:
            for peer in (r or {}).get("to") or []:
                blk = (peer or {}).get("ipBlock")
                if isinstance(blk, Mapping) and blk.get("cidr"):
                    try:
                        net = ipaddress.ip_network(blk["cidr"], strict=False)
                    except ValueError:
                        continue
                    if addr in net and not any(addr in ipaddress.ip_network(x, strict=False) for x in blk.get("except") or []) and _port_ok(
                            [{"ports": (r or {}).get("ports") or []}] if (r or {}).get("ports") else None, probe.port):
                        allow.append({"policy": f"NetworkPolicy/{md.get('name')}", "namespace": md.get("namespace", ""), "via": "ip-block", "value": blk["cidr"]})
    for scope, objs in (("namespaced", cilium), ("cluster-wide", clusterwide)):
        for cp in objs:
            md = cp.get("metadata") or {}
            if scope == "namespaced" and md.get("namespace") != probe.source_namespace:
                continue
            specs = [cp.get("spec") or {}] + [s for s in (cp.get("specs") or []) if isinstance(s, Mapping)]
            for sp in specs:
                m = _match(sp.get("endpointSelector"), labels)
                if m is None:
                    understood = False
                    continue
                if not m:
                    continue
                selecting.append(f"{cp.get('kind', 'CiliumNetworkPolicy')}/{md.get('name')}")
                for rule in sp.get("egressDeny") or []:
                    r = rule or {}
                    if not _port_ok(r.get("toPorts"), probe.port):
                        continue
                    for cidr in r.get("toCIDR") or []:
                        try:
                            if addr in ipaddress.ip_network(cidr, strict=False):
                                deny.append({"policy": f"{cp.get('kind', 'CiliumNetworkPolicy')}/{md.get('name')}", "namespace": md.get("namespace", ""),
                                             "via": "cidr", "value": cidr})
                        except ValueError:
                            continue
                    for cs in r.get("toCIDRSet") or []:
                        try:
                            if addr in ipaddress.ip_network((cs or {}).get("cidr", ""), strict=False) and not any(
                                    addr in ipaddress.ip_network(x, strict=False) for x in (cs or {}).get("except") or []):
                                deny.append({"policy": f"{cp.get('kind', 'CiliumNetworkPolicy')}/{md.get('name')}", "namespace": md.get("namespace", ""),
                                             "via": "cidr-set", "value": cs["cidr"]})
                        except ValueError:
                            continue
                    for ent in r.get("toEntities") or []:
                        in_cluster = any(addr in ipaddress.ip_network(n) for n in ("10.244.0.0/16", "10.43.0.0/16"))
                        if ent == "all" or (ent == "world" and not in_cluster):
                            deny.append({"policy": f"{cp.get('kind', 'CiliumNetworkPolicy')}/{md.get('name')}", "namespace": md.get("namespace", ""),
                                         "via": "entity", "value": ent})
    key = lambda d: (d["policy"], d["namespace"], d["via"], d["value"])
    return {"section": "policy_state", "id": probe.id, "source_namespace": probe.source_namespace, "target_ip": ip, "port": probe.port,
            "egress_deny_matches": sorted(deny, key=key), "egress_allow_matches": sorted(allow, key=key),
            "selecting_policies": sorted(set(selecting)), "default_deny_egress_selecting": default_deny, "selector_understood": understood}


def collect_policy_state(session: Any, data: Any, ctx: ProbeContext) -> List[Dict[str, Any]]:
    probes = parse_matrix(data.references, allow_metadata=True)
    k8s = _items(session.run(["get", "networkpolicy", "-A", "-o", "json"]))
    cil = _items(session.run(["get", "ciliumnetworkpolicy.cilium.io", "-A", "-o", "json"]))
    ccnp = _items(session.run(["get", "ciliumclusterwidenetworkpolicy.cilium.io", "-o", "json"]))
    from .collectors import lane_document
    rows: List[Dict[str, Any]] = [lane_document(session)]
    for p in probes:
        ip = resolve_target(session, p)
        rows.append(declared_row(p, ip, None))
        if ip:
            rows.append(policy_rows(p, ip, k8s, cil, ccnp))
        else:
            rows.append({"section": "policy_state", "id": p.id, "source_namespace": p.source_namespace, "target_ip": "", "port": p.port,
                         "egress_deny_matches": [], "egress_allow_matches": [], "selecting_policies": [], "default_deny_egress_selecting": False,
                         "selector_understood": False})
    return rows


CONNECTIVITY_COLLECTORS: Dict[str, Callable[[Any, Any, ProbeContext], List[Dict[str, Any]]]] = {
    "traffic": collect_traffic, "policy-state": collect_policy_state}
