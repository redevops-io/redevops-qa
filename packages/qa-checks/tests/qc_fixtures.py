# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Synthetic manifest fixtures, authored from public Kubernetes and Gateway API schemas. Nothing here is copied from a
real repository; names and registries are placeholders (the ``example.test`` domain is reserved)."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

import yaml

REGISTRY = "registry.example.test/team"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def namespace(name: str, labels: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": dict(labels or {})}}


def container(name: str = "app", image: str = f"{REGISTRY}/app@{DIGEST_A}", *, port: Optional[int] = 8080, probes: bool = True,
              secure: bool = True, resources: bool = True, env: Optional[List[Dict[str, Any]]] = None,
              env_from: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    c: Dict[str, Any] = {"name": name, "image": image}
    if port is not None:
        c["ports"] = [{"containerPort": port, "name": "http"}]
    if probes and port is not None:
        c["readinessProbe"] = {"httpGet": {"path": "/ready", "port": port}, "periodSeconds": 10}
        c["livenessProbe"] = {"httpGet": {"path": "/live", "port": "http"}, "periodSeconds": 20, "failureThreshold": 3}
    if secure:
        c["securityContext"] = {"runAsNonRoot": True, "runAsUser": 10001, "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    if resources:
        c["resources"] = {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "500m", "memory": "256Mi"}}
    if env is not None:
        c["env"] = env
    if env_from is not None:
        c["envFrom"] = env_from
    return c


def deployment(name: str = "app", ns: str = "demo", *, replicas: int = 2, containers: Optional[List[Dict[str, Any]]] = None,
               labels: Optional[Dict[str, str]] = None, pod_spec: Optional[Dict[str, Any]] = None,
               selector: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    lab = labels if labels is not None else {"app": name}
    spec = {"containers": containers if containers is not None else [container()]}
    spec.update(pod_spec or {})
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "namespace": ns, "labels": dict(lab)},
            "spec": {"replicas": replicas, "selector": {"matchLabels": dict(selector if selector is not None else lab)},
                     "template": {"metadata": {"labels": dict(lab)}, "spec": spec}}}


def service(name: str = "app", ns: str = "demo", *, selector: Optional[Dict[str, str]] = None, port: int = 80,
            target: Any = "http") -> Dict[str, Any]:
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": ns},
            "spec": {"selector": dict(selector if selector is not None else {"app": name}),
                     "ports": [{"port": port, "targetPort": target}]}}


def gateway(name: str = "public", ns: str = "infra", *, listeners: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    ls = listeners if listeners is not None else [
        {"name": "https", "port": 443, "protocol": "HTTPS", "hostname": "*.example.test",
         "allowedRoutes": {"namespaces": {"from": "Selector", "selector": {"matchLabels": {"gateway-access": "true"}}}}}]
    return {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
            "metadata": {"name": name, "namespace": ns}, "spec": {"gatewayClassName": "example", "listeners": ls}}


def httproute(name: str = "app", ns: str = "demo", *, gw: str = "public", gw_ns: str = "infra", section: Optional[str] = "https",
              hostnames: Optional[List[str]] = None, matches: Optional[List[Dict[str, Any]]] = None,
              backend: str = "app", filters: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    parent: Dict[str, Any] = {"name": gw, "namespace": gw_ns}
    if section:
        parent["sectionName"] = section
    rule: Dict[str, Any] = {"matches": matches if matches is not None else [{"path": {"type": "PathPrefix", "value": "/"}, "method": "GET"}],
                            "backendRefs": [{"name": backend, "port": 80}]}
    if filters:
        rule["filters"] = filters
    return {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute", "metadata": {"name": name, "namespace": ns},
            "spec": {"parentRefs": [parent], "hostnames": hostnames or ["app.example.test"], "rules": [rule]}}


def netpol(name: str, ns: str = "demo", *, types: Iterable[str] = ("Ingress", "Egress"), ingress: Optional[list] = None,
           egress: Optional[list] = None, pod_selector: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    spec: Dict[str, Any] = {"podSelector": pod_selector if pod_selector is not None else {}, "policyTypes": list(types)}
    if ingress is not None:
        spec["ingress"] = ingress
    if egress is not None:
        spec["egress"] = egress
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": name, "namespace": ns}, "spec": spec}


def cilium_deny(name: str, ns: str = "demo", *, cidrs: Iterable[str] = (), entities: Iterable[str] = (),
                ports: Iterable[tuple] = ()) -> Dict[str, Any]:
    rule: Dict[str, Any] = {}
    if cidrs:
        rule["toCIDR"] = list(cidrs)
    if entities:
        rule["toEntities"] = list(entities)
    if ports:
        rule["toPorts"] = [{"ports": [{"port": str(p), "protocol": proto} for p, proto in ports]}]
    return {"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy", "metadata": {"name": name, "namespace": ns},
            "spec": {"endpointSelector": {}, "egressDeny": [rule]}}


def kyverno_policy(name: str = "require-example", *, action: str = "Enforce", kinds: Iterable[str] = ("Pod",),
                   rule_type: str = "validate") -> Dict[str, Any]:
    body: Dict[str, Any] = {"validate": {"failureAction": action, "message": "example", "pattern": {"spec": {"x": "?*"}}}} \
        if rule_type == "validate" else {rule_type: {}}
    return {"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy", "metadata": {"name": name},
            "spec": {"validationFailureAction": action, "background": False,
                     "rules": [{"name": "r1", "match": {"any": [{"resources": {"kinds": list(kinds)}}]}, **body}]}}


def quota(ns: str = "demo", **hard: str) -> Dict[str, Any]:
    return {"apiVersion": "v1", "kind": "ResourceQuota", "metadata": {"name": "q", "namespace": ns},
            "spec": {"hard": hard or {"requests.cpu": "4", "requests.memory": "8Gi", "limits.cpu": "8", "limits.memory": "16Gi", "pods": "20"}}}


def reference(kind: str, spec: Mapping[str, Any], name: str = "ref") -> Dict[str, Any]:
    return {"apiVersion": "qa-checks/reference-1", "kind": kind, "metadata": {"name": name}, "spec": copy.deepcopy(dict(spec))}


def dump(docs: Iterable[Mapping[str, Any]]) -> str:
    return yaml.safe_dump_all([dict(d) for d in docs], sort_keys=True)


def write_tree(root: Path, files: Mapping[str, Iterable[Mapping[str, Any]]]) -> Path:
    for rel, docs in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(dump(docs), encoding="utf-8")
    return root


def good_set() -> Dict[str, List[Dict[str, Any]]]:
    """A small consistent set: namespace, workload, service, gateway, route, default-deny policies, a Kyverno policy."""
    return {
        "00-namespaces.yaml": [namespace("demo", {"gateway-access": "true", "pod-security.kubernetes.io/enforce": "restricted"}),
                               namespace("infra")],
        "10-app.yaml": [deployment(), service(), quota()],
        "20-gateway.yaml": [gateway(), httproute()],
        "30-policy.yaml": [netpol("default-deny"), kyverno_policy()],
    }
