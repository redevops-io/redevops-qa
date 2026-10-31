# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Drivers that turn kubectl responses from a guarded session into observation documents.

* ``DryRunDriver``: one server-side dry-run apply per object (``--dry-run=server`` persists nothing); the API server's answer is
  recorded and the rejection text is classified (admission webhook, Pod Security, quota, limit range, schema, unknown kind).
* ``StatusDriver``: reads Gateway, route, policy, quota and limit range status from objects that bring-up already created.

Everything goes through a ``GuardedSession``; a driver holds no runner. The classification works on text produced by the API
server and is a hypothesis until it has been compared with a real cluster's responses; anything it does not recognise is
reported as ``other`` with the message, never as an acceptance.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any, Dict, List, Optional, Sequence

from ..errors import EnvironmentFault, LimitExceeded

MAX_OBJECTS = 200
MESSAGE_LIMIT = 400
_LAYERS = ("apiserver", "kyverno", "admission_webhook", "pod_security", "resource_quota", "limit_range", "none")


def _squash(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def warnings_from(stderr: str) -> List[str]:
    return [_squash(l[len("Warning:"):]) for l in stderr.splitlines() if l.startswith("Warning:")][:20]


def classify_rejection(stderr: str) -> Dict[str, Any]:
    """Observed facts about a rejection message. ``layer`` says which part of the admission chain spoke."""
    low = stderr.lower()
    out: Dict[str, Any] = {"error_class": "other", "layer": "apiserver", "policies": [], "pod_security_level": "", "pod_security_checks": [],
                           "quota_name": "", "message": _squash(stderr)[:MESSAGE_LIMIT]}
    if "no matches for kind" in low or "ensure crds are installed" in low or "unable to recognize" in low:
        out["error_class"] = "kind_not_known"
    elif "admission webhook" in low and "denied the request" in low:
        out["layer"] = "kyverno" if "kyverno" in low else "admission_webhook"
        out["error_class"] = "admission_denied"
        block = stderr.split("following policies", 1)[1] if "following policies" in stderr else ""
        out["policies"] = sorted(set(re.findall(r"^\s*([a-z0-9][-a-z0-9.]*):\s*$", block, re.M)))
    elif "violates podsecurity" in low:
        out["layer"], out["error_class"] = "pod_security", "pod_security_violation"
        m = re.search(r'violates PodSecurity "([^"]+)"', stderr)
        out["pod_security_level"] = m.group(1) if m else ""
        tail = stderr.split("violates PodSecurity", 1)[1].split(":", 1)[1] if ":" in stderr.split("violates PodSecurity", 1)[1] else ""
        out["pod_security_checks"] = sorted(set(re.findall(r"(?:^|, |: )([A-Za-z][A-Za-z0-9 !=<>./_-]*?) \(", _squash(tail))))
    elif "exceeded quota" in low:
        out["layer"], out["error_class"] = "resource_quota", "quota_exceeded"
        m = re.search(r"exceeded quota: ([^,]+),", stderr)
        out["quota_name"] = m.group(1).strip() if m else ""
    elif ("maximum" in low or "minimum" in low) and "usage per" in low and "limit" in low:
        out["layer"], out["error_class"] = "limit_range", "limit_range_violation"
    elif "unknown field" in low or "strict decoding error" in low:
        out["error_class"] = "schema_unknown_field"
    elif "is invalid" in low or "invalid value" in low or "required value" in low:
        out["error_class"] = "schema_invalid"
    elif "namespaces" in low and "not found" in low:
        out["error_class"] = "namespace_not_found"
    elif "forbidden" in low:
        out["error_class"] = "forbidden_other"
    return out


def _doc(doc: Mapping[str, Any]) -> str:
    return json.dumps(doc, sort_keys=True)


def _identity(doc: Mapping[str, Any]) -> Dict[str, str]:
    md = doc.get("metadata") if isinstance(doc.get("metadata"), Mapping) else {}
    return {"api_version": str(doc.get("apiVersion", "")), "kind": str(doc.get("kind", "")), "namespace": str(md.get("namespace", "")),
            "name": str(md.get("name", ""))}


class DryRunDriver:
    def __init__(self, session: Any) -> None:
        self._s = session

    def dry_run(self, docs: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        if len(docs) > MAX_OBJECTS:
            raise LimitExceeded(f"more than {MAX_OBJECTS} objects in one dry run", count=len(docs))
        rows = []
        for i, d in enumerate(docs):
            res = self._s.run(["apply", "--dry-run=server", "--validate=strict", "-f", "-", "-o", "json"], stdin=_doc(d), timeout_s=60)
            row: Dict[str, Any] = {"section": "dry_run", "index": i, **_identity(d), "returncode": res.returncode,
                                   "warnings": warnings_from(res.stderr)}
            if res.returncode == 0:
                row.update({"response": "accepted", "error_class": "", "layer": "none", "policies": [], "pod_security_level": "",
                            "pod_security_checks": [], "quota_name": "", "message": ""})
            else:
                row.update({"response": "rejected", **classify_rejection(res.stderr)})
            rows.append(row)
        return rows


def _items(res: Any, what: str) -> List[Mapping[str, Any]]:
    if res.returncode != 0:
        raise EnvironmentFault(f"cannot read {what}", returncode=res.returncode)
    try:
        doc = json.loads(res.stdout)
    except ValueError:
        raise EnvironmentFault(f"{what} is not JSON") from None
    items = doc.get("items") if isinstance(doc, Mapping) else None
    return [x for x in items if isinstance(x, Mapping)] if isinstance(items, list) else ([doc] if isinstance(doc, Mapping) else [])


def _conds(v: Any) -> List[Dict[str, str]]:
    out = []
    for c in v if isinstance(v, list) else []:
        if isinstance(c, Mapping):
            out.append({"type": str(c.get("type", "")), "status": str(c.get("status", "")), "reason": str(c.get("reason", ""))})
    return sorted(out, key=lambda c: c["type"])


class StatusDriver:
    def __init__(self, session: Any) -> None:
        self._s = session

    def gateway_status(self) -> List[Dict[str, Any]]:
        rows = []
        for g in _items(self._s.run(["get", "gateway.gateway.networking.k8s.io", "-A", "-o", "json"]), "gateways"):
            md, st = g.get("metadata") or {}, g.get("status") or {}
            listeners = []
            for l in st.get("listeners") or []:
                if isinstance(l, Mapping):
                    listeners.append({"name": str(l.get("name", "")), "attached_routes": l.get("attachedRoutes") if type(l.get("attachedRoutes")) is int else None,
                                      "conditions": _conds(l.get("conditions"))})
            rows.append({"section": "gateway", "namespace": str(md.get("namespace", "")), "name": str(md.get("name", "")),
                         "conditions": _conds(st.get("conditions")), "listeners": sorted(listeners, key=lambda l: l["name"]),
                         "address_count": len(st.get("addresses") or [])})
        for r in _items(self._s.run(["get", "httproute.gateway.networking.k8s.io", "-A", "-o", "json"]), "routes"):
            md, st = r.get("metadata") or {}, r.get("status") or {}
            parents = []
            for p in st.get("parents") or []:
                if isinstance(p, Mapping):
                    ref = p.get("parentRef") or {}
                    parents.append({"gateway_namespace": str(ref.get("namespace", "")), "gateway": str(ref.get("name", "")),
                                    "section_name": str(ref.get("sectionName", "")), "controller": str(p.get("controllerName", "")),
                                    "conditions": _conds(p.get("conditions"))})
            rows.append({"section": "route", "namespace": str(md.get("namespace", "")), "name": str(md.get("name", "")),
                         "parents": sorted(parents, key=lambda p: (p["gateway_namespace"], p["gateway"], p["section_name"]))})
        return sorted(rows, key=lambda r: (r["section"], r["namespace"], r["name"]))

    def policy_status(self) -> List[Dict[str, Any]]:
        rows = []
        for p in _items(self._s.run(["get", "clusterpolicy.kyverno.io", "-o", "json"]), "cluster policies"):
            md, st = p.get("metadata") or {}, p.get("status") or {}
            rows.append({"section": "policy", "name": str(md.get("name", "")), "ready": st.get("ready") if isinstance(st.get("ready"), bool) else None,
                         "conditions": _conds(st.get("conditions"))})
        for q in _items(self._s.run(["get", "resourcequota", "-A", "-o", "json"]), "resource quotas"):
            md, st = q.get("metadata") or {}, q.get("status") or {}
            rows.append({"section": "quota", "namespace": str(md.get("namespace", "")), "name": str(md.get("name", "")),
                         "hard": sorted([k, str(v)] for k, v in (st.get("hard") or {}).items()),
                         "used": sorted([k, str(v)] for k, v in (st.get("used") or {}).items())})
        for l in _items(self._s.run(["get", "limitrange", "-A", "-o", "json"]), "limit ranges"):
            md, sp = l.get("metadata") or {}, l.get("spec") or {}
            rows.append({"section": "limit_range", "namespace": str(md.get("namespace", "")), "name": str(md.get("name", "")),
                         "types": sorted(str((x or {}).get("type", "")) for x in sp.get("limits") or [])})
        return sorted(rows, key=lambda r: (r["section"], r.get("namespace", ""), r["name"]))
