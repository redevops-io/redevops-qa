# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A fake cluster behind the ``KubectlRunner`` protocol, and builders for the local state a generated cluster leaves behind.

The fake never starts a process. It answers the allow-listed commands from data, records every call, and can be told to answer
as another cluster would (no marker object, another marker, another version)."""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from redevops_qa_checks.tierk import guard as G
from redevops_qa_checks.tierk.plan import build_plan
from redevops_qa_checks.tierk.runner import KubectlResult

PLAN = build_plan()


def kubeconfig_bytes(cluster: str, server: str, *, extra_user: Optional[Dict[str, Any]] = None, extra_cluster: Optional[Dict[str, Any]] = None,
                     contexts: int = 1) -> bytes:
    ctx = f"kind-{cluster}"
    user: Dict[str, Any] = {"client-certificate-data": base64.b64encode(b"cert-placeholder").decode(),
                            "client-key-data": base64.b64encode(b"key-placeholder").decode()}
    user.update(extra_user or {})
    cl: Dict[str, Any] = {"server": server, "certificate-authority-data": base64.b64encode(b"ca-placeholder").decode()}
    cl.update(extra_cluster or {})
    doc: Dict[str, Any] = {"apiVersion": "v1", "kind": "Config", "current-context": ctx,
                           "clusters": [{"name": ctx, "cluster": cl}],
                           "contexts": [{"name": ctx, "context": {"cluster": ctx, "user": ctx}}],
                           "users": [{"name": ctx, "user": user}]}
    if contexts > 1:
        doc["contexts"].append({"name": "other", "context": {"cluster": ctx, "user": ctx}})
    return json.dumps(doc, sort_keys=True).encode()


def make_entry(lane: str = "primary", *, server: Optional[str] = None, nonce: str = "n" * 32, plan_sha256: Optional[str] = None,
               version: Optional[str] = None, kubeconfig: Optional[bytes] = None) -> Tuple[G.MarkerEntry, bytes]:
    l = PLAN.lane(lane)
    server = server or f"https://127.0.0.1:{l['api_server_port']}"
    kc = kubeconfig if kubeconfig is not None else kubeconfig_bytes(l["cluster_name"], server)
    entry = G.MarkerEntry(lane=lane, cluster_name=l["cluster_name"], context_name=l["context_name"], kubeconfig_file=f"{lane}.kubeconfig",
                          kubeconfig_sha256=hashlib.sha256(kc).hexdigest(), server=server, nonce=nonce,
                          plan_sha256=plan_sha256 or PLAN.plan_sha256, kubernetes_version=version or l["kubernetes_version"])
    return entry, kc


def make_state(tmp: Path, lanes: Sequence[str] = ("primary",), **kw: Any) -> Tuple[Path, Dict[str, G.MarkerEntry]]:
    state = G.write_state_dir(tmp / "state")
    entries = {}
    for lane in lanes:
        entry, kc = make_entry(lane, **kw)
        G.register_cluster(state, entry, kc)
        entries[lane] = entry
    return state, entries


def make_guard(state: Path, **kw: Any) -> G.TierKGuard:
    return G.TierKGuard(state, plan_sha256=kw.pop("plan_sha256", PLAN.plan_sha256), lanes=kw.pop("lanes", PLAN.lane_versions()), **kw)


class FakeCluster:
    """Implements ``KubectlRunner``. ``dry_run`` maps an object name to ``(returncode, stderr)``."""

    def __init__(self, entry: G.MarkerEntry, *, marker: Optional[Dict[str, Any]] = "auto", server_version: Optional[str] = None,
                 dry_run: Optional[Mapping[str, Tuple[int, str]]] = None, objects: Optional[Dict[str, Any]] = None) -> None:
        self.entry = entry
        self.marker = G.marker_object(entry) if marker == "auto" else marker
        self.server_version = server_version or entry.kubernetes_version
        self.dry_run_answers = dict(dry_run or {})
        self.objects = dict(objects or {})
        self.calls: List[Tuple[List[str], Optional[str]]] = []

    def run(self, args: Sequence[str], *, stdin: Optional[str] = None, timeout_s: int = 60) -> KubectlResult:
        args = list(args)
        self.calls.append((args, stdin))
        if args == ["version", "-o", "json"]:
            return KubectlResult(0, json.dumps({"serverVersion": {"gitVersion": self.server_version}}))
        if args[:3] == ["get", "configmap", "qa-disposable-marker"]:
            if self.marker is None:
                return KubectlResult(1, "", 'Error from server (NotFound): configmaps "qa-disposable-marker" not found')
            return KubectlResult(0, json.dumps(self.marker))
        if args[:4] == ["apply", "--dry-run=server", "--validate=strict", "-f"]:
            doc = json.loads(stdin or "{}")
            name = doc.get("metadata", {}).get("name", "")
            rc, err = self.dry_run_answers.get(name, (0, ""))
            return KubectlResult(rc, json.dumps(doc) if rc == 0 else "", err)
        if args[0] == "get":
            key = args[1]
            return KubectlResult(0, json.dumps(self.objects.get(key, {"items": []})))
        return KubectlResult(1, "", "fake: not handled")

    def mutating_calls(self) -> List[List[str]]:
        return [a for a, _ in self.calls if a[0] in ("create", "delete") or (a[0] == "apply" and "--dry-run=server" not in a)]

    def non_marker_calls(self) -> List[List[str]]:
        return [a for a, _ in self.calls if a[:3] != ["get", "configmap", "qa-disposable-marker"] and a != ["version", "-o", "json"]]


def open_session(tmp: Path, lane: str = "primary", *, fake_kw: Optional[Dict[str, Any]] = None, **session_kw: Any):
    from redevops_qa_checks.tierk.guard import GuardedSession, local_for_lane
    state, entries = make_state(tmp, (lane,))
    guard = make_guard(state)
    local = local_for_lane(guard, lane)
    fake = FakeCluster(entries[lane], **(fake_kw or {}))
    return GuardedSession(guard, local, fake, **session_kw), fake, guard, state, entries[lane]
