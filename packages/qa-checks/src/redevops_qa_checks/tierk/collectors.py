# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Collectors: what a tier K program has observed from the cluster before it runs (hashed with the program that names it).

A collector takes the guarded session and the loaded manifests and returns observation documents. The first document of every
result identifies the lane, so results from the two node lanes can never be mistaken for one another.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Callable, Dict, List, Sequence

from .drivers import DryRunDriver, StatusDriver


def _thaw(v: Any) -> Any:
    if isinstance(v, Mapping):
        return {k: _thaw(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_thaw(x) for x in v]
    return v


def lane_document(session: Any) -> Dict[str, Any]:
    return {"section": "lane", "lane": session.lane, "kubernetes_version": session.kubernetes_version, "disposable_proof": session.proof_ref}


def collect_dry_run(session: Any, manifests: Sequence[Any]) -> List[Dict[str, Any]]:
    return [lane_document(session)] + DryRunDriver(session).dry_run([_thaw(m.doc) for m in manifests])


def collect_gateway_status(session: Any, manifests: Sequence[Any]) -> List[Dict[str, Any]]:
    return [lane_document(session)] + StatusDriver(session).gateway_status()


def collect_policy_status(session: Any, manifests: Sequence[Any]) -> List[Dict[str, Any]]:
    return [lane_document(session)] + StatusDriver(session).policy_status()


COLLECTORS: Dict[str, Callable[[Any, Sequence[Any]], List[Dict[str, Any]]]] = {
    "dry-run": collect_dry_run, "gateway-status": collect_gateway_status, "policy-status": collect_policy_status}
#: collectors that need manifest inputs (the others read the cluster only)
NEEDS_INPUTS = frozenset({"dry-run"})
