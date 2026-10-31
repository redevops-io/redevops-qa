# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Verify a ``compat-receipt/1``: its hash, its own consistency, and whether it is still current.

Statuses, worst first: ``TAMPERED`` (the hash does not verify), ``INVALID`` (not a well-formed or self-consistent
receipt), ``STALE`` (some pin differs from what the receipt was produced against), ``FAILED`` (hash verifies and the
receipt is current, but its result is not PASS), ``VALID``. A receipt blocks a release approval unless it is ``VALID``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..deps import current_state
from ..pins import DependencyPin, Pins
from .items import CHECKS
from .receipt import RECEIPT_SCHEMA, RECEIPT_VERSION, receipt_hash_of, redevops_qa_state

EXIT = {"VALID": 0, "FAILED": 1, "INVALID": 1, "TAMPERED": 1, "STALE": 2}
_TOP = ("receipt_schema", "receipt_version", "result", "subjects", "environment", "schema_ids", "dependencies_available",
        "vectors", "checks", "collected_tests", "skipped_tests", "failed_tests", "timestamp_utc", "runner", "receipt_hash")


def _has_float(v: Any) -> bool:
    if isinstance(v, float):
        return True
    if isinstance(v, dict):
        return any(_has_float(x) for x in v.values())
    if isinstance(v, list):
        return any(_has_float(x) for x in v)
    return False


def consistency_problems(r: Dict[str, Any]) -> List[str]:
    problems = []
    for key in _TOP:
        if key not in r:
            problems.append(f"missing field {key}")
    if problems:
        return problems
    if r["receipt_schema"] != RECEIPT_SCHEMA or r["receipt_version"] != RECEIPT_VERSION:
        problems.append("not a redevops-qa/compat-receipt version 1")
    if _has_float(r):
        problems.append("a receipt contains no floats")
    ids = [c.get("check_id") for c in r["checks"]]
    if ids != list(CHECKS):
        problems.append(f"the receipt must hold exactly the seven checks in order, found {ids}")
        return problems
    for c in r["checks"]:
        if c["collected"] != c["passed"] + c["failed"] + c["skipped"]:
            problems.append(f"{c['check_id']}: collected is not passed + failed + skipped")
        want = "PASS" if c["collected"] > 0 and c["failed"] == 0 and c["skipped"] == 0 and c["passed"] == c["collected"] else "FAIL"
        if c["status"] != want:
            problems.append(f"{c['check_id']}: status {c['status']} contradicts its counts")
    if sum(c["collected"] for c in r["checks"]) > r["collected_tests"]:
        problems.append("the checks collected more tests than the receipt total")
    if sum(c["skipped"] for c in r["checks"]) > r["skipped_tests"] or sum(c["failed"] for c in r["checks"]) > r["failed_tests"]:
        problems.append("the totals are smaller than the sum over the checks")
    if r["result"] == "PASS":
        clean = r["subjects"].get("redevops_qa", {}).get("worktree_clean") is True
        if not (all(c["status"] == "PASS" for c in r["checks"]) and r["collected_tests"] > 0 and r["skipped_tests"] == 0
                and r["failed_tests"] == 0 and all(r["dependencies_available"].values()) and clean):
            problems.append("result is PASS but a check failed, nothing was collected, a test was skipped or failed, a "
                            "dependency was unavailable or the working tree was not clean")
    elif r["result"] != "FAIL":
        problems.append(f"result must be PASS or FAIL, not {r['result']!r}")
    for item in r["vectors"].get("items", []):
        if item.get("equal") is not (len({_digest(item[k]) for k in ("canon_v1_hash", "rcv1_hash", "golden_hash")}) == 1):
            problems.append(f"vector {item.get('vector_id')}: the equal flag contradicts its hashes")
            break
    return problems


def _digest(h: str) -> str:
    return h.split(":", 1)[-1] if isinstance(h, str) else ""


def _dependency_differences(name: str, recorded: Dict[str, Any], dep: DependencyPin, vectors_recorded: Dict[str, str],
                            ) -> List[str]:
    diff = []
    state = current_state(dep)
    expected = {"repo": dep.repo, "version": dep.version, "tag": dep.tag, "commit": dep.commit}
    if name == "harness_qa":
        expected["base_pin"] = dep.base_pin
    for key, want in expected.items():
        if recorded.get(key) != want:
            diff.append(f"{name}.{key}: receipt {recorded.get(key)!r}, pins {want!r}")
    live = state.get("distribution_sha256", "")
    if recorded.get("distribution_digest") != ("sha256:" + live if live else ""):
        diff.append(f"{name}.distribution_digest: receipt {recorded.get('distribution_digest')!r}, installed "
                    f"{'sha256:' + live if live else None!r}")
    if live != dep.distribution_sha256:
        diff.append(f"{name}: the installed tree is not the pinned one (digest {live!r} vs pinned "
                    f"{dep.distribution_sha256!r})")
    live_files = state.get("vector_files", {})
    for rel in sorted(set(live_files) | set(vectors_recorded)):
        if live_files.get(rel) != vectors_recorded.get(rel):
            diff.append(f"{name} vector file {rel}: receipt {vectors_recorded.get(rel)!r}, current {live_files.get(rel)!r}")
    for rel, want in dep.vector_files.items():
        if live_files.get(rel) != want:
            diff.append(f"{name} vector file {rel} differs from pins.toml")
    return diff


def stale_reasons(r: Dict[str, Any], pins: Pins, redevops_root: Optional[Path]) -> List[str]:
    diff: List[str] = []
    subjects = r["subjects"]
    if subjects.get("pin_set") != pins.pin_set:
        diff.append(f"pin set: receipt {subjects.get('pin_set')!r}, selected {pins.pin_set!r}")
    vec = r["vectors"]
    diff += _dependency_differences("contracts", subjects["contracts"], pins.contracts, vec["contracts_vector_files_sha256"])
    diff += _dependency_differences("harness_qa", subjects["harness_qa"], pins.harness_qa, vec["harness_vector_files_sha256"])
    if redevops_root is not None:
        now = redevops_qa_state(redevops_root)
        recorded = subjects["redevops_qa"]
        if recorded.get("commit") != now["commit"]:
            diff.append(f"redevops_qa.commit: receipt {recorded.get('commit')!r}, now {now['commit']!r}")
    return diff


def verify_receipt(path: Path, pins: Pins, *, redevops_root: Optional[Path] = None) -> Tuple[str, List[str]]:
    """``(status, reasons)``."""
    try:
        with open(path, encoding="utf-8") as handle:
            receipt = json.load(handle)
    except (OSError, ValueError) as exc:
        return "INVALID", [f"unreadable receipt: {exc}"]
    if not isinstance(receipt, dict) or "receipt_hash" not in receipt:
        return "INVALID", ["not a receipt (no receipt_hash)"]
    try:
        recomputed = receipt_hash_of(receipt)
    except ValueError as exc:
        return "INVALID", [str(exc)]
    if recomputed != receipt["receipt_hash"]:
        return "TAMPERED", [f"receipt_hash {receipt['receipt_hash']} does not match the recomputed {recomputed}"]
    problems = consistency_problems(receipt)
    if problems:
        return "INVALID", problems
    stale = stale_reasons(receipt, pins, redevops_root)
    if stale:
        return "STALE", stale
    if receipt["result"] != "PASS":
        failing = [f"{c['check_id']} {c['name']}: {', '.join(c['failure_codes'])}" for c in receipt["checks"]
                   if c["status"] != "PASS"]
        return "FAILED", ["the receipt's result is FAIL"] + failing
    return "VALID", []
