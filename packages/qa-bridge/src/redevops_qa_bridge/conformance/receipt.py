# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``compat-receipt/1``: the machine-readable result of a conformance run (ADR A.2.7).

Counts are integers, versions and hashes are strings, there are no floats, and nothing in it is a secret. ``receipt_hash``
is the sha256 of the canonical JSON (sorted keys, no whitespace) of every other field, the timestamp included.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import deps, __version__
from ..pins import DependencyPin, Pins, tree_digest
from .items import CHECKS
from .model import Evidence
from .pytest_plugin import UNMAPPED

RECEIPT_SCHEMA = "redevops-qa/compat-receipt"
RECEIPT_VERSION = "1"
REDEVOPS_QA_REPO = "redevops-io/redevops-qa"
NO_TESTS = "NO_TESTS_COLLECTED"


def canonical_json(value: Any) -> str:
    def check(v: Any) -> None:
        if isinstance(v, float):
            raise ValueError("a receipt contains no floats")
        if isinstance(v, dict):
            for k, x in v.items():
                if not isinstance(k, str):
                    raise ValueError("receipt keys are strings")
                check(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                check(x)
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def receipt_hash_of(receipt: Dict[str, Any]) -> str:
    body = {k: v for k, v in receipt.items() if k != "receipt_hash"}
    return "sha256:" + hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def seal(receipt: Dict[str, Any]) -> Dict[str, Any]:
    receipt = {k: v for k, v in receipt.items() if k != "receipt_hash"}
    receipt["receipt_hash"] = receipt_hash_of(receipt)
    return receipt


# -- subjects -------------------------------------------------------------------------------------------------------------

def _git(args: List[str], cwd: Path) -> str:
    try:
        out = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def redevops_qa_state(root: Path) -> Dict[str, Any]:
    commit = _git(["rev-parse", "HEAD"], root)
    dirty = bool(_git(["status", "--porcelain"], root)) if commit else True
    tag = _git(["describe", "--tags", "--exact-match", "HEAD"], root) if commit else ""
    return {"repo": REDEVOPS_QA_REPO, "version": __version__, "commit": commit, "tag": tag, "worktree_clean": not dirty}


def _dependency_subject(dep: DependencyPin) -> Dict[str, Any]:
    try:
        digest = tree_digest(dep.resolved_path, dep.distribution_paths)
    except Exception:
        digest = ""
    out = {"repo": dep.repo, "version": dep.version, "tag": dep.tag, "temp_pin": dep.temp_pin, "commit": dep.commit,
           "distribution_digest": "sha256:" + digest if digest else ""}
    if dep.name == "harness_qa":
        out["base_pin"] = dep.base_pin
    return out


def environment() -> Dict[str, Any]:
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    return {"python_version": platform.python_version(), "platform": platform.platform(),
            "interpreter_class": "virtual-environment" if in_venv else "system-or-other",
            "pythonhashseed": os.environ.get("PYTHONHASHSEED", "random")}


def runner_info() -> Dict[str, str]:
    """CI workflow reference and run id. Only these two names are read; nothing credential-like is copied."""
    return {"workflow": os.environ.get("QA_CI_WORKFLOW", "local"), "run_id": os.environ.get("QA_CI_RUN_ID", "local")}


# -- assembling -----------------------------------------------------------------------------------------------------------

def _checks_section(tests: List[Dict[str, Any]], collected_total: int) -> List[Dict[str, Any]]:
    rows = []
    for check_id, name in CHECKS.items():
        mine = [t for t in tests if t["check"] == check_id]
        collected = len(mine)
        passed = sum(1 for t in mine if t["outcome"] == "passed")
        skipped = sum(1 for t in mine if t["outcome"] == "skipped")
        failed = sum(1 for t in mine if t["outcome"] == "failed")
        codes = sorted({t["code"] for t in mine if t["outcome"] == "failed" and t["code"]})
        if collected == 0:
            codes = sorted(set(codes) | {NO_TESTS})
        status = "PASS" if collected > 0 and failed == 0 and skipped == 0 and passed == collected else "FAIL"
        if skipped:
            codes = sorted(set(codes) | {"SKIPPED_TESTS"})
        rows.append({"check_id": check_id, "name": name, "collected": collected, "passed": passed, "failed": failed,
                     "skipped": skipped, "status": status, "failure_codes": codes})
    return rows


def build_receipt(pins: Pins, summary: Dict[str, Any], evidence: Evidence, availability: Dict[str, bool],
                  redevops_root: Path, *, timestamp: Optional[str] = None) -> Dict[str, Any]:
    tests = summary["tests"]
    checks = _checks_section(tests, summary["collected"])
    unmapped = [t for t in tests if t["check"] == UNMAPPED]
    collected = summary["collected"]
    skipped = sum(1 for t in tests if t["outcome"] == "skipped")
    failed = sum(1 for t in tests if t["outcome"] == "failed") + len(summary["collection_errors"])
    state = redevops_qa_state(redevops_root)
    from ..deps import current_state
    cstate, hstate = current_state(pins.contracts), current_state(pins.harness_qa)
    golden_sha = cstate.get("vector_files", {}).get("golden/qa.json", "") if isinstance(cstate, dict) else ""
    schemas = evidence.schemas if evidence.schemas is not None else []
    info = evidence.schema_info
    all_checks_pass = all(c["status"] == "PASS" for c in checks)
    result = "PASS" if (all_checks_pass and collected > 0 and skipped == 0 and failed == 0 and not unmapped
                        and all(availability.values()) and state["worktree_clean"] and bool(state["commit"])) else "FAIL"
    receipt = {
        "receipt_schema": RECEIPT_SCHEMA, "receipt_version": RECEIPT_VERSION, "result": result,
        "subjects": {"pin_set": pins.pin_set, "contracts": _dependency_subject(pins.contracts),
                     "harness_qa": _dependency_subject(pins.harness_qa), "redevops_qa": state},
        "environment": environment(),
        "schema_ids": {"contract_id": info.get("contract_id", ""), "neutral_api": info.get("neutral_api", ""),
                       "hash_algorithms": {"contracts": "rcv1", "neutral": "canon-v1"}, "schemas": schemas,
                       "contracts_only": info.get("contracts_only", [])},
        "dependencies_available": {"contracts": bool(availability.get("contracts")),
                                   "harness_qa": bool(availability.get("harness_qa"))},
        "vectors": {"items": evidence.sorted_vectors(),
                    "contracts_golden_qa_json_sha256": golden_sha,
                    "contracts_vector_files_sha256": dict(sorted(cstate.get("vector_files", {}).items())),
                    "harness_vector_files_sha256": dict(sorted(hstate.get("vector_files", {}).items()))},
        "checks": checks,
        "collected_tests": collected, "skipped_tests": skipped, "failed_tests": failed,
        "timestamp_utc": timestamp or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "runner": runner_info(),
    }
    return seal(receipt)
