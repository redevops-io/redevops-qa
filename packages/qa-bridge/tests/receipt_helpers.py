# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Builders shared by the receipt, verifier and CLI tests."""
import subprocess
from pathlib import Path

from redevops_qa_bridge.conformance.items import CHECKS
from redevops_qa_bridge.conformance.model import Evidence


def git(root: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True,
                          env={"PATH": "/usr/bin:/bin", "HOME": str(root), "GIT_CONFIG_NOSYSTEM": "1"})
    return done.stdout.strip()


def make_repo(root: Path, *, commit: bool = True) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@example.invalid")
    git(root, "config", "user.name", "t")
    (root / "f.txt").write_text("x\n")
    git(root, "add", "f.txt")
    if commit:
        git(root, "commit", "-q", "-m", "init")
    return root


def summary(per_check=3, *, failed=(), skipped=(), drop=(), unmapped=0, collection_errors=(), pins=None):
    """A pytest summary with ``per_check`` passing tests per check; ``failed``/``skipped`` name checks that get one
    failing/skipped test instead of one passing; ``drop`` removes a check's tests entirely."""
    tests = []
    for check in CHECKS:
        if check in drop:
            continue
        for i in range(per_check):
            outcome = "passed"
            code = None
            if i == 0 and check in failed:
                outcome, code = "failed", "HASH_DIVERGENCE"
            if i == 0 and check in skipped:
                outcome = "skipped"
            tests.append({"nodeid": f"t.py::test_item[{check}-{i}]", "check": check, "outcome": outcome, "code": code,
                          "message": "", "details": {}})
    for n in (pins.not_applicable if pins is not None else ()):
        tests.append({"nodeid": f"t.py::test_item[{n.item}]", "check": n.check, "item": n.item, "outcome": "not_applicable",
                      "code": None, "message": "", "details": {}})
    for i in range(unmapped):
        tests.append({"nodeid": f"t.py::test_stray[{i}]", "check": "UNMAPPED", "outcome": "passed", "code": None,
                      "message": "", "details": {}})
    return {"collected": len(tests), "collection_errors": list(collection_errors), "tests": tests}


def evidence(pins=None):
    ev = Evidence()
    for n in (pins.not_applicable if pins is not None else ()):
        ev.not_applicable[(n.check, n.item)] = {"real_item_result": "FAIL:ENUM_PARITY"}
    ev.vector("v1", "contracts_golden", "canon-v1:" + "a" * 64, "rcv1:" + "a" * 64, "rcv1:" + "a" * 64, True)
    ev.schemas = [{"schema_id": "runtime-contracts/qa/checkpoint", "contracts_schema_version": "0.1",
                   "neutral_schema_version": "0.1", "equal": True}]
    ev.schema_info = {"contract_id": "qa/v1", "neutral_api": "qa-neutral/1", "contracts_only": []}
    return ev
