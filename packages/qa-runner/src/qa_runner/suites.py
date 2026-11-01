# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The Robot suites this release ships, reviewed and hashed, and the check program that reads what they record.

A Robot lane names a suite (``"suite": "order-discount"``). ``freeze`` hashes the suite's files (and the registered check program) into the lock; the run copies the
files into the lane's workspace, requires the copies to hash as frozen, and gives the Robot adapter the library file's hash as the only reviewed library. A suite or
library that changed after the plan was frozen is refused before anything runs."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Tuple

from .errors import PlanError

SUITE_DIR = Path(__file__).resolve().parent / "robot_suite"
SUITES: Dict[str, Dict[str, object]] = {
    "order-discount": {"files": ("order_discount.robot", "OrderApi.py"), "library": "OrderApi.py", "suite": "order_discount.robot"},
}
EVIDENCE_PROGRAM_ID = "evidence.robot-observations"
EVIDENCE_PROGRAM_VERSION = "1.0.0"
OBSERVATIONS_PATH_FORMAT = "lanes/{lane_id}/observations.json"


def suite_files(name: str) -> Dict[str, bytes]:
    if name not in SUITES:
        raise PlanError("UNKNOWN_SUITE", f"no suite named {str(name)[:40]!r} (this release ships: {', '.join(sorted(SUITES))})")
    out = {}
    for rel in SUITES[name]["files"]:                                    # type: ignore[union-attr]
        path = SUITE_DIR / rel
        out[rel] = path.read_bytes()
    return out


def suite_digests(name: str) -> Dict[str, str]:
    return {rel: "sha256:" + hashlib.sha256(data).hexdigest() for rel, data in sorted(suite_files(name).items())}


def evidence_program_ref() -> Dict[str, str]:
    """The ``check_program_ref`` of ``evidence.robot-observations`` as registered now: id, version and the hash of its source bundle."""
    from redevops_qa_checks.registry import evidence_registry
    h = evidence_registry().registered_program_hash(EVIDENCE_PROGRAM_ID, EVIDENCE_PROGRAM_VERSION)
    return {"id": EVIDENCE_PROGRAM_ID, "version": EVIDENCE_PROGRAM_VERSION, "program_hash": h}
