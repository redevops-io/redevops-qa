# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Policy state: which network policy objects select each declared probe's source and match its target, read from the cluster.
No traffic is sent. Evidence kind: policy-state (never proof of traffic)."""
from __future__ import annotations

from ._cluster import lane
from ._connectivity import evaluate_policy_state, policy_counts

PROGRAM_ID = "connectivity.policy-state"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Network policy objects selecting each declared probe source and matching its target (policy-state evidence)"
SUPPORT = ("programs/_common.py", "programs/_cluster.py", "programs/_connectivity.py")
FRAMEWORK = ("tierk/argv.py", "tierk/subnets.py", "tierk/connectivity.py")
TIER = "K"
COLLECTOR = "policy-state"


def run(data):
    rows = evaluate_policy_state(data)
    return {"lane": lane(data), "evidence": "policy-state", "matrix": rows, "counts": policy_counts(rows), "input_errors": []}


def run_counts(data):
    out = run(data)
    return {"lane": out["lane"], "evidence": "policy-state", "counts": out["counts"], "input_error_count": 0}
