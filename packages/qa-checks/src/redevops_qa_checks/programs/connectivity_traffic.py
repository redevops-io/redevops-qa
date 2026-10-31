# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Actual traffic: the result of one TCP connection per declared probe, made by a fixed probe pod to an IP literal, beside the
result of the same probe from a control namespace. Evidence kind: traffic."""
from __future__ import annotations

from ._cluster import lane
from ._common import counts_only
from ._connectivity import evaluate_matrix, matrix_counts

PROGRAM_ID = "connectivity.traffic"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Probe results per declared connectivity probe with control results, from fixed probe pods (traffic evidence)"
SUPPORT = ("programs/_common.py", "programs/_cluster.py", "programs/_connectivity.py")
FRAMEWORK = ("tierk/argv.py", "tierk/probes.py", "tierk/subnets.py", "tierk/connectivity.py")
TIER = "K"
COLLECTOR = "traffic"


def run(data):
    rows = evaluate_matrix(data)
    return {"lane": lane(data), "evidence": "traffic", "matrix": rows, "counts": matrix_counts(rows), "input_errors": []}


def run_counts(data):
    out = run(data)
    return {"lane": out["lane"], "evidence": "traffic", "counts": out["counts"], "input_error_count": 0}
