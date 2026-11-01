# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The exit status of a run, from its report. ``run``, ``demo`` and ``verify`` use the same table, so the separate-process verification of a bundle reproduces the status the run returned."""
from __future__ import annotations

from typing import Any, Mapping

from . import constants as K


def exit_code_for(report: Mapping[str, Any], cancelled: bool = False) -> int:
    outcome = report["verdict"]["outcome"]
    if outcome == "VERIFIED":
        return K.EXIT_VERIFIED
    if outcome == "FAILED":
        return K.EXIT_FAILED
    if cancelled or any(l["native"]["status"] not in ("NATIVE_PASS", "NATIVE_FAIL") for l in report["lanes"]):
        return K.EXIT_ENVIRONMENT
    return K.EXIT_INCONCLUSIVE
