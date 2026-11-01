# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The engine-side (native) status of a lane, derived from what the engine itself wrote. The run uses these functions to fill the report; ``verify`` uses them again over the files
of a bundle, so a report whose native status was relabelled (a FAIL written as a PASS) disagrees with the native files it sits next to. None of this is a verdict."""
from __future__ import annotations

from typing import Any, Mapping, Optional, Tuple


def native_from_harness(outcome: str, reason: Optional[str]) -> Tuple[str, str]:
    """A browser lane: the harness executor's outcome. PASS maps to NATIVE_PASS only: it is never a verdict."""
    if outcome == "PASS":
        return "NATIVE_PASS", "PASS"
    if outcome == "PRODUCT_FAIL":
        return "NATIVE_FAIL", "PRODUCT_FAIL"
    if reason and "DEADLINE" in str(reason).upper():
        return "NATIVE_TIMEOUT", outcome
    return "NATIVE_ERROR", outcome


def native_from_adapter_result(status: Any, error_code: Any) -> Optional[Tuple[str, str]]:
    """A Robot lane: the Robot adapter's native result (kit statuses PASS, FAIL, SKIP, ERROR). ``None`` for anything else (an unknown status is not mapped to a pass)."""
    if status == "PASS":
        return "NATIVE_PASS", "PASS"
    if status == "FAIL":
        return "NATIVE_FAIL", "FAIL"
    if status == "SKIP":
        return "NATIVE_SKIPPED", "SKIP"
    if status == "ERROR":
        if error_code == "TIMEOUT":
            return "NATIVE_TIMEOUT", "timeout"
        if error_code == "CANCELLED":
            return "NATIVE_ERROR", "cancelled"
        if error_code == "SPAWN_FAILED":
            return "NATIVE_UNAVAILABLE", "spawn-failed"
        return "NATIVE_ERROR", ("error-" + str(error_code or "unknown")).lower()[:60]
    return None
