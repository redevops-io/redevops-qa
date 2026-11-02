# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The operator's limits from the environment (``REDEVOPS_QA_READ_TIMEOUT``, ``REDEVOPS_QA_BUNDLE_READ_TIMEOUT``, ``REDEVOPS_QA_MAX_EVIDENCE_BYTES``), parsed strictly: a finite positive number inside
a sane range, or a ``PlanError`` (exit 2, a message that names the variable). Never a traceback, never ``nan`` or ``inf`` or a huge number that would amount to no limit, never zero."""
from __future__ import annotations

import math
import os
import re
from typing import Optional

from qa_evidence.canon import safe_text

from .errors import PlanError

MAX_SECONDS = 3600.0
MAX_BYTES = 8 * 1024 ** 3
MIN_BYTES = 1024
_NUMBER = re.compile(r"^[0-9]{1,6}(\.[0-9]{1,6})?$")
_INTEGER = re.compile(r"^[0-9]{1,13}$")


def env_seconds(name: str, default: float) -> float:
    """Seconds from the environment variable ``name`` (1 to 3600), or ``default`` when it is not set or empty."""
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    value: Optional[float] = float(raw) if _NUMBER.fullmatch(raw) else None
    if value is None or not math.isfinite(value) or not 1.0 <= value <= MAX_SECONDS:
        raise PlanError("BAD_ENV_LIMIT", f"{name} must be a number of seconds from 1 to {int(MAX_SECONDS)}, got {safe_text(raw, 40)!r}")
    return value


def env_bytes(name: str, default: int) -> int:
    """A number of bytes from the environment variable ``name`` (1024 to 8 GiB), or ``default`` when it is not set or empty."""
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    value = int(raw) if _INTEGER.fullmatch(raw) else None
    if value is None or not MIN_BYTES <= value <= MAX_BYTES:
        raise PlanError("BAD_ENV_LIMIT", f"{name} must be a whole number of bytes from {MIN_BYTES} to {MAX_BYTES}, got {safe_text(raw, 40)!r}")
    return value
