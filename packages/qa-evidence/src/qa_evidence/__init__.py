# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Portable QA evidence bundle: layout, run-report schema, reader and offline verifier. Standard library only."""
from __future__ import annotations

from .constants import PACKAGE_VERSION as __version__, SCHEMA_VERSION, Limits, DEFAULT_LIMITS

__all__ = ["__version__", "SCHEMA_VERSION", "Limits", "DEFAULT_LIMITS"]
