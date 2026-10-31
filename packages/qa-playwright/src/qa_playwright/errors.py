# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Errors specific to this package. Each keeps the stable ``code`` of a harness adapter error (the bridge maps errors by
code, so a code of our own would be unmapped); the class only adds a distinct, testable type and a fixed meaning."""
from __future__ import annotations

from ._harness import EnvironmentUnhealthy


class DriverUnavailable(EnvironmentUnhealthy):
    """The real browser driver cannot be used (Playwright is not installed, or the browser cannot be started). Typed,
    never silent: a caller that needs a browser fails here and does not fall back to anything."""

    recoverable = False
