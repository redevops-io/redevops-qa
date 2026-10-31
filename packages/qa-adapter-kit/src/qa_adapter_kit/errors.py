# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Typed refusals. Each carries the ``ErrorCode`` the runner reports; the message never contains a secret value."""
from __future__ import annotations

from .status import ErrorCode


class AdapterKitError(Exception):
    code: ErrorCode = ErrorCode.INVALID_REQUEST

    def __init__(self, message: str, code: ErrorCode | None = None):
        super().__init__(message)
        if code is not None:
            self.code = code


class ModelError(AdapterKitError, ValueError):
    """A model failed validation (wrong type, out of bounds, unknown field, forbidden value)."""
    code = ErrorCode.INVALID_REQUEST


class PathRefused(AdapterKitError):
    code = ErrorCode.PROHIBITED_PATH


class PolicyRefused(AdapterKitError):
    """The supervisor refused a command, environment or limit before anything was started."""


class AdapterFault(AdapterKitError):
    """Raised by an interactive adapter for an action that failed. ``retryable`` is the adapter's own statement."""
    code = ErrorCode.ADAPTER_CRASH

    def __init__(self, message: str, *, retryable: bool = False, code: ErrorCode | None = None):
        super().__init__(message, code)
        self.retryable = retryable


class AdapterUnavailable(AdapterKitError):
    """The adapter's dependency is not present (no real browser, no emulator, no licensed worker). Never a pass, never a skip."""
    code = ErrorCode.UNAVAILABLE
