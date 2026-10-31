# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Typed errors of the check library, each with a stable ``code``.

The library raises these; the adapter (``adapter.py``) maps a code to the harness error of the same meaning
(``ActionBlockedByPolicy``, ``UnsupportedOperation``, ``AssertionProgramUnregistered`` ...). Callers branch on ``code``,
never on message text. ``details`` carries plain data only.
"""
from __future__ import annotations

from typing import Any, Dict


class Codes:
    CHECK_ERROR = "CHECK_ERROR"
    PROGRAM_UNREGISTERED = "PROGRAM_UNREGISTERED"
    PROGRAM_HASH_MISMATCH = "PROGRAM_HASH_MISMATCH"
    PROGRAM_REFUSED = "PROGRAM_REFUSED"
    OUTPUT_REFUSED = "OUTPUT_REFUSED"
    EXPECTED_VALUE_REFUSED = "EXPECTED_VALUE_REFUSED"
    PATH_REFUSED = "PATH_REFUSED"
    LOAD_REFUSED = "LOAD_REFUSED"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    RESOURCE_AMBIGUOUS = "RESOURCE_AMBIGUOUS"
    UNSUPPORTED = "UNSUPPORTED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    ENVIRONMENT = "ENVIRONMENT"
    CASE_ROOT_MISMATCH = "CASE_ROOT_MISMATCH"


class CheckError(Exception):
    code: str = Codes.CHECK_ERROR

    def __init__(self, message: str = "", **details: Any) -> None:
        super().__init__(message or self.code)
        self.message = message or self.code
        self.details: Dict[str, Any] = dict(details)

    def __str__(self) -> str:
        return f"{self.code}: {self.message}" if self.message != self.code else self.code


class ProgramUnregistered(CheckError):
    """No check program is registered under ``{id, version}``."""
    code = Codes.PROGRAM_UNREGISTERED


class ProgramHashMismatch(CheckError):
    """The ``program_hash`` an assertion froze is not the hash of the program the registry holds for ``{id, version}``."""
    code = Codes.PROGRAM_HASH_MISMATCH


class ProgramRefused(CheckError):
    """A program was refused at registration (impure construct, malformed declaration, duplicate id)."""
    code = Codes.PROGRAM_REFUSED


class OutputRefused(CheckError):
    """A program returned something that is not an observed value (a float, a non-JSON type, a verdict-shaped key)."""
    code = Codes.OUTPUT_REFUSED


class ExpectedValueRefused(CheckError):
    """An expected value (or a verdict-shaped argument) reached a check. Checks never receive one."""
    code = Codes.EXPECTED_VALUE_REFUSED


class PathRefused(CheckError):
    """A path leaves the case root, is absolute, is a symbolic link or is not a regular file or directory."""
    code = Codes.PATH_REFUSED


class LoadRefused(CheckError):
    code = Codes.LOAD_REFUSED


class ResourceNotFound(CheckError):
    code = Codes.RESOURCE_NOT_FOUND


class ResourceAmbiguous(CheckError):
    code = Codes.RESOURCE_AMBIGUOUS


class Unsupported(CheckError):
    """A property that cannot be expressed here (reported as not expressible, never as a pass)."""
    code = Codes.UNSUPPORTED


class LimitExceeded(CheckError):
    code = Codes.LIMIT_EXCEEDED


class PolicyBlocked(CheckError):
    """An operation outside the allowed set (not a disposable cluster, an unlisted command, a write)."""
    code = Codes.POLICY_BLOCKED


class EnvironmentFault(CheckError):
    code = Codes.ENVIRONMENT


class CaseRootMismatch(CheckError):
    code = Codes.CASE_ROOT_MISMATCH
