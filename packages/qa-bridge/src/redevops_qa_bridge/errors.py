# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Typed bridge errors with stable ``code`` strings.

Callers branch on ``code`` (never on message text). A code that already exists on the contracts side or the harness
neutral side keeps that spelling (``UNSUPPORTED_COVERAGE_CONTRACT``, ``UNKNOWN_FIELD``, ...); codes that only the
bridge can raise are listed in :class:`Codes`.
"""
from __future__ import annotations

from typing import Any, Dict


class Codes:
    BRIDGE_ERROR = "BRIDGE_ERROR"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    PINS_INVALID = "PINS_INVALID"
    PIN_MISMATCH = "PIN_MISMATCH"
    DATA_ONLY_VIOLATION = "DATA_ONLY_VIOLATION"
    UNKNOWN_SCHEMA = "UNKNOWN_SCHEMA"
    UNKNOWN_TYPE = "UNKNOWN_TYPE"
    HASH_DISAGREEMENT = "HASH_DISAGREEMENT"
    HASH_FORMAT = "HASH_FORMAT"
    CONVERSION_REFUSED = "CONVERSION_REFUSED"
    ERROR_CODE_UNMAPPED = "ERROR_CODE_UNMAPPED"
    ADAPTER_REFUSED = "ADAPTER_REFUSED"
    SPEC_STORE_REFUSED = "SPEC_STORE_REFUSED"
    EVIDENCE_REFUSED = "EVIDENCE_REFUSED"
    POLICY_REFUSED = "POLICY_REFUSED"
    BLOB_STORE_FAULT = "BLOB_STORE_FAULT"
    UNSUPPORTED_COVERAGE_CONTRACT = "UNSUPPORTED_COVERAGE_CONTRACT"
    PLAN_INVALID = "PLAN_INVALID"


class BridgeError(Exception):
    """Base class. ``code`` is stable; ``details`` carries data (never class instances)."""

    code: str = Codes.BRIDGE_ERROR

    def __init__(self, message: str = "", **details: Any) -> None:
        super().__init__(message or self.code)
        self.message = message or self.code
        self.details: Dict[str, Any] = dict(details)

    def __str__(self) -> str:
        return f"{self.code}: {self.message}" if self.message != self.code else self.code


class DependencyUnavailable(BridgeError):
    """A pinned dependency cannot be imported. Never downgraded to a skip."""

    code = Codes.DEPENDENCY_UNAVAILABLE


class PinsInvalid(BridgeError):
    code = Codes.PINS_INVALID


class PinMismatch(BridgeError):
    """An installed or checked-out dependency is not the pinned one (floating or wrong install)."""

    code = Codes.PIN_MISMATCH


class DataOnlyViolation(BridgeError):
    """A value that is not plain JSON data was handed to a boundary function (a class instance, a float, ...)."""

    code = Codes.DATA_ONLY_VIOLATION


class UnknownSchema(BridgeError):
    code = Codes.UNKNOWN_SCHEMA


class UnknownType(BridgeError):
    code = Codes.UNKNOWN_TYPE


class HashFormatError(BridgeError):
    code = Codes.HASH_FORMAT


class HashDisagreement(BridgeError):
    """The two sides compute different digests for the same payload. The converted object is never returned."""

    code = Codes.HASH_DISAGREEMENT


class ConversionRefused(BridgeError):
    """The destination side refused the data. ``details['cause_code']`` is the destination's own code."""

    code = Codes.CONVERSION_REFUSED


class ErrorCodeUnmapped(BridgeError):
    code = Codes.ERROR_CODE_UNMAPPED


class AdapterRefused(BridgeError):
    """A component handed to a shim does not satisfy the protocol it is meant to (missing member, wrong api_version)."""

    code = Codes.ADAPTER_REFUSED


class SpecStoreRefused(BridgeError):
    code = Codes.SPEC_STORE_REFUSED


class EvidenceRefused(BridgeError):
    code = Codes.EVIDENCE_REFUSED


class PolicyRefused(BridgeError):
    code = Codes.POLICY_REFUSED


class BlobStoreFault(BridgeError):
    """A contracts blob error that has no neutral class; ``code`` is the contracts spelling (``BLOB_NOT_FOUND``...)."""

    code = Codes.BLOB_STORE_FAULT

    def __init__(self, message: str = "", *, blob_code: str = Codes.BLOB_STORE_FAULT, **details: Any) -> None:
        super().__init__(message, **details)
        self.code = blob_code


class PlanRejected(BridgeError):
    """A plan the bridge refuses. ``code`` is the contracts reason code (``UNSUPPORTED_COVERAGE_CONTRACT``,
    ``UNKNOWN_FIELD``, ``PLAN_INVALID``, ...), so a refusal reads the same on both sides."""

    code = Codes.PLAN_INVALID

    def __init__(self, message: str = "", *, reason_code: str = Codes.PLAN_INVALID, **details: Any) -> None:
        super().__init__(message, **details)
        self.code = reason_code


class UnsupportedCoverageContract(PlanRejected):
    def __init__(self, message: str = "", **details: Any) -> None:
        super().__init__(message, reason_code=Codes.UNSUPPORTED_COVERAGE_CONTRACT, **details)
