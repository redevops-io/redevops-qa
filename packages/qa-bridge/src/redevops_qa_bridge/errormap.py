# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Mapping typed errors across the boundary by their stable ``code`` string.

Only the code crosses: a neutral ``QAError`` becomes the contracts error class with the same code and the other way
round. A code with no counterpart is not guessed: contracts-only structural codes become the neutral ``SpecInvalid``
(and ``ASSERTION_INTEGRITY``, the generic integrity code, becomes the integrity class ``AssertionHashMismatch`` so the
run still halts); a neutral-only code becomes a contracts ``QAContractError`` carrying the neutral code string. An
exception that carries no code is never mapped (``ErrorCodeUnmapped``), and an exception that is not a ``qa/v1`` error at
all is left alone.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator, Optional

from . import deps
from .errors import BlobStoreFault, ErrorCodeUnmapped

#: contracts codes whose contracts class is ``AssertionIntegrityError`` (the run ends INCONCLUSIVE(ASSERTION_INTEGRITY))
INTEGRITY_CODES = frozenset({"ASSERTION_INTEGRITY", "ASSERTION_HASH_MISMATCH", "EXECUTOR_MISMATCH", "EXPECTED_MISMATCH",
                             "RECOVERY_PAYLOAD_REJECTED", "COVERAGE_VIOLATION"})
#: contracts-only codes and the neutral class they degrade to (fail closed)
CONTRACTS_ONLY_FALLBACK = {"ASSERTION_INTEGRITY": "ASSERTION_HASH_MISMATCH"}
NEUTRAL_STRUCTURAL = "SPEC_INVALID"


def _is_contracts_error(exc: BaseException) -> bool:
    c = deps.contracts_qa()
    errs = deps.contracts_module("errors")
    base = deps.contracts_module("base")
    return isinstance(exc, (errs.QAAdapterError, errs.BlobStoreError, base.QAContractError))


def _is_neutral_error(exc: BaseException) -> bool:
    return isinstance(exc, deps.neutral_qa().errors.QAError)


def _code_of(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    code = getattr(code, "value", code)
    if not isinstance(code, str) or not code:
        raise ErrorCodeUnmapped(f"{type(exc).__name__} carries no stable code", exception=type(exc).__name__)
    return code


def neutral_error_for_contracts(exc: BaseException) -> BaseException:
    """The neutral error with the same ``code`` as a contracts error."""
    c = deps.contracts_qa()
    n = deps.neutral_qa()
    errs = deps.contracts_module("errors")
    code = _code_of(exc)
    message = str(getattr(exc, "detail", None) or exc)
    if isinstance(exc, errs.BlobStoreError):
        return BlobStoreFault(message, blob_code=code)
    adapter_cls = n.errors.ADAPTER_ERRORS.get(code)
    if adapter_cls is not None:
        return adapter_cls(message)
    neutral_cls = n.errors.ERRORS_BY_CODE.get(code)
    if neutral_cls is not None:
        return neutral_cls(message)
    fallback = CONTRACTS_ONLY_FALLBACK.get(code, NEUTRAL_STRUCTURAL)
    return n.errors.ERRORS_BY_CODE[fallback](message, contracts_code=code)


def contracts_error_for_neutral(exc: BaseException) -> BaseException:
    """The contracts error with the same ``code`` as a neutral error."""
    c = deps.contracts_qa()
    code = _code_of(exc)
    message = getattr(exc, "message", None) or str(exc)
    try:
        result_code = c.ResultCode(code)
    except ValueError:
        result_code = None
    if result_code is not None and result_code in c.ADAPTER_ERRORS:
        return c.ADAPTER_ERRORS[result_code](message)
    if code == "UNKNOWN_ENUM_VALUE":
        return c.UnknownEnumValue(message)
    if code in INTEGRITY_CODES:
        return c.AssertionIntegrityError(code, message)
    return c.QAContractError(code, message)


@contextmanager
def contracts_to_neutral() -> Iterator[None]:
    """Run a call into a contracts-typed component on behalf of a neutral caller: its errors become neutral errors."""
    try:
        yield
    except BaseException as exc:                     # noqa: BLE001 - re-raised below unless it is a contracts error
        if isinstance(exc, (KeyboardInterrupt, SystemExit)) or not _is_contracts_error(exc):
            raise
        raise neutral_error_for_contracts(exc) from exc


@contextmanager
def neutral_to_contracts() -> Iterator[None]:
    """Run a call into a neutral component on behalf of a contracts-typed caller: its errors become contracts errors."""
    try:
        yield
    except BaseException as exc:                     # noqa: BLE001
        if isinstance(exc, (KeyboardInterrupt, SystemExit)) or not _is_neutral_error(exc):
            raise
        raise contracts_error_for_neutral(exc) from exc
