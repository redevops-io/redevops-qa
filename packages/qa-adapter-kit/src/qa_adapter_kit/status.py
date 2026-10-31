# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Closed vocabularies of the adapter protocol."""
from __future__ import annotations

from enum import Enum


class Status(str, Enum):
    """Result status. A native status is what the framework reported; none of these is an oracle verdict unless it was
    produced by an independent verifier (see ``mapping.OracleVerdict``)."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIP = "SKIP"
    UNKNOWN = "UNKNOWN"
    UNVERIFIED = "UNVERIFIED"


class AdapterClass(str, Enum):
    INTERACTIVE = "interactive"     # bounded actions and observations, one step at a time
    SUITE = "suite"                 # run an existing test suite, import the native report; never steered mid-test


class ErrorCode(str, Enum):
    """Why a run is ``ERROR``. Closed so that callers can branch on it; messages are free text and always redacted."""

    INVALID_REQUEST = "INVALID_REQUEST"
    PROHIBITED_PATH = "PROHIBITED_PATH"
    ENV_REFUSED = "ENV_REFUSED"
    EXECUTABLE_NOT_ALLOWED = "EXECUTABLE_NOT_ALLOWED"
    DOCKER_REFUSED = "DOCKER_REFUSED"
    DOWNLOAD_REFUSED = "DOWNLOAD_REFUSED"
    PIN_MISMATCH = "PIN_MISMATCH"
    SPAWN_FAILED = "SPAWN_FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    OUTPUT_LIMIT = "OUTPUT_LIMIT"
    MALFORMED_RESULT = "MALFORMED_RESULT"
    MISSING_ARTIFACT = "MISSING_ARTIFACT"
    ARTIFACT_REFUSED = "ARTIFACT_REFUSED"
    LIBRARY_REFUSED = "LIBRARY_REFUSED"    # a suite imports or used a library, resource or construct the adapter does not allow
    STEP_LIMIT = "STEP_LIMIT"
    RETRY_LIMIT = "RETRY_LIMIT"
    ADAPTER_CRASH = "ADAPTER_CRASH"
    NATIVE_ERROR = "NATIVE_ERROR"      # the framework itself reported an error (not a failed check)
    UNAVAILABLE = "UNAVAILABLE"        # the dependency (a real browser, an emulator, a licensed worker) is not there
