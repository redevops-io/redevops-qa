# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The single place in this package that imports the harness neutral module (``agent_harness.qa``).

Every other module imports harness names from here, so the import boundary is one file. If ``agent_harness.qa`` is not
importable the pinned tree named in ``pins.toml`` is put on ``sys.path`` through the bridge's documented helper
(``redevops_qa_bridge.deps.prepare_paths``) and the import is retried; if that fails too the import error says so. Nothing
is vendored or copied.
"""
from __future__ import annotations

import importlib


def _load():
    try:
        return importlib.import_module("agent_harness.qa")
    except ModuleNotFoundError as first:
        if first.name not in ("agent_harness", "agent_harness.qa"):
            raise
        try:
            from redevops_qa_bridge import deps as bridge_deps
            from redevops_qa_bridge.pins import load_pins
            bridge_deps.prepare_paths(load_pins())
            return importlib.import_module("agent_harness.qa")
        except Exception as second:
            raise ImportError(
                "agent_harness.qa is not importable: install the pinned agent-harness or set QA_PIN_HARNESS_QA_PATH "
                f"(pins.toml names the exact commit); fallback through the bridge failed with {type(second).__name__}"
            ) from first


_load()

from agent_harness.qa import blobs, canon, egress, errors, ports, receipts, records   # noqa: E402,F401
from agent_harness.qa.blobs import digest_of_bytes, evidence_ref                         # noqa: E402,F401
from agent_harness.qa.egress import (ABOUT_BLANK, EgressDecision, EgressGuard, EgressPolicy, NoResolver,   # noqa: E402,F401
                                     Resolver)
from agent_harness.qa.errors import (ActionBlockedByPolicy, ActionTimeout, AdapterCrash, BrowserCrash,        # noqa: E402,F401
                                     EnvironmentUnhealthy, LocatorAmbiguous, LocatorNotFound, NavigationDenied,
                                     QAAdapterError, RedactionFailed, ResetFailed, ResourceLimitExceeded,
                                     SessionLost, TargetNotActionable, UnexpectedDialog, UnsupportedOperation)
from agent_harness.qa.ports import BlobSink, Clock, NeutralQAAdapter, Redactor                         # noqa: E402,F401
from agent_harness.qa.receipts import action_value_digest, bounded_id, json_value_digest, state_hash   # noqa: E402,F401
from agent_harness.qa.records import (ActionKind, ActionOutcome, ActionRequest, AssertionSubject, CaptureKind,   # noqa: E402,F401
                                      CleanupReport, EvidenceRef, LocateCandidate, LocateMode, LocateResult,
                                      LocatorDescriptor, Observation, ObservationSource, ObservedValue, ObserveRequest,
                                      Phase, ResetResult, ResetScope, Resolution, ResolvedTarget, ResultCode, SecretRef,
                                      SessionHandle, SessionProfile, SubjectKind)
