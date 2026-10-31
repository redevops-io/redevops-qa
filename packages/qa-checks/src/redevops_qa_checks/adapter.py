# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``CheckAdapter`` (``qa-check-adapter/1``) over the check engine, in the harness neutral form.

Structurally this satisfies ``agent_harness.qa.ports.NeutralCheckAdapter``; the bridge wraps it for the contracts form.
Rules kept here:

* ``run_check`` takes a subject (program reference, input references, tier) and returns an ``ObservedValue``: no expected
  value in, no verdict out. A subject that carries an expected-value or verdict-shaped key is refused.
* The program reference is verified against the registry (``{id, version, program_hash}``) before any input is read.
* The case workspace is read-only. The adapter writes nothing except evidence appended through the injected
  ``Redactor`` and ``BlobSink`` (``capture``), and a failed redaction is ``RedactionFailed``, never a raw artifact.
* ``tier = K`` needs a configured disposable-cluster gate (``tier_k``); without one it is ``ActionBlockedByPolicy``. The
  gate is the only route to a cluster and is refused unless the workspace profile carries a verifiable
  ``disposable_proof_ref``.

The neutral module is imported when an adapter is constructed (through ``pins.toml`` in tests), never at package import.
"""
from __future__ import annotations

import hashlib
import importlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple

from . import errors as ce
from .canonical import canonical_bytes, sha256_ref
from .engine import CheckEngine, Outcome
from .image_store import ImageStore
from .registry import ProgramRegistry, builtin_registry

ADAPTER_ID = "redevops-qa-checks"
ADAPTER_VERSION = "0.1.0"
API_VERSION = "qa-check-adapter/1"


def neutral() -> Any:
    """``agent_harness.qa`` (raises ``EnvironmentFault`` if it cannot be imported; never a skip)."""
    try:
        return importlib.import_module("agent_harness.qa")
    except Exception as exc:
        raise ce.EnvironmentFault(f"agent_harness.qa cannot be imported: {type(exc).__name__}: {exc}") from exc


class TierKGate(Protocol):
    """What the adapter needs from a disposable-cluster gate (see ``tierk``)."""

    def verify_proof(self, disposable_proof_ref: str) -> None: ...        # raises PolicyBlocked unless it names this tool's cluster

    def run_check(self, engine: CheckEngine, subject: Mapping) -> Outcome: ...

    def reset(self, scope: str) -> None: ...

    def close(self) -> Sequence[str]: ...                                 # ids of anything left behind (empty when clean)


def _strip_none(v: Any) -> Any:
    if isinstance(v, Mapping):
        return {k: _strip_none(x) for k, x in v.items() if x is not None}
    if isinstance(v, (list, tuple)):
        return [_strip_none(x) for x in v]
    return v


class CheckAdapter:
    adapter_id = ADAPTER_ID
    adapter_version = ADAPTER_VERSION
    api_version = API_VERSION

    def __init__(self, case_root: Path, *, registry: Optional[ProgramRegistry] = None, redactor: Any = None,
                 blobs: Any = None, image_store: Any = None, tier_k: Optional[TierKGate] = None) -> None:
        self._n = neutral()
        self._engine = CheckEngine(Path(case_root), registry if registry is not None else builtin_registry(),
                                   image_store=image_store if image_store is not None else ImageStore(Path(case_root)))
        self._redactor = redactor
        self._blobs = blobs
        self._tier_k = tier_k
        self._ws: Dict[str, Dict[str, Any]] = {}
        self._counter = 0

    # -- error mapping ----------------------------------------------------------------------------------------------------
    def _err(self, exc: ce.CheckError) -> Exception:
        E = self._n.errors
        table = {
            ce.Codes.PATH_REFUSED: E.ActionBlockedByPolicy,
            ce.Codes.POLICY_BLOCKED: E.ActionBlockedByPolicy,
            ce.Codes.PROGRAM_UNREGISTERED: E.AssertionProgramUnregistered,
            ce.Codes.PROGRAM_HASH_MISMATCH: E.AssertionProgramMismatch,
            ce.Codes.EXPECTED_VALUE_REFUSED: E.SpecInvalid,
            ce.Codes.UNSUPPORTED: E.UnsupportedOperation,
            ce.Codes.LIMIT_EXCEEDED: E.ResourceLimitExceeded,
            ce.Codes.CASE_ROOT_MISMATCH: E.EnvironmentUnhealthy,
            ce.Codes.ENVIRONMENT: E.EnvironmentUnhealthy,
            ce.Codes.RESOURCE_NOT_FOUND: E.EnvironmentUnhealthy,
            ce.Codes.RESOURCE_AMBIGUOUS: E.EnvironmentUnhealthy,
            ce.Codes.LOAD_REFUSED: E.EnvironmentUnhealthy,
            ce.Codes.OUTPUT_REFUSED: E.AdapterCrash,
            ce.Codes.PROGRAM_REFUSED: E.AdapterCrash,
        }
        cls = table.get(exc.code, E.AdapterCrash)
        return cls(exc.message, check_error_code=exc.code, **{k: v for k, v in exc.details.items() if isinstance(v, (str, int, bool))})

    # -- protocol ---------------------------------------------------------------------------------------------------------
    def open_workspace(self, profile: Any):
        R = self._n.records
        try:
            tier = str(profile.tier.value if hasattr(profile.tier, "value") else profile.tier)
            if tier == "K":
                if self._tier_k is None:
                    raise ce.PolicyBlocked("tier K needs a configured disposable-cluster gate; none is configured")
                if profile.disposable_proof_ref is None:
                    raise ce.PolicyBlocked("tier K needs a disposable_proof_ref")
                self._tier_k.verify_proof(profile.disposable_proof_ref)
            actual = self._engine.case_root_digest()
            if actual != profile.case_root_digest:
                raise ce.CaseRootMismatch("the case root does not match the profile's case_root_digest",
                                          expected=profile.case_root_digest, actual=actual)
        except ce.CheckError as exc:
            raise self._err(exc) from None
        self._counter += 1
        wid = "ws-" + hashlib.sha256(f"{profile.case_root_digest}/{tier}/{self._counter}".encode()).hexdigest()[:16]
        self._ws[wid] = {"tier": tier, "runs": []}
        return R.WorkspaceHandle(workspace_id=wid)

    def _state(self, w: Any) -> Dict[str, Any]:
        st = self._ws.get(w.workspace_id)
        if st is None:
            raise self._n.errors.EnvironmentUnhealthy("unknown or closed workspace")
        return st

    def resolve(self, w: Any, ref: Any):
        R = self._n.records
        self._state(w)
        try:
            out = self._engine.resolve(_strip_none(ref.to_json()))
        except ce.CheckError as exc:
            raise self._err(exc) from None
        return R.ResolvedResource(content_digest=out["content_digest"], ref=ref)

    def run_check(self, w: Any, subject: Any):
        R, canon = self._n.records, self._n.canon
        st = self._state(w)
        try:
            data = _strip_none(subject.to_json())
            if data.get("tier") == "K":
                if st["tier"] != "K" or self._tier_k is None:
                    raise ce.PolicyBlocked("a tier K subject needs a tier K workspace behind the disposable-cluster gate")
                outcome = self._tier_k.run_check(self._engine, data)
            else:
                outcome = self._engine.run_check(data)
        except ce.CheckError as exc:
            raise self._err(exc) from None
        st["runs"].append({"check_program_ref": data["check_program_ref"], "tier": data["tier"],
                           "resolution": outcome.resolution, "match_count": outcome.match_count,
                           "inputs": [list(i) for i in outcome.inputs], "value_sha256": outcome.value_sha256,
                           "value": outcome.value})
        if outcome.resolution != "RESOLVED":
            return R.ObservedValue(resolution=R.Resolution(outcome.resolution), match_count=outcome.match_count)
        return R.ObservedValue(resolution=R.Resolution.RESOLVED, match_count=1, value=outcome.value,
                               value_digest=canon.to_contract_ref(canon.canon_hash(outcome.value)))

    def capture(self, w: Any, kinds: Sequence[Any]):
        R = self._n.records
        st = self._state(w)
        E = self._n.errors
        wanted = [str(getattr(k, "value", k)) for k in kinds]
        if any(k != "TRACE" for k in wanted):
            raise E.UnsupportedOperation("only a TRACE capture exists for resource checks",
                                         unsupported=",".join(sorted(k for k in wanted if k != "TRACE")))
        if self._redactor is None or self._blobs is None:
            raise E.RedactionFailed("no redactor and blob sink are configured; a raw artifact is never produced")
        if not wanted:
            return ()
        body = canonical_bytes({"adapter": ADAPTER_ID, "adapter_version": ADAPTER_VERSION, "api_version": API_VERSION,
                                "tier": st["tier"], "runs": st["runs"]})
        try:
            redacted = self._redactor.redact(body, "application/json")
            digest = self._blobs.put(redacted, "application/json")
        except E.QAError:
            raise
        except Exception as exc:
            raise E.RedactionFailed(f"redaction or storage failed: {type(exc).__name__}") from None
        return (R.EvidenceRef(ref=digest, content_hash=digest, media_type="application/json", modality="check-trace",
                              ref_type="evidence", source=ADAPTER_ID, version=ADAPTER_VERSION),)

    def reset(self, w: Any, scope: Any):
        R, E = self._n.records, self._n.errors
        st = self._state(w)
        if st["tier"] != "K" or self._tier_k is None:
            raise E.UnsupportedOperation("an offline workspace is read-only and has nothing to reset")
        try:
            self._tier_k.reset(str(getattr(scope, "value", scope)))
        except ce.CheckError as exc:
            raise E.ResetFailed(exc.message, check_error_code=exc.code) from None
        return R.ResetResult(ok=True, scope=scope)

    def close_workspace(self, w: Any):
        R = self._n.records
        st = self._state(w)
        leaked: Tuple[str, ...] = ()
        if st["tier"] == "K" and self._tier_k is not None:
            leaked = tuple(sorted(self._tier_k.close()))
        del self._ws[w.workspace_id]
        return R.CleanupReport(handle_id=w.workspace_id, verified=not leaked, leaked=leaked,
                               released=() if leaked else (w.workspace_id,))
