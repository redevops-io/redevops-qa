# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Bridge-side loaders: a read-only spec store over contracts specs, and an evidence sink.

``ContractsSpecStore`` is the *writer side* of the immutable-assertion rule (ADR A.2.4 item 6): it loads contracts
``TestSpec`` data, computes ``assertion_set_hash`` with ``rcv1`` and serves the frozen assertion documents by that hash
through the harness ``SpecStore`` protocol (one operation, a read). It also recomputes the same hash with the neutral
``canon-v1`` and refuses to hold a set on which the two disagree; the harness verifier recomputes again before any
assertion is evaluated.

``EvidenceSink`` is the harness ``EvidenceStream`` (``append``) over a contracts-side appender. The appender is a
structural interface (``append_record``) that the ``qa-evidence`` package will implement; nothing here writes files.
"""
from __future__ import annotations

import copy
import json
from typing import Any, Dict, Iterable, Mapping, Protocol, Sequence, Tuple, runtime_checkable

from . import deps, hashing
from .convert import (assert_data_only, contracts_data_to_neutral, from_contracts, neutral_data_to_contracts)
from .errors import EvidenceRefused, HashDisagreement, SpecStoreRefused


class ContractsSpecStore:
    """Immutable, content-addressed store of frozen assertion sets loaded from contracts specs."""

    __slots__ = ("_docs", "_specs")

    def __init__(self, specs: Iterable[Any] = (), *, cross_check: bool = True) -> None:
        object.__setattr__(self, "_docs", {})       # digest (64 hex) -> JSON text of the assertion documents
        object.__setattr__(self, "_specs", {})      # (spec id, version) -> (pin rcv1, spec JSON text)
        for spec in specs:
            self._load(spec, cross_check)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("ContractsSpecStore is read-only")

    # -- loading (construction only) --------------------------------------------------------------------------
    def _load(self, spec: Any, cross_check: bool) -> None:
        c = deps.contracts_qa()
        n = deps.neutral_qa()
        data = spec.to_json() if isinstance(spec, c.TestSpec) else spec
        assert_data_only(data, "spec")
        try:
            parsed = c.TestSpec.from_json(copy.deepcopy(data))      # strict: refuses a stored content_hash mismatch
        except c.QAContractError as exc:
            raise SpecStoreRefused(f"contracts refused the spec: {exc}", cause_code=exc.code) from exc
        key = (parsed.id, parsed.version)
        if key in self._specs:
            raise SpecStoreRefused(f"spec {parsed.id} version {parsed.version} is already loaded", spec_id=parsed.id)
        pin = parsed.assertion_set_hash                          # rcv1:<hex>
        docs = [a.to_json() for a in parsed.assertions]
        if cross_check:
            neutral_spec = from_contracts(parsed)                # raises HashDisagreement on any spec-hash difference
            recomputed = n.records.assertion_set_hash(neutral_spec.assertions)
            if hashing.digest_of(recomputed) != hashing.digest_of(pin):
                raise HashDisagreement("the contracts rcv1 assertion_set_hash and the neutral canon-v1 recomputation "
                                       "differ", loader_hash=pin, neutral_hash=recomputed)
        self._docs.setdefault(hashing.digest_of(pin), json.dumps(docs, sort_keys=True))
        self._specs[key] = (pin, json.dumps(parsed.to_json(), sort_keys=True))

    # -- the harness SpecStore protocol -------------------------------------------------------------------------
    def get_assertion_set(self, assertion_set_hash: str) -> Sequence[Mapping[str, Any]]:
        try:
            digest = hashing.digest_of(assertion_set_hash)
        except Exception:
            raise KeyError("not a canon-v1 or rcv1 hash") from None
        return json.loads(self._docs[digest])

    # -- reads for the runner ------------------------------------------------------------------------------------
    def pin(self, spec_id: str, version: int) -> str:
        """``rcv1:<hex>`` assertion-set hash of a loaded spec (what the runner pins before the first adapter call)."""
        try:
            return self._specs[(spec_id, version)][0]
        except KeyError:
            raise KeyError(f"spec {spec_id} version {version} is not loaded") from None

    def pins(self) -> Tuple[str, ...]:
        return tuple(sorted({pin for pin, _ in self._specs.values()}))

    def contracts_spec_data(self, spec_id: str, version: int) -> Dict[str, Any]:
        return json.loads(self._specs[(spec_id, version)][1])

    def neutral_spec_data(self, spec_id: str, version: int) -> Dict[str, Any]:
        """The spec as neutral JSON, ready for the harness ``TestSpec.from_json``."""
        return contracts_data_to_neutral(self.contracts_spec_data(spec_id, version))


@runtime_checkable
class RecordAppender(Protocol):
    """Contracts-side destination of evidence events (implemented by ``qa-evidence``)."""

    def append_record(self, event: Mapping[str, Any]) -> None: ...


class EvidenceSink:
    """The harness ``EvidenceStream`` over a :class:`RecordAppender`.

    Each event is data only. When its payload is a ``qa/v1`` record the payload is re-parsed by the contracts side
    (which re-checks the record's own ``content_hash``) and the event's ``payload_hash`` must carry the same digest;
    otherwise the append is refused (the harness turns a refused append into ``EvidenceUnavailable``). The appender
    receives the event with the contracts spelling of the payload and the original, unmodified chain fields.
    """

    def __init__(self, appender: Any) -> None:
        if not hasattr(appender, "append_record"):
            raise EvidenceRefused("the appender lacks append_record")
        self._appender = appender

    def append(self, event: Mapping[str, Any]) -> None:
        if type(event) is not dict:
            raise EvidenceRefused("an evidence event is a plain dict")
        assert_data_only(event, "event")
        forwarded = copy.deepcopy(event)
        payload = event.get("payload")
        if isinstance(payload, dict) and isinstance(payload.get("schema_id"), str) \
                and payload["schema_id"].startswith("runtime-contracts/qa/"):
            c = deps.contracts_qa()
            contracts_payload = neutral_data_to_contracts(payload)
            cls = {r.SCHEMA_ID: r for r in deps.contracts_module("registry").RECORDS}.get(
                payload["schema_id"])
            if cls is None:
                raise EvidenceRefused(f"unknown record schema {payload['schema_id']!r}")
            try:
                parsed = cls.from_json(contracts_payload)
            except c.QAContractError as exc:
                raise EvidenceRefused(f"contracts refused the event payload: {exc}", cause_code=exc.code) from exc
            declared = event.get("payload_hash")
            if not isinstance(declared, str) or hashing.digest_of(declared) != hashing.digest_of(parsed.content_hash):
                raise EvidenceRefused("the event's payload_hash is not the hash the contracts side computes for the "
                                      "payload")
            forwarded["payload"] = parsed.to_json()
            forwarded["payload_hash_rcv1"] = parsed.content_hash
        self._appender.append_record(forwarded)
