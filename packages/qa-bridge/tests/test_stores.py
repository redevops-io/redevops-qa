# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import copy
import json

import pytest

from redevops_qa_bridge import convert, deps, hashing
from redevops_qa_bridge.errors import EvidenceRefused, HashDisagreement, SpecStoreRefused
from redevops_qa_bridge.stores import ContractsSpecStore, EvidenceSink


@pytest.fixture()
def spec_ui(contracts, gi):
    return contracts.TestSpec.from_json(gi("test_spec_ui"))


def test_the_store_pins_the_contracts_rcv1_hash(spec_ui):
    store = ContractsSpecStore([spec_ui])
    assert store.pin(spec_ui.id, spec_ui.version) == spec_ui.assertion_set_hash
    assert store.pins() == (spec_ui.assertion_set_hash,)
    assert store.pin(spec_ui.id, spec_ui.version).startswith("rcv1:")


def test_assertion_documents_are_served_by_either_hash_spelling(spec_ui):
    store = ContractsSpecStore([spec_ui])
    pin = spec_ui.assertion_set_hash
    docs = store.get_assertion_set(pin)
    assert [d["assertion_id"] for d in docs] == sorted(spec_ui.assertion_ids)
    assert store.get_assertion_set(hashing.to_neutral_hash(pin)) == docs


def test_unknown_or_malformed_hash_is_a_key_error(spec_ui):
    store = ContractsSpecStore([spec_ui])
    with pytest.raises(KeyError):
        store.get_assertion_set("rcv1:" + "0" * 64)
    with pytest.raises(KeyError):
        store.get_assertion_set("not-a-hash")


def test_the_store_is_read_only_and_serves_copies(spec_ui):
    store = ContractsSpecStore([spec_ui])
    with pytest.raises(AttributeError):
        store.anything = 1
    assert not any(hasattr(store, name) for name in ("put", "delete", "add", "set"))
    docs = store.get_assertion_set(spec_ui.assertion_set_hash)
    docs[0]["predicate"]["expected"] = "changed"
    again = store.get_assertion_set(spec_ui.assertion_set_hash)
    assert again[0]["predicate"]["expected"] != "changed"


def test_a_duplicate_spec_version_is_refused(spec_ui):
    with pytest.raises(SpecStoreRefused):
        ContractsSpecStore([spec_ui, spec_ui])


def test_a_spec_whose_stored_hash_is_wrong_is_refused(gi):
    data = gi("test_spec_ui")
    data["content_hash"] = "rcv1:" + "0" * 64
    with pytest.raises(SpecStoreRefused) as info:
        ContractsSpecStore([data])
    assert info.value.details["cause_code"] == "HASH_MISMATCH"


def test_a_non_data_spec_is_refused(gi):
    with pytest.raises(Exception) as info:
        ContractsSpecStore([{**gi("test_spec_ui"), "x": object()}])
    assert info.value.code == "DATA_ONLY_VIOLATION"


def test_the_neutral_recomputation_must_agree_with_the_loader(spec_ui, monkeypatch, neutral):
    monkeypatch.setattr(neutral.records, "assertion_set_hash", lambda assertions: "canon-v1:" + "0" * 64)
    with pytest.raises(HashDisagreement):
        ContractsSpecStore([spec_ui])


def test_neutral_spec_data_is_ready_for_the_harness(spec_ui, neutral):
    store = ContractsSpecStore([spec_ui])
    data = store.neutral_spec_data(spec_ui.id, spec_ui.version)
    spec = neutral.records.TestSpec.from_json(data)
    assert spec.canon_hash().removeprefix("canon-v1:") == spec_ui.spec_hash.removeprefix("rcv1:")


def test_the_harness_verifier_loads_frozen_assertions_from_the_bridge_store(spec_ui, neutral):
    store = ContractsSpecStore([spec_ui])
    pin = store.pin(spec_ui.id, spec_ui.version)
    v = deps.neutral_module("verifier")
    frozen = v.load_frozen_assertions(store, pin, lineage=v.ApprovedLineage([pin]),
                                      programs=deps.neutral_module("specstore").InMemoryProgramRegistry())
    assert frozen.assertion_set_hash == pin
    assert frozen.assertion_ids == tuple(sorted(spec_ui.assertion_ids))


def test_script_assertions_load_with_a_matching_program_registry(contracts, gi, neutral):
    data = gi("test_spec_resource")
    data["assertions"] = [gi("assertion_spec_script")]
    spec = contracts.TestSpec.from_json(data)
    store = ContractsSpecStore([spec])
    pin = store.pin(spec.id, spec.version)
    programs = {}
    for a in spec.assertions:
        if a.check_program_ref is not None:
            programs[(a.check_program_ref.id, a.check_program_ref.version)] = a.check_program_ref.program_hash
    assert programs
    v = deps.neutral_module("verifier")
    frozen = v.load_frozen_assertions(store, pin, lineage=v.ApprovedLineage([pin]),
                                      programs=deps.neutral_module("specstore").InMemoryProgramRegistry(programs))
    assert set(frozen.assertion_ids) == set(spec.assertion_ids)


# -- evidence sink -------------------------------------------------------------------------------------------------------

class _Appender:
    def __init__(self):
        self.events = []

    def append_record(self, event):
        self.events.append(event)


def _event(neutral, kind="ReviewItem"):
    rec = neutral.records.ReviewItem(review_item_id="review-1", run_id="run-1", reason="INCONCLUSIVE")
    body = {"kind": kind, "payload_hash": rec.canon_hash(), "prev": None, "seq": 0}
    return {**body, "event_hash": neutral.canon.canon_hash(body), "payload": rec.to_json(with_hash=True)}


def test_the_sink_forwards_a_verified_record_event(neutral):
    appender = _Appender()
    sink = EvidenceSink(appender)
    event = _event(neutral)
    assert isinstance(sink, deps.neutral_module("hooks").EvidenceStream)
    sink.append(event)
    (forwarded,) = appender.events
    assert forwarded["payload"]["content_hash"].startswith("rcv1:")
    assert forwarded["payload_hash_rcv1"] == "rcv1:" + event["payload_hash"].removeprefix("canon-v1:")
    assert forwarded["event_hash"] == event["event_hash"] and forwarded["payload_hash"] == event["payload_hash"]


def test_the_sink_refuses_a_payload_hash_the_contracts_side_does_not_compute(neutral):
    sink = EvidenceSink(_Appender())
    event = _event(neutral)
    event["payload_hash"] = "canon-v1:" + "0" * 64
    with pytest.raises(EvidenceRefused):
        sink.append(event)


def test_the_sink_refuses_a_tampered_payload(neutral):
    sink = EvidenceSink(_Appender())
    event = _event(neutral)
    event["payload"]["reason"] = "TAMPERED"
    with pytest.raises(EvidenceRefused):
        sink.append(event)


def test_the_sink_passes_non_record_events_as_data(neutral):
    appender = _Appender()
    sink = EvidenceSink(appender)
    sink.append({"kind": "RunStarted", "payload_hash": "canon-v1:" + "1" * 64, "prev": None, "seq": 0,
                 "event_hash": "canon-v1:" + "2" * 64, "payload": {"run_id": "run-1"}})
    assert len(appender.events) == 1 and "payload_hash_rcv1" not in appender.events[0]


def test_the_sink_refuses_non_data_events_and_bad_appenders(neutral):
    with pytest.raises(EvidenceRefused):
        EvidenceSink(object())
    sink = EvidenceSink(_Appender())
    with pytest.raises(EvidenceRefused):
        sink.append(neutral.records.ReviewItem(review_item_id="r", run_id="x", reason="A"))
    with pytest.raises(Exception) as info:
        sink.append({"kind": "x", "payload": object()})
    assert info.value.code == "DATA_ONLY_VIOLATION"
