# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The conformance suite must fail when the bridge or a hash mapping is broken. Each test first runs the item unmutated
(it passes), then breaks one thing in-process and shows the same item now fails with a stable code."""
import dataclasses
import enum

import pytest

from redevops_qa_bridge import convert, deps, hashing, plan as bridge_plan
from redevops_qa_bridge.conformance import checks
from redevops_qa_bridge.conformance.context import get_context, set_pins
from redevops_qa_bridge.conformance.items import enumerate_items
from redevops_qa_bridge.conformance.model import ConformanceFailure


@pytest.fixture(scope="module")
def items(pins):
    set_pins(pins)
    get_context()
    return {i.item_id: i for lst in enumerate_items().values() for i in lst}


def passes(item):
    checks.run_item(item)


def fails(item, *codes):
    with pytest.raises(ConformanceFailure) as info:
        checks.run_item(item)
    if codes:
        assert info.value.code in codes, (info.value.code, info.value.message)
    return info.value


@pytest.mark.parametrize("item_id", ["rec:action_receipt", "rec:run_manifest_pass", "rec:test_spec_ui", "nrec:checkpoint",
                                     "rt:observation", "nrt:review_item"])
def test_a_broken_hash_prefix_mapping_is_caught(items, monkeypatch, item_id):
    item = items[item_id]
    passes(item)
    monkeypatch.setattr(hashing, "to_neutral_hash", lambda h: "canon-v1:" + "0" * 64)
    monkeypatch.setattr(hashing, "to_contracts_hash", lambda h: "rcv1:" + "0" * 64)
    fails(item, "HASH_DIVERGENCE", "CONVERSION_REFUSED", "SOURCE_REFUSED")


def test_a_bridge_that_alters_a_field_while_converting_is_caught(items, monkeypatch):
    item = items["rec:action_receipt"]
    passes(item)
    original = convert.contracts_data_to_neutral

    def tampering(data, **kw):
        out = original(data, **kw)
        out["step_id"] = "other-step"
        return out
    monkeypatch.setattr(convert, "contracts_data_to_neutral", tampering)
    fails(item, "HASH_DIVERGENCE", "CONVERSION_REFUSED")


def test_a_bridge_that_drops_custody_conversion_is_caught_by_the_round_trip(items, monkeypatch):
    item = items["rt:observation"]
    passes(item)
    original = convert.neutral_data_to_contracts

    def losing(data, **kw):
        out = original(data, **kw)
        out.pop("custody", None)
        return out
    monkeypatch.setattr(convert, "neutral_data_to_contracts", losing)
    fails(item, "HASH_DIVERGENCE", "CONVERSION_REFUSED", "ROUND_TRIP_DIFFERS")


def test_a_broken_neutral_canonicalizer_is_caught_by_the_vector_checks(items, monkeypatch, neutral):
    cid = next(i for i in items if i.startswith("canon:qa_canon_vectors.json#key_order"))
    nid = next(i for i in items if i.startswith("nvec:qa_canon_vectors.json#key_order"))
    passes(items[cid])
    passes(items[nid])
    real = neutral.canon.canonical_text
    monkeypatch.setattr(neutral.canon, "canonical_text", lambda v: real(v).replace("{", "{ "))
    fails(items[cid], "CANON_DIVERGENCE")
    fails(items[nid], "CANON_DIVERGENCE")


def test_a_neutral_hash_that_ignores_nfc_is_caught(items, monkeypatch, neutral):
    cid = next(i for i in items if i.startswith("canon:qa_canon_vectors.json#nfc_normalization"))
    passes(items[cid])
    monkeypatch.setattr(neutral.canon, "_nfc", lambda text, what: text)
    fails(items[cid], "CANON_DIVERGENCE")


def test_a_hash_that_differs_from_the_golden_value_is_caught(items, monkeypatch):
    item = items["val:budget"]
    passes(item)
    monkeypatch.setattr(convert, "neutral_digest", lambda obj: "canon-v1:" + "1" * 64)
    fails(item, "HASH_DIVERGENCE", "GOLDEN_MISMATCH")


def _replace_registry(monkeypatch, **changes):
    real = convert.registry()
    monkeypatch.setattr(convert, "registry", lambda: dataclasses.replace(real, **changes))


def test_a_pairing_of_the_wrong_neutral_class_is_caught_by_field_parity(items, monkeypatch):
    item = items["fields:Checkpoint"]
    passes(item)
    reg = convert.registry()
    pairs = dict(reg.records)
    sid = "runtime-contracts/qa/checkpoint"
    pairs[sid] = (pairs[sid][0], pairs["runtime-contracts/qa/review-item"][1])
    _replace_registry(monkeypatch, records=pairs)
    fails(item, "FIELD_PARITY")


def test_an_enum_that_lost_a_member_is_caught_by_enum_parity(items, monkeypatch):
    item = items["enum:Executor"]
    passes(item)
    reg = convert.registry()
    smaller = enum.StrEnum("Executor", {"PLAYWRIGHT": "PLAYWRIGHT"})
    enums = dict(reg.enums)
    enums["Executor"] = (enums["Executor"][0], smaller)
    _replace_registry(monkeypatch, enums=enums)
    err = fails(item, "ENUM_PARITY")
    assert err.details["contracts_only"] == [("SCRIPT", "SCRIPT")]


def test_an_enum_value_renamed_is_caught(items, monkeypatch):
    item = items["enum:Outcome"]
    passes(item)
    reg = convert.registry()
    renamed = enum.StrEnum("Outcome", {"PASS": "pass", "PRODUCT_FAIL": "PRODUCT_FAIL", "TEST_DEFECT": "TEST_DEFECT",
                                       "ENVIRONMENT_FAIL": "ENVIRONMENT_FAIL", "INCONCLUSIVE": "INCONCLUSIVE"})
    enums = dict(reg.enums)
    enums["Outcome"] = (enums["Outcome"][0], renamed)
    _replace_registry(monkeypatch, enums=enums)
    fails(item, "ENUM_PARITY")


def test_a_protocol_that_renamed_a_parameter_is_caught(items, monkeypatch, neutral):
    item = items["protocol:QAAdapter"]
    passes(item)
    ports = deps.neutral_module("ports")

    from typing import Protocol, runtime_checkable

    @runtime_checkable
    class Broken(Protocol):
        adapter_id: str
        adapter_version: str
        api_version: str

        def open_session(self, profile): ...
        def observe(self, session, req): ...                # renamed: s -> session
        def locate(self, s, target, *, mode): ...
        def act(self, s, action, target): ...
        def assert_(self, s, subject): ...
        def capture(self, s, kinds): ...
        def reset(self, s, scope): ...
        def close_session(self, s): ...
    monkeypatch.setattr(ports, "NeutralQAAdapter", Broken)
    err = fails(item, "PROTOCOL_PARITY")
    assert "observe" in err.details["parameters"]


def test_a_reference_adapter_that_no_longer_satisfies_a_protocol_is_caught(items, monkeypatch):
    item = items["reference-adapter:QAAdapter"]
    passes(item)
    monkeypatch.delattr(checks._RefQAAdapter, "close_session")
    fails(item, "PROTOCOL_PARITY")


def test_a_plan_validator_that_lets_subset_through_is_caught_by_refusal_parity(items, monkeypatch):
    item = items["refusal:qa.json#plan_coverage_subset"]
    passes(item)
    monkeypatch.setattr(bridge_plan, "validate_plan", lambda plan: plan)
    fails(item, "REFUSAL_PARITY", "INTEGRITY_CODE_VOCABULARY")


def test_a_neutral_side_that_accepts_an_edited_assertion_set_is_caught(items, monkeypatch, neutral):
    item = items["refusal:qa.json#expected_edited_after_pinning"]
    passes(item)
    verifier = deps.neutral_module("verifier")
    monkeypatch.setattr(verifier, "_require_pinned_digest", lambda assertions, pin: None)
    fails(item, "REFUSAL_PARITY")


def test_an_error_class_whose_attributes_drifted_is_caught(items, monkeypatch, neutral):
    item = items["error-class:LOCATOR_NOT_FOUND"]
    passes(item)
    monkeypatch.setattr(neutral.errors.LocatorNotFound, "recoverable", False)
    err = fails(item, "ERROR_ATTRIBUTE_PARITY")
    assert err.details["differing"] == ["recoverable"]


def test_a_missing_vector_in_the_harness_set_is_caught(items, monkeypatch):
    ids = [i for i in items if i.startswith("vecset:qa_canon_vectors.json")]
    assert ids
    item = items[ids[0]]
    passes(item)
    data = dict(item.data)
    data["vectors"] = list(data["vectors"]) + [{"id": "invented-vector", "rcv1": "rcv1:" + "0" * 64, "canonical_json": "{}"}]
    err = fails(dataclasses.replace(item, data=data), "VECTOR_SET_DRIFT")
    assert err.details["missing_ids"] == ["invented-vector"]


def test_a_vector_file_that_cannot_be_used_is_a_failure(items):
    item = checks.Item("CHK1", "file:contracts:golden/x.json", "bad_file", {"side": "contracts", "rel": "golden/x.json", "error": "boom"})
    fails(item, "VECTOR_FILE_UNUSABLE")


def test_an_unknown_item_kind_is_a_failure_not_a_pass():
    fails(checks.Item("CHK1", "x", "no-such-kind"), "UNKNOWN_ITEM_KIND")


def test_an_unknown_refusal_operation_in_a_fixture_is_a_failure(items):
    item = checks.Item("CHK6", "refusal:x#y", "refusal", {"fixture": {"id": "y", "operation": "do_something_new", "input": {},
                                                                     "expect": {"refused": False}}, "source": "x", "golden": None})
    fails(item, "REFUSAL_PARITY")


def test_an_unavailable_item_fails_with_the_reason():
    item = checks.Item("CHK1", "unavailable", "unavailable", {"code": "DEPENDENCY_UNAVAILABLE", "message": "gone", "details": {}})
    assert fails(item, "DEPENDENCY_UNAVAILABLE").message == "gone"
