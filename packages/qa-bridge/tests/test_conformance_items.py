# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""What the suite enumerates, and the divergence report built from its failures."""
import json

import pytest

from redevops_qa_bridge import deps
from redevops_qa_bridge.conformance import report
from redevops_qa_bridge.conformance.context import get_context, set_pins
from redevops_qa_bridge.conformance.items import CHECKS, enumerate_items


@pytest.fixture(scope="module")
def items(pins):
    set_pins(pins)
    get_context()
    return enumerate_items()


def test_seven_checks_each_with_items(items):
    assert list(items) == list(CHECKS) and len(CHECKS) == 7
    assert all(len(v) > 0 for v in items.values())
    assert not any(i.kind == "unavailable" for v in items.values() for i in v)


def test_item_ids_are_unique_within_a_check(items):
    for check, lst in items.items():
        ids = [i.item_id for i in lst]
        assert len(ids) == len(set(ids)), check


def test_every_vector_of_every_pinned_canonical_file_is_an_item(items, pins):
    n = 0
    for rel in pins.contracts.vector_files:
        if "canon_vectors" in rel:
            data = json.loads(pins.contracts.vector_path(rel).read_text())
            n += len(data["vectors"])
            ids = {i.item_id for i in items["CHK1"]}
            for v in data["vectors"]:
                assert f"canon:{rel.rsplit('/', 1)[-1]}#{v['id']}" in ids
    assert n >= 97


def test_the_97_frozen_vectors_are_all_checked(items):
    base = [i for i in items["CHK1"] if i.item_id.startswith("canon:qa_canon_vectors.json#")]
    assert len(base) == 97
    assert len([i for i in items["CHK1"] if i.item_id.startswith("canon-refusal:qa_canon_vectors.json#")]) == 3
    assert len([i for i in items["CHK2"] if i.item_id.startswith("nvec:qa_canon_vectors.json#")]) == 97


def test_addendum_items_exist_exactly_when_the_addendum_is_pinned(items, pins):
    pinned = any("addendum" in rel for rel in pins.contracts.vector_files)
    has_items = any("addendum" in i.item_id for v in items.values() for i in v)
    assert pinned == has_items
    kinds = {i.kind for v in items.values() for i in v}
    for kind in ("valdigest", "setorder", "pred", "reason_code", "classification"):
        assert (kind in kinds) == pinned, kind


def test_every_golden_refusal_is_an_item(items, golden):
    ids = {i.item_id for i in items["CHK6"]}
    for r in golden["refusals"]:
        assert f"refusal:qa.json#{r['id']}" in ids


def test_every_adapter_error_is_an_item(items, contracts):
    ids = {i.item_id for i in items["CHK6"]}
    for rc in contracts.ADAPTER_ERRORS:
        assert f"error-class:{rc.value}" in ids


def test_every_mirrored_record_and_value_has_a_field_parity_item(items):
    names = {i.item_id for i in items["CHK3"]}
    assert len([n for n in names if n.startswith("fields:")]) == 16 + 36


def test_the_vector_set_item_is_per_file_and_the_inventory_is_compared(items):
    assert any(i.item_id == "vecset:qa_canon_vectors.json" for i in items["CHK2"])
    assert any(i.item_id.startswith("inventory:") for i in items["CHK2"])


def test_the_collected_count_is_in_the_hundreds(items):
    assert sum(len(v) for v in items.values()) > 600


def test_protocol_parameter_kind_differences_are_exactly_the_known_ones(contracts, neutral):
    """The gate compares parameter names (ADR A.2.5). Kinds differ in one known place: contracts declares media_type
    keyword-only on BlobStore.put and Redactor.redact, the neutral protocols accept it positionally. The bridge's
    blob and redactor shims exist for that difference; any other kind difference is a change to review."""
    ports = deps.neutral_module("ports")
    differences = {}
    for c_proto, n_proto in ((contracts.QAAdapter, ports.NeutralQAAdapter), (contracts.CheckAdapter, ports.NeutralCheckAdapter),
                             (contracts.BlobStore, ports.BlobSink), (contracts.Redactor, ports.Redactor)):
        a, b = _kinds(c_proto), _kinds(n_proto)
        for method in a:
            if a[method] != b[method]:
                differences[f"{c_proto.__name__}.{method}"] = (a[method], b[method])
    assert set(differences) == {"BlobStore.put", "Redactor.redact"}
    for (c_kinds, n_kinds) in differences.values():
        assert c_kinds[-1] == ("media_type", "KEYWORD_ONLY") and n_kinds[-1][0] == "media_type"
        assert n_kinds[-1][1] != "KEYWORD_ONLY"


def _kinds(proto):
    import inspect
    return {n: [(p.name, p.kind.name) for p in inspect.signature(f).parameters.values() if p.name != "self"]
            for n, f in vars(proto).items() if inspect.isfunction(f) and not n.startswith("_")}


# -- the report ---------------------------------------------------------------------------------------------------------------

def failure(code, item, **details):
    return {"code": code, "item": item, "details": details}


@pytest.mark.parametrize("f,group", [
    (failure("VALUE_DIGEST_DEFINITION", "valdigest:x#string_plain"), "K1"),
    (failure("SET_ORDER_DIVERGENCE", "setorder:fixtures_by_id", differing_fields=["fixtures"]), "K2"),
    (failure("SET_ORDER_DIVERGENCE", "setorder:x", differing_fields=["assertion_results", "step_results"]), "K2"),
    (failure("SET_ORDER_DIVERGENCE", "setorder:check", differing_fields=["assertion_results[0].check.evidence_refs"]), "additional"),
    (failure("SET_ORDER_DIVERGENCE", "setorder:x", differing_fields=[]), "additional"),
    (failure("INTEGRITY_CODE_VOCABULARY", "refusal:qa_clarifications.json#pin_not_found"), "K3"),
    (failure("REFUSAL_PARITY", "classification:A_CODE_FROM_A_LATER_VERSION"), "K3"),
    (failure("REASON_CODE_PARITY", "enum-presence:RecoveryReason"), "K4"),
    (failure("FIELD_PARITY", "fields:FaultRecovery", schema="FaultRecovery",
             differences={"hashed": {"contracts_only": ["reason_code"], "neutral_only": []}}), "K4"),
    (failure("FIELD_PARITY", "fields:FaultRecovery", schema="FaultRecovery",
             differences={"hashed": {"contracts_only": ["reason_code", "other"], "neutral_only": []}}), "additional"),
    (failure("FIELD_PARITY", "fields:Step", schema="Step", differences={}), "additional"),
    (failure("VECTOR_SET_DRIFT", "vecset:x"), "P1"),
    (failure("HASH_DIVERGENCE", "variant:check-detail-wording"), "additional"),
])
def test_failures_are_grouped(f, group):
    assert report.classify(f) == group


def test_the_report_names_each_failing_check_with_the_concrete_mismatch():
    summary = {"collected": 2, "collection_errors": [], "tests": [
        {"nodeid": "t.py::test_item[valdigest:x#string_plain]", "check": "CHK1", "outcome": "failed",
         "code": "VALUE_DIGEST_DEFINITION", "message": "m", "details": {"golden": "rcv1:" + "a" * 64, "canon_v1": "canon-v1:" + "b" * 64}},
        {"nodeid": "t.py::test_item[rec:ok]", "check": "CHK1", "outcome": "passed", "code": None, "message": "", "details": {}}]}
    rec = {"result": "FAIL", "receipt_hash": "sha256:" + "c" * 64, "collected_tests": 2, "failed_tests": 1,
           "subjects": {"pin_set": "c4", "contracts": {"commit": "x"}, "harness_qa": {"commit": "y"}},
           "checks": [{"check_id": "CHK1", "name": "n", "status": "FAIL", "failed": 1, "failure_codes": ["VALUE_DIGEST_DEFINITION"]}]}
    rep = report.build_report(summary, rec)
    assert rep["groups"]["K1"]["count"] == 1 and rep["groups"]["K2"]["count"] == 0
    only = rep["groups"]["K1"]["failures"][0]
    assert only["check"] == "CHK1" and only["item"] == "valdigest:x#string_plain" and only["details"]["golden"].startswith("rcv1:")
    md = report.render_markdown(rep)
    assert "valdigest:x#string_plain" in md and "canon-v1:" + "b" * 64 in md and "K1" in md
