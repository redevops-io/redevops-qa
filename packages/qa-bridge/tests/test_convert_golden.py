# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Every frozen golden case and value converts both ways, keeps its hash and round-trips to the identity."""
import pytest

from redevops_qa_bridge import convert
from redevops_qa_bridge.convert import assert_data_only


def _case_names(golden):
    return sorted(golden["cases"])


def test_the_golden_file_has_cases(golden):
    assert len(golden["cases"]) >= 25 and len(golden["values"]) >= 40


@pytest.fixture(scope="module")
def reg(contracts, neutral):
    return convert.registry()


def test_registry_pairs_every_record_but_the_plan(reg):
    assert set(reg.contracts_only_records) == {"runtime-contracts/qa/qa-plan"}
    assert not reg.neutral_only_records
    assert len(reg.records) == 16
    assert set(reg.reused) == {"Check", "EvidenceRef", "SecretRef"}


@pytest.mark.parametrize("name", ["action_receipt", "action_receipt_blocked_by_policy", "assertion_result_indeterminate",
                                  "assertion_result_pass", "assertion_spec_playwright", "assertion_spec_script",
                                  "assertion_spec_without_requirement_ref", "checkpoint", "cleanup_report",
                                  "fault_detection", "fault_event", "fault_recovery", "locator_candidate", "observation",
                                  "observed_value_ambiguous", "observed_value_resolved", "policy_decision", "review_item",
                                  "review_record", "run_manifest_assertion_integrity", "run_manifest_inconclusive_skipped",
                                  "run_manifest_pass", "test_spec_resource", "test_spec_ui"])
def test_record_cases_convert_both_ways(name, golden, gi, reg):
    case = golden["cases"][name]
    c_cls, n_cls = reg.records[case["schema_id"]]
    original = c_cls.from_json(gi(name))
    neutral_obj = convert.from_contracts(original)
    assert type(neutral_obj) is n_cls
    assert type(neutral_obj).__module__.startswith("agent_harness")
    assert neutral_obj.canon_hash().removeprefix("canon-v1:") == case["hash"].removeprefix("rcv1:")
    back = convert.to_contracts(neutral_obj)
    assert type(back) is c_cls and type(back).__module__.startswith("runtime_contracts")
    assert back == original
    assert back.content_hash == case["hash"]


def test_every_golden_record_case_is_covered_here(golden):
    covered = {"action_receipt", "action_receipt_blocked_by_policy", "assertion_result_indeterminate",
               "assertion_result_pass", "assertion_spec_playwright", "assertion_spec_script",
               "assertion_spec_without_requirement_ref", "checkpoint", "cleanup_report", "fault_detection",
               "fault_event", "fault_recovery", "locator_candidate", "observation", "observed_value_ambiguous",
               "observed_value_resolved", "policy_decision", "review_item", "review_record",
               "run_manifest_assertion_integrity", "run_manifest_inconclusive_skipped", "run_manifest_pass",
               "test_spec_resource", "test_spec_ui"}
    assert set(golden["cases"]) - covered == {"qa_plan"}


def test_every_golden_value_converts_both_ways(golden, reg):
    n_done = 0
    for name, entry in golden["values"].items():
        pair = reg.values.get(entry["type"])
        if pair is None:
            assert entry["type"] in {"PlanGate", "PlanItem", "ResourceClaim"}, name
            continue
        c_cls, n_cls = pair
        original = c_cls.from_json(entry["input"])
        neutral_obj = convert.from_contracts(original)
        assert type(neutral_obj) is n_cls
        assert neutral_obj.canon_hash().removeprefix("canon-v1:") == entry["hash"].removeprefix("rcv1:")
        assert convert.to_contracts(neutral_obj) == original
        n_done += 1
    assert n_done == 41


def test_plan_values_never_cross(golden, contracts):
    from redevops_qa_bridge.errors import UnknownSchema, UnknownType
    plan = contracts.QAPlan.from_json(golden["cases"]["qa_plan"]["input"])
    with pytest.raises(UnknownSchema) as info:
        convert.from_contracts(plan)
    assert info.value.code == "UNKNOWN_SCHEMA"
    gate = contracts.PlanGate.from_json(golden["values"]["plan_gate"]["input"])
    with pytest.raises(UnknownType):
        convert.from_contracts(gate)


def test_data_level_functions_return_plain_data_only(golden, gi, reg):
    data = gi("run_manifest_pass")
    out = convert.contracts_data_to_neutral(reg.records["runtime-contracts/qa/run-manifest"][0].from_json(data).to_json())
    assert_data_only(out)
    back = convert.neutral_data_to_contracts(out)
    assert_data_only(back)
    assert back["content_hash"].startswith("rcv1:") and out["content_hash"].startswith("canon-v1:")


def test_nested_records_get_their_hashes_mapped_too(gi, reg):
    manifest = reg.records["runtime-contracts/qa/run-manifest"][0].from_json(gi("run_manifest_pass")).to_json()
    out = convert.contracts_data_to_neutral(manifest)
    nested = [r for r in out["assertion_results"]]
    assert nested and all(r["content_hash"].startswith("canon-v1:") for r in nested)


def test_enum_members_convert_by_value(contracts, neutral):
    for name in ("Executor", "Outcome", "ActionKind", "ResultCode", "SideEffect", "Verdict"):
        c_enum, n_enum = convert.registry().enums[name]
        for member in c_enum:
            converted = convert.from_contracts(member)
            assert type(converted) is n_enum and converted.value == member.value
            assert convert.to_contracts(converted) is member


def test_unknown_enum_member_is_refused_not_guessed(neutral):
    from redevops_qa_bridge.errors import UnknownType
    with pytest.raises(UnknownType):
        convert.to_contracts("PASS")      # a bare string is not a qa/v1 type
