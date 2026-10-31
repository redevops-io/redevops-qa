# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import copy

import pytest

from redevops_qa_bridge import plan as bridge_plan
from redevops_qa_bridge.errors import DataOnlyViolation, PlanRejected, UnsupportedCoverageContract


@pytest.fixture()
def plan_data(gi):
    return gi("qa_plan")


def test_a_full_plan_validates_and_comes_back_as_plain_data(plan_data):
    out = bridge_plan.validate_plan(plan_data)
    assert out["coverage_contract"] == "FULL" and out["content_hash"].startswith("rcv1:")


def test_subset_is_rejected_before_anything_else(plan_data):
    plan_data["coverage_contract"] = "SUBSET"
    with pytest.raises(UnsupportedCoverageContract) as info:
        bridge_plan.validate_plan(plan_data)
    assert info.value.code == "UNSUPPORTED_COVERAGE_CONTRACT"


@pytest.mark.parametrize("value", ["SUBSET", "subset", "PARTIAL", "", None, 1, "FULL "])
def test_anything_but_exactly_full_is_rejected(plan_data, value):
    plan_data["coverage_contract"] = value
    with pytest.raises(UnsupportedCoverageContract):
        bridge_plan.validate_plan(plan_data)


def test_a_subset_plan_releases_no_items(plan_data):
    plan_data["coverage_contract"] = "SUBSET"
    with pytest.raises(UnsupportedCoverageContract):
        bridge_plan.runnable_items(plan_data)


def test_a_missing_coverage_contract_is_the_contracts_refusal(plan_data):
    del plan_data["coverage_contract"]
    with pytest.raises(PlanRejected) as info:
        bridge_plan.validate_plan(plan_data)
    assert info.value.code == "MISSING_FIELD"


def test_a_plan_with_a_dispatch_field_keeps_the_contracts_reason_code(plan_data):
    plan_data["work_stealing"] = True
    with pytest.raises(PlanRejected) as info:
        bridge_plan.validate_plan(plan_data)
    assert info.value.code == "UNKNOWN_FIELD"


def test_a_contracts_plan_object_whose_coverage_was_forced_to_subset_is_rejected(contracts, plan_data):
    plan = contracts.QAPlan.from_json(plan_data)
    object.__setattr__(plan, "coverage_contract", contracts.CoverageContract.SUBSET)    # bypassing the frozen type
    with pytest.raises(UnsupportedCoverageContract):
        bridge_plan.validate_plan(plan)


def test_a_contracts_plan_object_is_accepted_and_returned_as_data(contracts, plan_data):
    plan = contracts.QAPlan.from_json(plan_data)
    out = bridge_plan.validate_plan(plan)
    assert type(out) is dict and out["content_hash"] == plan.content_hash


def test_a_non_data_plan_is_refused(plan_data):
    with pytest.raises(DataOnlyViolation):
        bridge_plan.validate_plan({**plan_data, "extra": object()})
    with pytest.raises(PlanRejected):
        bridge_plan.validate_plan(None)
    with pytest.raises(PlanRejected):
        bridge_plan.validate_plan([plan_data])


def test_items_are_released_in_lane_order(plan_data):
    items = bridge_plan.runnable_items(plan_data)
    assert [i["spec_ref"] for i in items]
    keys = [(plan_data["lanes"].index(i["lane"]), i["order"]) for i in items]
    assert keys == sorted(keys)
    for item in items:
        assert type(item) is dict


def test_released_items_are_copies(plan_data):
    first = bridge_plan.runnable_items(plan_data)
    first[0]["lane"] = "tampered"
    assert bridge_plan.runnable_items(plan_data)[0]["lane"] != "tampered"


def test_the_named_guard_is_what_rejects_subset(plan_data, monkeypatch):
    """The refusal lives in _guard_full_coverage; with it removed the contracts validator is the remaining wall."""
    monkeypatch.setattr(bridge_plan, "_guard_full_coverage", lambda value: None)
    plan_data["coverage_contract"] = "SUBSET"
    with pytest.raises(PlanRejected) as info:
        bridge_plan.validate_plan(plan_data)
    assert info.value.code == "UNSUPPORTED_COVERAGE_CONTRACT"       # contracts still refuses (defence in depth)
