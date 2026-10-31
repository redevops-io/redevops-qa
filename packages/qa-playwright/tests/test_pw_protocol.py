# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The adapter satisfies both forms of the qa-adapter/1 protocol, and the one rule that matters most is in its signature."""
import inspect

import pytest
from qa_playwright import PlaywrightAdapter
from redevops_qa_bridge import deps
from redevops_qa_bridge.conformance import checks

from qa_pw_support import make_world


def test_the_adapter_satisfies_the_neutral_protocol(pins):
    from agent_harness.qa.ports import NeutralQAAdapter
    world = make_world()
    assert isinstance(world.adapter, NeutralQAAdapter)
    assert isinstance(PlaywrightAdapter.adapter_id, str) and PlaywrightAdapter.api_version == "qa-adapter/1"


def test_the_adapter_class_satisfies_the_contracts_and_the_neutral_form_with_the_bridges_own_check(pins):
    contracts = deps.contracts_qa()
    neutral_ports = deps.neutral_module("ports")
    assert checks._satisfies(PlaywrightAdapter, contracts.QAAdapter) == []
    assert checks._satisfies(PlaywrightAdapter, neutral_ports.NeutralQAAdapter) == []


def test_the_bridges_qa_playwright_conformance_item_passes_for_this_class(pins):
    import copy
    from types import SimpleNamespace
    contracts, neutral = deps.contracts_qa(), deps.neutral_qa()
    conformance = dict(pins.conformance, qa_playwright_class="qa_playwright:PlaywrightAdapter", qa_playwright_required=True)
    ctx = SimpleNamespace(pins=SimpleNamespace(conformance=conformance), contracts=contracts, neutral=neutral)
    checks.run_qa_playwright(ctx, SimpleNamespace(data={}))
    broken = copy.deepcopy(conformance)
    broken["qa_playwright_class"] = "qa_playwright:NoSuchClass"
    with pytest.raises(Exception):
        checks.run_qa_playwright(SimpleNamespace(pins=SimpleNamespace(conformance=broken), contracts=contracts, neutral=neutral),
                                 SimpleNamespace(data={}))


def test_the_bridge_shim_accepts_the_adapter_in_both_directions(pins):
    from redevops_qa_bridge import ContractsQAAdapterFromNeutral
    world = make_world()
    shim = ContractsQAAdapterFromNeutral(world.adapter)
    assert shim.adapter_id == world.adapter.adapter_id and shim.api_version == "qa-adapter/1"


def test_assert_takes_a_subject_and_nothing_else():
    params = list(inspect.signature(PlaywrightAdapter.assert_).parameters)
    assert params == ["self", "s", "subject"]
    for name in params:
        assert "expect" not in name
    returns = inspect.signature(PlaywrightAdapter.assert_).return_annotation
    assert "ObservedValue" in str(returns)


def test_protocol_method_names_and_parameters_are_exactly_the_documented_ones():
    expected = {
        "open_session": ["self", "profile"], "observe": ["self", "s", "req"], "locate": ["self", "s", "target", "mode"],
        "act": ["self", "s", "action", "target"], "assert_": ["self", "s", "subject"], "capture": ["self", "s", "kinds"],
        "reset": ["self", "s", "scope"], "close_session": ["self", "s"]}
    for name, params in expected.items():
        assert list(inspect.signature(getattr(PlaywrightAdapter, name)).parameters) == params
    assert inspect.signature(PlaywrightAdapter.locate).parameters["mode"].kind is inspect.Parameter.KEYWORD_ONLY
