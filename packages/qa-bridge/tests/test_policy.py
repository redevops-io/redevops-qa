# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import pytest

from redevops_qa_bridge.policy import PHASE, PolicyPlaneActionPolicy


@pytest.fixture()
def step(gi, neutral):
    spec = neutral.records.TestSpec.from_json(__import__("redevops_qa_bridge").convert.contracts_data_to_neutral(gi("test_spec_ui")))
    return spec.steps[0]


def _answer(**over):
    base = {"id": "pd-s1-1", "phase": PHASE, "decision": "allow", "rule_id": "rule-1", "reason": "ok",
            "provider": "cr-plane", "scope": ["ui:click"]}
    base.update(over)
    return base


def _policy(provider, **kw):
    return PolicyPlaneActionPolicy(provider, principal="qa-runner", app="app-1", **kw)


def test_it_satisfies_the_neutral_action_policy_port(neutral):
    assert isinstance(_policy(lambda r: _answer()), neutral.ports.ActionPolicy)


def test_an_allow_becomes_an_allow_record_bound_to_the_run_and_step(step, neutral):
    seen = []
    policy = _policy(lambda req: seen.append(req) or _answer())
    rec = policy.decide("run-1", step, 1)
    assert rec.decision is neutral.records.PolicyDecisionKind.ALLOW
    assert (rec.run_id, rec.step_id, rec.phase, rec.policy_decision_id) == ("run-1", step.step_id, "ui_action", "pd-s1-1")
    assert (rec.action_kind, rec.side_effect, rec.provider, rec.rule_id) == (step.action.kind, step.side_effect, "cr-plane", "rule-1")
    req = seen[0]
    assert req["phase"] == "ui_action" and req["step_id"] == step.step_id and req["attempt"] == 1
    assert all(type(v) in (str, int, list) for v in req.values())


def test_the_request_is_plain_data_and_a_copy(step):
    def provider(req):
        req["step_id"] = "tampered"
        return _answer()
    rec = _policy(provider).decide("run-1", step, 1)
    assert rec.step_id == step.step_id


@pytest.mark.parametrize("decision,expected", [("deny", "DENY"), ("DENY", "DENY"), ("require_approval", "REQUIRE_APPROVAL")])
def test_deny_and_require_approval_carry_through(step, neutral, decision, expected):
    rec = _policy(lambda r: _answer(decision=decision)).decide("run-1", step, 1)
    assert rec.decision.value == expected


@pytest.mark.parametrize("answer", [
    _answer(decision="redact"), _answer(decision="flag"), _answer(decision="maybe"), _answer(decision=None),
    _answer(phase="tool_call"), {k: v for k, v in _answer().items() if k != "phase"},
    _answer(run_id="other-run"), _answer(step_id="other-step"), _answer(id="bad id"), {k: v for k, v in _answer().items() if k != "id"},
    "allow", ["allow"], None, 7,
])
def test_anything_unusable_is_a_denial(step, neutral, answer):
    rec = _policy(lambda r: answer).decide("run-1", step, 1)
    assert rec.decision is neutral.records.PolicyDecisionKind.DENY
    assert rec.run_id == "run-1" and rec.step_id == step.step_id


@pytest.mark.parametrize("exc", [RuntimeError("down"), TimeoutError("slow"), KeyError("k"), ValueError("v")])
def test_a_provider_error_or_timeout_is_a_denial(step, neutral, exc):
    def provider(req):
        raise exc
    rec = _policy(provider).decide("run-1", step, 2)
    assert rec.decision is neutral.records.PolicyDecisionKind.DENY and rec.rule_id == "policy-plane-unusable"


def test_a_class_instance_answer_is_refused_as_not_data(step, neutral):
    class Decision:            # stands in for a Context Runtime dataclass: not plain data, so not accepted
        decision = "allow"
    rec = _policy(lambda r: Decision()).decide("run-1", step, 1)
    assert rec.decision is neutral.records.PolicyDecisionKind.DENY


def test_the_record_hash_is_stable_and_excludes_custody(step):
    class Clock:
        def now_utc(self):
            return "2026-10-30T10:00:00Z"
    a = _policy(lambda r: _answer(reason="one"), clock=Clock()).decide("run-1", step, 1)
    b = _policy(lambda r: _answer(reason="two")).decide("run-1", step, 1)
    assert a.canon_hash() == b.canon_hash()
