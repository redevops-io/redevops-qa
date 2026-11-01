# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The golden plan: the specification the fixture app (``qa-fixture-app``) is checked with. Plain data, generated here and checked in as
``examples/golden-plan.json`` (a test requires the two to be identical, so the file a user reads is the plan the tests run).

Browser lane: sign in as the seeded user, open Settings, tick "Email notifications", save. Frozen assertions: the status text, the state of the
checkbox on the page that follows, and the final URL. With the ``settings`` defect the save is acknowledged and nothing is stored, so the
checkbox assertion fails and the other two hold."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import constants as K

VERIFIER_ID = "det-verifier"            # the verifier id the harness verifier answers to (agent_harness.qa.verifier.VERIFIER_ID)
VERIFIER_RANGE = ">=1.0,<2"


def _loc(role: Optional[str] = None, name: Optional[str] = None, test_id: Optional[str] = None) -> Dict[str, Any]:
    d: Dict[str, Any] = {"frame_path": []}
    if role:
        d["role"] = role
    if name:
        d["name"] = name
    if test_id:
        d["test_id"] = test_id
    return d


def _step(step_id: str, kind: str, locator: Dict[str, Any], *, value: Optional[str] = None, effect: str = "NONE", transition: str = "the page changes") -> Dict[str, Any]:
    action: Dict[str, Any] = {"kind": kind}
    if value is not None:
        action["value"] = value
    return {"step_id": step_id, "intent": f"{kind} ({step_id})", "action": action, "expected_transition": transition,
            "idempotency": "IDEMPOTENT" if effect == "NONE" else "AT_MOST_ONCE", "retry_safety": "SAFE" if effect == "NONE" else "UNSAFE",
            "side_effect": effect, "observation_deadline_ms": 5000, "permitted_recovery": [], "target": {"kind": "ui", "locator": locator}}


def _assertion(assertion_id: str, subject: Dict[str, Any], op: str, expected: Any) -> Dict[str, Any]:
    return {"schema_id": "runtime-contracts/qa/assertion-spec", "schema_version": "0.1", "assertion_id": assertion_id, "executor": "PLAYWRIGHT",
            "determinism": "DETERMINISTIC", "on_unresolvable": "INDETERMINATE", "predicate": {"op": op, "expected": expected},
            "subject": {"inputs": [], "subject_alternates": [], **subject}, "verifier_id": VERIFIER_ID, "verifier_version_range": VERIFIER_RANGE}


def browser_spec() -> Dict[str, Any]:
    o = K.ORIGIN_PLACEHOLDER
    return {
        "schema_id": "runtime-contracts/qa/test-spec", "schema_version": "0.1", "id": "golden-settings", "version": 1,
        "target": {"app_id": "qa-fixture-app", "build_sha": "0123456789abcdef", "environment_profile": "local"},
        "steps": [
            _step("s1", "navigate", _loc(role="document"), value=o + "/login"),
            _step("s2", "fill", _loc(role="textbox", name="Email"), value="alice@example.test", effect="WRITES_INTERNAL"),
            _step("s3", "fill", _loc(role="textbox", name="Password"), value="correct horse", effect="WRITES_INTERNAL"),
            _step("s4", "click", _loc(role="button", name="Sign in"), effect="WRITES_INTERNAL"),
            _step("s5", "click", _loc(role="link", name="Settings")),
            _step("s6", "check", _loc(role="checkbox", name="Email notifications"), effect="WRITES_INTERNAL"),
            _step("s7", "click", _loc(role="button", name="Save settings"), effect="WRITES_INTERNAL"),
        ],
        "assertions": [
            _assertion("A-SAVED", {"kind": "UI_ELEMENT", "locator": _loc(test_id="save-status")}, "EQUALS", "Settings saved"),
            _assertion("A-NOTIF-ON", {"kind": "UI_ELEMENT", "locator": _loc(role="checkbox", name="Email notifications")}, "EQUALS", True),
            _assertion("A-URL", {"kind": "URL", "pattern": r"/settings\?saved=1$"}, "MATCHES", r"/settings\?saved=1$"),
        ],
        "budget": {"deadline_ms": 60000, "max_model_calls": 0, "max_recovery_attempts": 0, "max_retries": 0, "max_tokens": 0},
        "egress_profile": "lane", "allowed_side_effects": ["WRITES_INTERNAL"], "preconditions": [], "fixtures": [], "depends_on": [], "cleanup": [],
        "sensitivity_labels": [],
    }


def _script_assertion(assertion_id: str, lane_id: str, expected: Any, program_ref: Dict[str, str]) -> Dict[str, Any]:
    return {"schema_id": "runtime-contracts/qa/assertion-spec", "schema_version": "0.1", "assertion_id": assertion_id, "executor": "SCRIPT", "determinism": "DETERMINISTIC",
            "on_unresolvable": "INDETERMINATE", "predicate": {"op": "EQUALS", "expected": expected}, "check_program_ref": dict(program_ref),
            "subject": {"kind": "RESOURCE_INPUTS", "inputs": [{"kind": "MANIFEST_PATH", "path": f"lanes/{lane_id}/observations.json"}], "subject_alternates": []},
            "verifier_id": VERIFIER_ID, "verifier_version_range": VERIFIER_RANGE}


def robot_spec() -> Dict[str, Any]:
    """The Robot lane's spec: no steps (the suite is the engine's work) and one SCRIPT assertion. The expected value is FROZEN here, in the assertion; the observation
    record the suite's run produces never carries it and the check program never receives it."""
    from .suites import evidence_program_ref
    expected = {"documents": 1, "input_errors": [], "observations": {"order_101_total_cents": 9450, "order_102_total_cents": 9999, "order_103_total_cents": 9000,
                                                                       "order_104_total_cents": 9005}}
    return {
        "schema_id": "runtime-contracts/qa/test-spec", "schema_version": "0.1", "id": "golden-order-discount", "version": 1,
        "target": {"app_id": "qa-fixture-app", "build_sha": "0123456789abcdef", "environment_profile": "local"},
        "steps": [], "assertions": [_script_assertion("A-ORDER-RULE", "robot", expected, evidence_program_ref())],
        "budget": {"deadline_ms": 60000, "max_model_calls": 0, "max_recovery_attempts": 0, "max_retries": 0, "max_tokens": 0},
        "egress_profile": "lane", "allowed_side_effects": [], "preconditions": [], "fixtures": [], "depends_on": [], "cleanup": [], "sensitivity_labels": [],
    }


def robot_lane() -> Dict[str, Any]:
    return {"lane_id": "robot", "engine": K.ENGINE_ROBOT, "egress": "not-enforced", "deadline_s": 120, "suite": "order-discount", "spec": robot_spec()}


def browser_lane() -> Dict[str, Any]:
    return {"lane_id": "browser", "engine": K.ENGINE_PLAYWRIGHT, "egress": "origin-only", "deadline_s": 120, "spec": browser_spec()}


def robot_plan() -> Dict[str, Any]:
    """A one-lane plan with the Robot lane (``examples/robot-plan.json``)."""
    return {"schema": K.PLAN_SCHEMA, "schema_version": K.SCHEMA_VERSION, "plan_id": "golden-fixture-robot", "target": {"kind": "fixture-app"}, "lanes": [robot_lane()]}


def golden_plan() -> Dict[str, Any]:
    lanes: List[Dict[str, Any]] = [browser_lane()]
    return {"schema": K.PLAN_SCHEMA, "schema_version": K.SCHEMA_VERSION, "plan_id": "golden-fixture", "target": {"kind": "fixture-app"}, "lanes": lanes}
