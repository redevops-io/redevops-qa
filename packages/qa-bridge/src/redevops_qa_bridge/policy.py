# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Data-only adapter from the Context Runtime policy plane to the neutral ``ActionPolicy``.

The harness asks ``ActionPolicy.decide(run_id, step, attempt)`` for every UI action and records the answer as a
``PolicyDecisionRecord`` whose hash goes into the action receipt. The policy plane (Context Runtime, ``ui_action``
phase) owns the rules. This adapter connects the two with plain data only: it builds a JSON request, calls a provider
callable ``request -> response`` and reads the response as a JSON object. Context Runtime is not imported.

Fail closed (plan R3): a provider that raises (including a timeout), answers with anything but a plain JSON object,
names an unknown decision, answers for another phase, run or step, or omits a usable decision id produces a ``DENY``
record. ``redact`` and ``flag`` are not meaningful in this phase and are denials. Only ``allow``, ``deny`` and
``require_approval`` carry through.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, Mapping, Optional

from . import deps
from .convert import assert_data_only
from .errors import DataOnlyViolation

PHASE = "ui_action"
PROVIDER_ID = "context-runtime-policy-plane"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DECISIONS = {"allow": "ALLOW", "deny": "DENY", "require_approval": "REQUIRE_APPROVAL"}


def _request(run_id: str, step: Any, attempt: int, principal: str, app: str) -> Dict[str, Any]:
    kind = step.action.kind.value
    return {"phase": PHASE, "run_id": run_id, "step_id": step.step_id, "attempt": attempt, "principal": principal,
            "app": app, "action_kind": kind, "side_effect": step.side_effect.value,
            "idempotency": step.idempotency.value, "target_kind": step.target.kind.value, "scope": [f"ui:{kind}"]}


class PolicyPlaneActionPolicy:
    """``ActionPolicy`` backed by a policy-plane provider. ``provider(request) -> response`` exchanges plain JSON."""

    def __init__(self, provider: Callable[[Dict[str, Any]], Mapping[str, Any]], *, principal: str, app: str,
                 clock: Optional[Any] = None) -> None:
        if not callable(provider):
            raise TypeError("provider must be callable")
        self._provider = provider
        self._principal = principal
        self._app = app
        self._clock = clock

    def decide(self, run_id: str, step: Any, attempt: int):
        n = deps.neutral_qa()
        request = _request(run_id, step, attempt, self._principal, self._app)
        try:
            response = self._provider(dict(request))
            if type(response) is not dict:
                raise DataOnlyViolation("the policy plane must answer with a plain JSON object")
            assert_data_only(response, "policy response")
            return self._record(n, run_id, step, attempt, response)
        except Exception as exc:                                   # fail closed: any failure is a denial
            return self._deny(n, run_id, step, attempt, "policy-plane-unusable",
                              f"the policy plane did not give a usable decision ({type(exc).__name__})")

    def _deny(self, n: Any, run_id: str, step: Any, attempt: int, rule_id: str, reason: str):
        return deps.neutral_module("policy").failsafe_decision(run_id=run_id, step=step, attempt=attempt, rule_id=rule_id, reason=reason,
                                          principal=self._principal, app=self._app, clock=self._clock)

    def _record(self, n: Any, run_id: str, step: Any, attempt: int, response: Dict[str, Any]):
        decision = _DECISIONS.get(str(response.get("decision", "")).lower())
        if decision is None:
            return self._deny(n, run_id, step, attempt, "policy-plane-decision-unusable",
                              "the policy plane named a decision that is not allow, deny or require_approval")
        if response.get("phase") != PHASE:
            return self._deny(n, run_id, step, attempt, "policy-plane-wrong-phase", "the answer is not for ui_action")
        for key, expected in (("run_id", run_id), ("step_id", step.step_id)):
            if key in response and response[key] != expected:
                return self._deny(n, run_id, step, attempt, "policy-plane-wrong-binding",
                                  f"the answer decides another {key}")
        decision_id = response.get("id")
        if not isinstance(decision_id, str) or not _ID.fullmatch(decision_id):
            return self._deny(n, run_id, step, attempt, "policy-plane-no-decision-id", "the answer has no usable id")
        rule_id = response.get("rule_id")
        provider = response.get("provider")
        reason = response.get("reason")
        scope = response.get("scope", [f"ui:{step.action.kind.value}"])
        rec = n.records
        record = rec.PolicyDecisionRecord(
            policy_decision_id=decision_id, run_id=run_id, step_id=step.step_id, principal=self._principal,
            app=self._app, decision=rec.PolicyDecisionKind(decision),
            provider=provider if isinstance(provider, str) and _ID.fullmatch(provider) else PROVIDER_ID,
            action_kind=step.action.kind, side_effect=step.side_effect, phase=PHASE,
            rule_id=rule_id if isinstance(rule_id, str) and _ID.fullmatch(rule_id) else None,
            scope=tuple(scope) if isinstance(scope, (list, tuple)) else (),
            decided_at=self._clock.now_utc() if self._clock is not None else None,
            reason=reason[:4096] if isinstance(reason, str) else None)
        return record
