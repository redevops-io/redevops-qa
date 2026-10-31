# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The action receipt payload the adapter keeps for every action it performed.

The runner builds the ``ActionReceipt`` record itself (``agent_harness.qa.receipts.build_receipt``); the adapter has no say
in the policy decision, the postcondition or the attempt number. What only the adapter can know is the state of the page
on either side of the action and exactly what it used, so it keeps that, as plain data, for the runner (or a test) to
read with :meth:`PlaywrightAdapter.receipt_payloads`. The state hashes are the harness's own (``receipts.state_hash``
over an observation built the way ``observe`` builds one), so a hash taken here equals the hash of an ``observe`` result
for the same page state.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from ._harness import LocatorDescriptor


@dataclass(frozen=True)
class ActionReceiptPayload:
    session_id: str
    step_id: str
    idempotency_key: str
    policy_decision_ref: str
    action_kind: str
    value_digest: Optional[str]          # digest of the literal value, or the SecretRef fingerprint; never the value
    candidate_ref: Optional[str]
    locator_used: Optional[LocatorDescriptor]
    strategy: Optional[str]
    state_before_hash: str
    state_after_hash: str
    result: str
    duration_ms: int

    @property
    def state_changed(self) -> bool:
        return self.state_before_hash != self.state_after_hash

    def to_json(self) -> Dict[str, Any]:
        return {
            "action_kind": self.action_kind, "candidate_ref": self.candidate_ref, "duration_ms": self.duration_ms,
            "idempotency_key": self.idempotency_key,
            "locator_used": self.locator_used.to_json() if self.locator_used is not None else None,
            "policy_decision_ref": self.policy_decision_ref, "result": self.result, "session_id": self.session_id,
            "state_after_hash": self.state_after_hash, "state_before_hash": self.state_before_hash,
            "step_id": self.step_id, "strategy": self.strategy, "value_digest": self.value_digest}
