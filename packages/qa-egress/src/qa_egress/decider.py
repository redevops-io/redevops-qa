# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Where decisions come from. The default :class:`GuardDecider` asks the harness egress policy; the gateway never decides by
itself, and what the policy decides it can only make stricter (``gateway.py`` refuses a few things whatever a decider says)."""
from __future__ import annotations

import asyncio
from typing import Optional

from ._harness import EgressDecision, EgressGuard, EgressPolicy, EgressVerdict, Reason, Resolver
from .limits import GatewayLimits


class Decider:
    """The three questions the gateway asks. Subclass for tests (a deliberately wrong decider shows what the gateway still
    refuses on its own)."""

    policy_id: str = ""

    async def decide_url(self, url: str, *, purpose: str, hop: int, previous_scheme: Optional[str]) -> EgressDecision:
        raise NotImplementedError

    async def decide_connect(self, host: str, port: int) -> EgressDecision:
        raise NotImplementedError

    async def decide_redirect(self, previous_url: str, location: str, *, hop: int, previous: EgressDecision) -> EgressDecision:
        raise NotImplementedError


def _resolver_timeout(policy_id: str, purpose: str, hop: int) -> EgressDecision:
    return EgressDecision(verdict=EgressVerdict.DENY, reasons=(Reason.DENY_RESOLVER_ERROR.value,), purpose=purpose, hop=hop,
                          policy_id=policy_id, resolved=True)


class GuardDecider(Decider):
    """Decisions by the harness ``EgressGuard``: one guard per decision (so no state is shared between requests), the
    resolver called once, in a worker thread, under a deadline."""

    def __init__(self, policy: EgressPolicy, resolver: Resolver, limits: GatewayLimits) -> None:
        self._policy = policy
        self._resolver = resolver
        self._limits = limits
        self.policy_id = policy.policy_id

    def _guard(self) -> EgressGuard:
        return EgressGuard(self._policy, self._resolver)

    async def _run(self, call, *, purpose: str, hop: int) -> EgressDecision:
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(loop.run_in_executor(None, call), self._limits.dns_timeout_s)
        except asyncio.TimeoutError:
            return _resolver_timeout(self.policy_id, purpose, hop)

    async def decide_url(self, url: str, *, purpose: str, hop: int, previous_scheme: Optional[str]) -> EgressDecision:
        guard = self._guard()
        return await self._run(lambda: guard.check(url, purpose=purpose, hop=hop, previous_scheme=previous_scheme),
                               purpose=purpose, hop=hop)

    async def decide_connect(self, host: str, port: int) -> EgressDecision:
        guard = self._guard()
        return await self._run(lambda: guard.check_host_port(host, port, scheme="https", purpose="connection"),
                               purpose="connection", hop=0)

    async def decide_redirect(self, previous_url: str, location: str, *, hop: int, previous: EgressDecision) -> EgressDecision:
        guard = self._guard()
        return await self._run(lambda: guard.check_redirect(previous_url, location, hop=hop, previous=previous),
                               purpose="redirect", hop=hop)
