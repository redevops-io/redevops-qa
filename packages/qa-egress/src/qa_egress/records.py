# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""What the gateway keeps about what it did: one record per request or connection, and counters.

A record holds the egress decision (plain data with a ``canon-v1`` hash: scheme, host, port, addresses, reason codes; never a
path, a query, a header or a body) and what then happened. ``evidence_event`` renders a record in the shape the runner writes
for an egress decision, plus the gateway's own fields, so the two streams read the same.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Optional, Tuple

from ._harness import EgressDecision

#: closed vocabularies: nothing else is ever written into a record or a counter name
KINDS = ("http", "connect", "upgrade", "malformed")
OUTCOMES = ("relayed", "tunnelled", "denied", "refused", "upstream_error", "limit", "aborted")
LIMITS_HIT = ("header_bytes", "header_lines", "uri", "request_body", "response_bytes", "response_header_bytes",
              "tunnel_bytes", "connections", "read_timeout", "connect_timeout", "dns_timeout", "upstream_timeout",
              "idle_timeout", "total_timeout", "redirects")
OVERFLOW_HOST = "(other)"


@dataclass(frozen=True)
class GatewayRecord:
    seq: int
    kind: str
    outcome: str
    status: Optional[int]
    bytes_up: int
    bytes_down: int
    duration_ms: int
    decision: Optional[EgressDecision] = None
    redirect_decision: Optional[EgressDecision] = None      # the decision on the Location of a 3xx answer, if there was one
    limit: Optional[str] = None
    reason: Optional[str] = None            # a protocol-level refusal code (a short constant), when there is no decision

    def __post_init__(self) -> None:
        assert self.kind in KINDS and self.outcome in OUTCOMES, (self.kind, self.outcome)
        assert self.limit is None or self.limit in LIMITS_HIT, self.limit

    def evidence_events(self) -> List[Dict[str, Any]]:
        """The request's event, then (if the answer was a redirect) the event of the decision on its target."""
        events = [self._event()]
        if self.redirect_decision is not None:
            events.append({"kind": "EgressDecision", "seq": self.seq, "request_kind": "redirect",
                           "decision": self.redirect_decision.to_json(), "decision_hash": self.redirect_decision.record_hash})
        return events

    def _event(self) -> Dict[str, Any]:
        event: Dict[str, Any] = {"kind": "EgressDecision", "seq": self.seq, "request_kind": self.kind, "outcome": self.outcome,
                                 "status": self.status, "bytes_up": self.bytes_up, "bytes_down": self.bytes_down,
                                 "duration_ms": self.duration_ms}
        if self.decision is not None:
            event["decision"] = self.decision.to_json()
            event["decision_hash"] = self.decision.record_hash
        if self.limit is not None:
            event["limit"] = self.limit
        if self.reason is not None:
            event["reason"] = self.reason
        return event


class Ledger:
    """Bounded record log and counters. Used from the gateway's event loop only."""

    def __init__(self, max_records: int, max_denied_hosts: int, policy_id: str) -> None:
        self._records: Deque[GatewayRecord] = deque()
        self._max = max_records
        self._max_hosts = max_denied_hosts
        self._policy_id = policy_id
        self.counts: Dict[str, int] = {"connections": 0, "requests": 0, "allowed": 0, "denied": 0, "refused": 0, "relayed": 0,
                                       "tunnelled": 0, "upstream_errors": 0, "bytes_up": 0, "bytes_down": 0,
                                       "dropped_records": 0, "log_dropped": 0}
        for name in LIMITS_HIT:
            self.counts["limit_" + name] = 0
        self._denied_hosts: Dict[str, int] = {}
        self._seq = 0

    def next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def add(self, record: GatewayRecord) -> GatewayRecord:
        c = self.counts
        c["requests"] += 1
        c["bytes_up"] += record.bytes_up
        c["bytes_down"] += record.bytes_down
        for decision in (record.decision, record.redirect_decision):
            if decision is None:
                continue
            if decision.allowed:
                c["allowed"] += 1
            else:
                c["denied"] += 1
                host = decision.host or "(unparsed)"
                if host not in self._denied_hosts and len(self._denied_hosts) >= self._max_hosts:
                    host = OVERFLOW_HOST
                self._denied_hosts[host] = self._denied_hosts.get(host, 0) + 1
        if record.outcome == "refused":
            c["refused"] += 1
        elif record.outcome in ("relayed", "tunnelled"):
            c[record.outcome] += 1
        elif record.outcome == "upstream_error":
            c["upstream_errors"] += 1
        if record.limit is not None:
            c["limit_" + record.limit] += 1
        if len(self._records) >= self._max:
            c["dropped_records"] += 1
        else:
            self._records.append(record)
        return record

    def note_limit(self, name: str) -> None:
        self.counts["limit_" + name] += 1

    def records(self) -> Tuple[GatewayRecord, ...]:
        return tuple(self._records)

    def drain(self) -> Tuple[GatewayRecord, ...]:
        out = tuple(self._records)
        self._records.clear()
        return out

    def denied_hosts(self) -> Tuple[Tuple[str, int], ...]:
        return tuple(sorted(self._denied_hosts.items()))

    def summary_event(self) -> Dict[str, Any]:
        return {"kind": "EgressSummary", "counts": dict(sorted(self.counts.items())),
                "denied_hosts": [list(item) for item in self.denied_hosts()], "policy_id": self._policy_id}
