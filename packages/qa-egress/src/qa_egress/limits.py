# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Resource bounds of the gateway. Every one is finite and checked at construction; a value outside its range is refused
rather than clamped (a bound that quietly becomes something else is not a bound)."""
from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any, Dict, Mapping

_RANGES: Dict[str, tuple] = {
    "max_header_bytes": (256, 1 << 20), "max_header_lines": (4, 1000), "max_uri_chars": (64, 8192),
    "max_request_body_bytes": (0, 1 << 30), "max_response_bytes": (1, 1 << 32), "max_response_header_bytes": (256, 1 << 20),
    "max_tunnel_bytes": (1, 1 << 32), "max_connections": (1, 100000), "max_records": (1, 1 << 20),
    "max_denied_hosts": (1, 1 << 16),
    "read_timeout_s": (0.01, 600.0), "connect_timeout_s": (0.01, 600.0), "dns_timeout_s": (0.01, 600.0),
    "upstream_header_timeout_s": (0.01, 600.0), "idle_timeout_s": (0.01, 3600.0), "total_timeout_s": (0.01, 3600.0),
    "tunnel_total_timeout_s": (0.01, 86400.0), "redirect_memory": (1, 1 << 16), "redirect_ttl_s": (0.1, 3600.0),
}


@dataclass(frozen=True)
class GatewayLimits:
    max_header_bytes: int = 16 * 1024            # the request head (request line and headers)
    max_header_lines: int = 100
    max_uri_chars: int = 2048                    # the same bound the egress policy applies to a URL
    max_request_body_bytes: int = 1 << 20
    max_response_bytes: int = 8 << 20            # relayed response bytes (body, including any chunk framing)
    max_response_header_bytes: int = 16 * 1024
    max_tunnel_bytes: int = 16 << 20             # both directions together, per CONNECT tunnel or upgraded connection
    max_connections: int = 64                    # concurrent client connections; one more is answered 503
    max_records: int = 4096                      # decision records kept until drained
    max_denied_hosts: int = 1024                 # distinct denied hosts counted (the rest go to one overflow bucket)
    read_timeout_s: float = 5.0                  # for the whole request head
    connect_timeout_s: float = 5.0
    dns_timeout_s: float = 3.0
    upstream_header_timeout_s: float = 10.0
    idle_timeout_s: float = 15.0                 # between two reads on any connection
    total_timeout_s: float = 30.0                # a plain request, start to end
    tunnel_total_timeout_s: float = 120.0
    redirect_memory: int = 1024                  # remembered redirects (for the chain-length count)
    redirect_ttl_s: float = 60.0

    def __post_init__(self) -> None:
        for name, (low, high) in _RANGES.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
                raise ValueError(f"GatewayLimits.{name}: expected a number between {low} and {high}")

    @staticmethod
    def from_config(config: Mapping[str, Any]) -> "GatewayLimits":
        known = {f.name for f in fields(GatewayLimits)}
        unknown = set(config) - known
        if unknown:
            raise ValueError(f"GatewayLimits: unknown keys {sorted(map(str, unknown))}")
        return GatewayLimits(**dict(config))
