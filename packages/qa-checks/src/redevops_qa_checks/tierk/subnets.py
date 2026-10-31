# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The synthetic subnet plan for real connectivity tests, as data, and the policy on what a probe may target.

Real traffic tests never use a range that a developer machine or a corporate network could use. The two synthetic networks are
taken from the documentation ranges reserved for examples (never routed on the internet): one for the "world" container, one for
the target that stands in for a local-network range. They are meant to exist only inside an isolated network namespace on the
isolated host (an internal container network with no route out). Policy-state checks for the real local-network range come
first and are reported as such; traffic against the synthetic range is reported as traffic, never as proof about the real range.

``check_free`` takes the CIDRs already present on the host (observed by whoever runs bring-up) and refuses any overlap.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from ..errors import PolicyBlocked

#: ranges that may never be used by the synthetic plan: private ranges (a LAN somewhere uses them), loopback, link-local
#: (includes the node metadata address), carrier-grade NAT, multicast, and the cluster's own pod and service subnets
FORBIDDEN_NETWORKS: Tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
                                       "224.0.0.0/4", "0.0.0.0/8", "240.0.0.0/4")
CLUSTER_NETWORKS: Tuple[str, ...] = ("10.244.0.0/16", "10.43.0.0/16")

SUBNET_PLAN: Dict[str, Any] = {
    "schema": "qa-checks/synthetic-subnet-plan/1",
    "networks": {
        "world": {"cidr": "198.51.100.0/24", "purpose": "a container that stands for the outside world",
                  "hosts": {"gateway": "198.51.100.1", "world-target": "198.51.100.10"},
                  "listening_ports": {"denied": [25, 465, 587], "allowed": [8025]}},
        "lan-equivalent": {"cidr": "203.0.113.0/24", "purpose": "a target that stands in for a local-network range",
                           "hosts": {"gateway": "203.0.113.1", "lan-target": "203.0.113.10", "control-target": "203.0.113.20"},
                           "listening_ports": {"denied": [8080], "allowed": []}},
    },
    "isolation": {"container_network": "internal (no route to the internet or to any non-disposable system)", "location": "isolated host only",
                  "developer_machines": "not used: only policy-state checks run there"},
    "evidence": {"policy-state": "objects and enforcement state read from the cluster; reported as policy-state",
                 "traffic": "a probe result against the synthetic range; reported as traffic and never as proof about the real range"},
}


def _net(value: str) -> "ipaddress._BaseNetwork":
    return ipaddress.ip_network(value, strict=True)


def validate_plan(plan: Mapping[str, Any] = SUBNET_PLAN) -> None:
    """The synthetic networks are valid, do not overlap each other, the forbidden ranges or the cluster's networks; hosts lie inside."""
    nets = plan["networks"]
    parsed = {name: _net(n["cidr"]) for name, n in nets.items()}
    names = sorted(parsed)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if parsed[a].overlaps(parsed[b]):
                raise PolicyBlocked("synthetic networks overlap each other", guard_code="SUBNET_OVERLAP", networks=f"{a},{b}")
    for name, net in parsed.items():
        for bad in FORBIDDEN_NETWORKS + CLUSTER_NETWORKS:
            if net.overlaps(_net(bad)):
                raise PolicyBlocked("a synthetic network overlaps a forbidden or cluster range", guard_code="SUBNET_FORBIDDEN", network=name, range=bad)
        for host, ip in nets[name]["hosts"].items():
            if ipaddress.ip_address(ip) not in net:
                raise PolicyBlocked("a synthetic host lies outside its network", guard_code="SUBNET_HOST", network=name, host=host)


def check_free(existing_cidrs: Iterable[str], plan: Mapping[str, Any] = SUBNET_PLAN) -> None:
    """Refuse the plan if any network already on the host overlaps one of the synthetic networks (bring-up passes what it observed)."""
    validate_plan(plan)
    for cidr in existing_cidrs:
        try:
            other = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise PolicyBlocked("an observed network does not parse", guard_code="SUBNET_OBSERVED_INVALID") from None
        for name, n in plan["networks"].items():
            if other.version == _net(n["cidr"]).version and other.overlaps(_net(n["cidr"])):
                raise PolicyBlocked("a network already on the host overlaps the synthetic plan", guard_code="SUBNET_IN_USE", network=name)


class TargetPolicy:
    """Where a probe may point: the cluster's pod and service networks, the synthetic networks, and any extra network the bring-up
    declared (the container network the world target sits on). Never metadata or loopback or link-local addresses, never a name."""

    def __init__(self, extra_networks: Sequence[str] = (), plan: Mapping[str, Any] = SUBNET_PLAN) -> None:
        validate_plan(plan)
        extra = [ipaddress.ip_network(n, strict=True) for n in extra_networks]
        for n in extra:
            if any(n.version == _net(b).version and n.overlaps(_net(b)) for b in ("127.0.0.0/8", "169.254.0.0/16", "192.168.0.0/16")):
                raise PolicyBlocked("an extra target network may not overlap loopback, link-local or the 192.168.0.0/16 range",
                                    guard_code="TARGET_NETWORK_REFUSED")
        self._allowed = [_net(c) for c in CLUSTER_NETWORKS] + [_net(n["cidr"]) for n in plan["networks"].values()] + extra
        self._plan = plan

    def check(self, target: str) -> "ipaddress._BaseAddress":
        try:
            if type(target) is not str:
                raise ValueError
            ip = ipaddress.ip_address(target)
        except (ValueError, TypeError):
            raise PolicyBlocked("a probe target is an IP literal, never a name", guard_code="TARGET_NOT_IP_LITERAL") from None
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise PolicyBlocked("this address is never a probe target", guard_code="TARGET_REFUSED")
        if not any(ip.version == n.version and ip in n for n in self._allowed):
            raise PolicyBlocked("the address is outside the networks a probe may target", guard_code="TARGET_OUTSIDE_PLAN")
        return ip

    def is_synthetic(self, target: str) -> str:
        ip = ipaddress.ip_address(target)
        for name, n in self._plan["networks"].items():
            if ip in _net(n["cidr"]):
                return name
        return ""
