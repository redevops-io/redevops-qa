# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Name resolution for production. Tests inject a fake with the same one-method shape (the harness ``Resolver`` protocol)."""
from __future__ import annotations

import socket
from typing import List, Sequence


class SystemResolver:
    """Resolves a name with the operating system's resolver and returns the address literals it gave, once each, in a stable
    order. It is the only code in this package that asks the system to resolve a name; the gateway calls it once per decision
    and connects to the address the decision pinned, so what it answers a second time never matters."""

    def resolve(self, host: str) -> Sequence[str]:
        found: List[str] = []
        for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            address = sockaddr[0]
            if address not in found:
                found.append(address)
        return sorted(found)
