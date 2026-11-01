# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Fixtures for the fixture-app tests. The package imports no pinned tree. No live host may be contacted (loopback only), the same
guard the other packages use."""
import socket

import pytest

_REAL_CONNECT = socket.socket.connect
_REAL_CONNECT_EX = socket.socket.connect_ex
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def _guard(real):
    def guarded(self, address, *args, **kwargs):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            host = address[0] if isinstance(address, tuple) else address
            if host not in _LOOPBACK:
                raise AssertionError(f"tests may not connect to non-loopback address {host!r}")
        return real(self, address, *args, **kwargs)
    return guarded


@pytest.fixture(autouse=True, scope="session")
def _no_live_hosts():
    socket.socket.connect = _guard(_REAL_CONNECT)
    socket.socket.connect_ex = _guard(_REAL_CONNECT_EX)
    yield
    socket.socket.connect = _REAL_CONNECT
    socket.socket.connect_ex = _REAL_CONNECT_EX
