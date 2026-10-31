# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Fixtures for the adapter tests. The pinned harness tree named in pins.toml is put on sys.path first (through the bridge's
documented helper); a missing dependency makes every test that needs it fail (the import raises), never skip. The real
browser lane lives in ``tests/browser`` and is not collected here (see the repository's pytest configuration)."""
import socket

import pytest
from redevops_qa_bridge import deps
from redevops_qa_bridge.pins import load_pins

PINS = load_pins()
deps.prepare_paths(PINS)

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


@pytest.fixture(scope="session")
def pins():
    return PINS
