# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Fixture of the qa-service tests: a real server on an ephemeral loopback port (see qs_support for the fake command). Nothing here starts a browser or reaches a host other than loopback."""
import json
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from qa_service.config import load_config      # noqa: E402
from qa_service.server import QAServer         # noqa: E402
from qs_support import Client, make_env        # noqa: E402


@pytest.fixture
def make_server(tmp_path, monkeypatch):
    servers = []

    monkeypatch.setattr("qa_service.runs.available_modules", lambda names: [])        # the real lanes are not started here, so their packages are not needed

    def make(control=None, **extra):
        env = make_env(tmp_path, **extra)
        if control is not None:
            (tmp_path / "bin" / "control.json").write_text(json.dumps(control))
        cfg = load_config(env)
        srv = QAServer(cfg)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv, Client(srv.server_address[1])

    yield make
    for s in servers:
        s.shutdown()
        s.server_close()
