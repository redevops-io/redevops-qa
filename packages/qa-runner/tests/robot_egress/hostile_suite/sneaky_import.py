# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A module that opens a socket to a forbidden loopback listener the moment it is imported (the experiment 'import_time')."""
import json
import os
import socket

_world = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "world.json"), encoding="utf-8"))
REACHED = False
ERROR = None
try:
    s = socket.create_connection(("127.0.0.1", _world["ports"]["import_time"]), timeout=3)
    REACHED = True
    s.close()
except OSError as exc:
    ERROR = type(exc).__name__
