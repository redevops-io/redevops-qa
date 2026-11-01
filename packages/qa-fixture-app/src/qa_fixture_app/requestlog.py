# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Request log: one JSON object per line, written to the file the caller names.

A record says what was asked of the app, so a later experiment can assert what a browser or a test engine requested (for example
that nothing but the expected paths and Host headers arrived). It carries no clock and no client address, never a cookie value,
a form value or a password (form field names only), so the same requests give byte-identical records in any run.

Fields: ``seq`` (1-based, in the order the app answered), ``method``, ``target`` (the raw request target, path and query), ``host``
(the Host header, without ``:<port>`` when the port is the app's own, so the record does not depend on the ephemeral port),
``status``, ``has_cookie``, ``form_keys`` (sorted names of the submitted form fields), ``body_bytes``.
"""
from __future__ import annotations

import json
import threading
from typing import Dict, List, Optional, TextIO


class RequestLog:
    def __init__(self, path: Optional[str], own_port: int = 0):
        self._own_port = own_port
        self._lock = threading.Lock()
        self._seq = 0
        # newline="\n": the same bytes on every operating system. "w": a log describes one run of the app.
        self._file: Optional[TextIO] = open(path, "w", encoding="utf-8", newline="\n") if path else None

    @property
    def count(self) -> int:
        return self._seq

    def host_field(self, host_header: str) -> str:
        suffix = ":%d" % self._own_port
        return host_header[:-len(suffix)] if self._own_port and host_header.endswith(suffix) else host_header

    def record(self, method: str, target: str, host_header: str, status: int, has_cookie: bool, form_keys: List[str], body_bytes: int) -> Dict[str, object]:
        with self._lock:
            self._seq += 1
            entry: Dict[str, object] = {"seq": self._seq, "method": method, "target": target, "host": self.host_field(host_header),
                                        "status": status, "has_cookie": has_cookie, "form_keys": sorted(form_keys), "body_bytes": body_bytes}
            if self._file is not None:
                self._file.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
                self._file.flush()
            return entry

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                self._file.close()
                self._file = None
