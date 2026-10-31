# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Secret redaction for everything that leaves a run: output tails, messages, native report text, observations."""
from __future__ import annotations

import re
from typing import Iterable

REDACTED = "[REDACTED]"
# name=value or name: value pairs whose name looks like a credential, and bearer tokens
_PAIR = re.compile(r"(?i)\b([A-Za-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|credential|authorization)[A-Za-z0-9_.-]*)(\s*[:=]\s*)(?:(?:Bearer|Basic)\s+)?[^\s,;\"']+")
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}")
MIN_SECRET_LENGTH = 4


class Redactor:
    """Replaces every known secret value, and anything shaped like a credential assignment, with ``[REDACTED]``."""

    def __init__(self, secrets: Iterable[str] = ()):
        values = sorted({s for s in secrets if isinstance(s, str) and len(s) >= MIN_SECRET_LENGTH}, key=len, reverse=True)
        self._values = tuple(values)

    @property
    def active(self) -> bool:
        return bool(self._values)

    def text(self, value: str) -> str:
        for secret in self._values:
            value = value.replace(secret, REDACTED)
        value = _PAIR.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", value)
        return _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", value)

    def data(self, value: bytes, *, limit: int | None = None) -> str:
        """Decode (never fails), keep the last ``limit`` characters, redact. The cut happens after redaction would have been
        possible on the full text, so a secret straddling the cut cannot survive as a fragment: redaction runs first."""
        decoded = value.decode("utf-8", errors="replace")
        redacted = self.text(decoded)
        return redacted if limit is None or len(redacted) <= limit else redacted[-limit:]
