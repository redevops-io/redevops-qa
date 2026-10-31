# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Locators an action may use: ``css=``, ``id=``, ``name=`` or ``testid=`` followed by a bounded value. XPath is not offered: a locator
that comes from a request must stay small and checkable."""
from __future__ import annotations

import re
from dataclasses import dataclass

from qa_adapter_kit import AdapterFault

_KINDS = ("css", "id", "name", "testid")
_SIMPLE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_MAX = 512


@dataclass(frozen=True)
class Locator:
    kind: str          # css | id | name | testid
    value: str

    def css(self) -> str:
        """A CSS selector for every kind, so a driver needs one lookup path."""
        if self.kind == "css":
            return self.value
        if self.kind == "id":
            return f'[id="{self.value}"]'
        if self.kind == "name":
            return f'[name="{self.value}"]'
        return f'[data-testid="{self.value}"]'

    def __str__(self) -> str:
        return f"{self.kind}={self.value}"


def parse_locator(text: str) -> Locator:
    if not isinstance(text, str) or "\x00" in text or not text or len(text) > _MAX:
        raise AdapterFault("the locator is empty, too long or contains a NUL byte", retryable=False)
    kind, sep, value = text.partition("=")
    if not sep or kind not in _KINDS or not value.strip():
        raise AdapterFault(f"a locator is one of {', '.join(k + '=...' for k in _KINDS)}", retryable=False)
    if kind != "css" and not _SIMPLE.match(value):
        raise AdapterFault(f"the {kind} locator value has characters that are not allowed", retryable=False)
    if kind == "css" and any(c in value for c in "\n\r{};\\"):
        raise AdapterFault("the css locator contains a character that is not allowed", retryable=False)
    return Locator(kind, value)
