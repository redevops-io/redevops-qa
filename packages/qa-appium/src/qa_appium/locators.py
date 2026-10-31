# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Locators for a mobile action: ``id=`` (Android resource id) or ``acc=`` (accessibility id) with a bounded value. No XPath."""
from __future__ import annotations

import re
from dataclasses import dataclass

from qa_adapter_kit import AdapterFault

_VALUE = re.compile(r"^[A-Za-z0-9_.:/ -]{1,128}$")


@dataclass(frozen=True)
class MobileLocator:
    kind: str       # id | acc
    value: str

    def __str__(self) -> str:
        return f"{self.kind}={self.value}"


def parse_mobile_locator(text: str) -> MobileLocator:
    if not isinstance(text, str) or "\x00" in text or not text or len(text) > 256:
        raise AdapterFault("the locator is empty, too long or contains a NUL byte", retryable=False)
    kind, sep, value = text.partition("=")
    if not sep or kind not in ("id", "acc") or not _VALUE.match(value) or not value.strip():
        raise AdapterFault("a locator is id=<resource id> or acc=<accessibility id> with letters, digits and . _ : / - and spaces", retryable=False)
    return MobileLocator(kind, value)
