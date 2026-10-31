# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The session context: the active pins and the verified, imported dependencies.

``get_context()`` is what every conformance item starts from. It fails (never skips) with a stable code when the pinned
trees are absent, are not exactly the pinned ones, or cannot be imported.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .. import deps
from ..errors import DependencyUnavailable, PinMismatch, PinsInvalid
from ..pins import Pins, load_pins
from .model import ConformanceFailure

_ACTIVE: Optional[Pins] = None
_CONTEXT: Optional["Context"] = None


@dataclass(frozen=True)
class Context:
    pins: Pins
    contracts: Any              # runtime_contracts.qa
    neutral: Any                # agent_harness.qa


def set_pins(pins: Optional[Pins]) -> None:
    """Select the pins for this process (the CLI does this); ``None`` returns to the default file and pin set."""
    global _ACTIVE, _CONTEXT
    _ACTIVE = pins
    _CONTEXT = None


def active_pins() -> Pins:
    global _ACTIVE
    if _ACTIVE is None:
        try:
            _ACTIVE = load_pins()
        except PinsInvalid as exc:
            raise ConformanceFailure("PINS_INVALID", exc.message) from exc
    return _ACTIVE


def get_context() -> Context:
    global _CONTEXT
    if _CONTEXT is not None:
        return _CONTEXT
    pins = active_pins()
    try:
        deps.verify_pins(pins)
    except DependencyUnavailable as exc:
        raise ConformanceFailure("DEPENDENCY_UNAVAILABLE", exc.message, **exc.details) from exc
    except PinMismatch as exc:
        problems = exc.details.get("problems") or [{"code": "PIN_MISMATCH", "message": exc.message}]
        raise ConformanceFailure(problems[0]["code"], exc.message, problems=problems) from exc
    _CONTEXT = Context(pins=pins, contracts=deps.contracts_qa(), neutral=deps.neutral_qa())
    return _CONTEXT
