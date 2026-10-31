# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Operator configuration of the adapter. Plain data; nothing here is read from a page, a spec or a model."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from ._harness import CaptureKind, EgressPolicy, Resolver
from .driver import ProxySettings

#: what ``observe`` and the action receipts capture when the request names no kind
DEFAULT_CAPTURE: Tuple[CaptureKind, ...] = (CaptureKind.A11Y_SNAPSHOT, CaptureKind.DOM_META, CaptureKind.SCREENSHOT)


@dataclass(frozen=True)
class EgressProfile:
    """What a ``SessionProfile.egress_profile`` id stands for.

    ``policy`` is the operator's allow-list (default deny: with no entry nothing is reachable). The adapter applies it to
    every request the browser makes, in the browser (the request gate) and before a navigation, as a second layer behind
    the egress gateway (``qa-egress``), which is the enforcement point. ``launch_args`` and ``proxy`` are the browser
    launch settings that make the gateway the only way out; ``qa_egress.launch`` builds them.
    """

    profile_id: str
    policy: EgressPolicy
    resolver: Optional[Resolver] = None
    launch_args: Tuple[str, ...] = ()
    proxy: Optional[ProxySettings] = None


@dataclass(frozen=True)
class AdapterConfig:
    action_timeout_ms: int = 5000
    locate_timeout_ms: int = 2000
    assert_timeout_ms: int = 2000
    navigation_timeout_ms: int = 10000
    poll_interval_ms: int = 100
    default_capture: Tuple[CaptureKind, ...] = DEFAULT_CAPTURE
    #: a raw artifact over this many bytes is refused whole (ResourceLimitExceeded), never cut: a cut could leave half of
    #: a secret outside every redaction pattern
    max_raw_artifact_bytes: int = 1 << 20
    max_raw_text_bytes: int = 1 << 16
    max_excerpt_entries: int = 50
    max_excerpt_text_chars: int = 512
    max_candidates: int = 50
    max_candidate_table: int = 2000
    max_value_chars: int = 4096
    max_title_chars: int = 200
    allow_trace: bool = False
    #: tracing records DOM snapshots and network data: it is a restricted class of artifact. It is off by default and the
    #: redactor must explicitly acknowledge its media type before one is returned.
    trace_media_type: str = "application/zip"

    def __post_init__(self) -> None:
        for name in ("action_timeout_ms", "locate_timeout_ms", "assert_timeout_ms", "navigation_timeout_ms",
                     "poll_interval_ms", "max_raw_artifact_bytes", "max_raw_text_bytes", "max_excerpt_entries",
                     "max_excerpt_text_chars", "max_candidates", "max_candidate_table", "max_value_chars",
                     "max_title_chars"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"AdapterConfig.{name}: expected a positive integer")
        if self.poll_interval_ms > self.action_timeout_ms:
            raise ValueError("AdapterConfig.poll_interval_ms: must not exceed the action timeout")
        if any(not isinstance(k, CaptureKind) or k is CaptureKind.TRACE for k in self.default_capture):
            raise ValueError("AdapterConfig.default_capture: observation kinds only (no trace)")
