# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Egress profiles as data. A lane names a profile; the profile turns the origin of the target into an allow-list in the form the harness
``EgressPolicy.from_config`` reads. The data is recorded in the bundle (``lanes/<lane>/egress-profile.json``), so what a lane was allowed to reach is part
of the evidence. Later hardening adds profiles here without changing the lanes."""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict

from .errors import PlanError


def policy_config(profile: str, origin: str) -> Dict[str, Any]:
    if profile != "origin-only":
        raise PlanError("BAD_EGRESS_PROFILE", f"unknown egress profile {profile!r}")
    parts = urllib.parse.urlsplit(origin)
    if parts.scheme != "http" or parts.hostname not in ("127.0.0.1",) or parts.port is None:
        raise PlanError("BAD_ORIGIN", "the origin-only profile allows exactly one http loopback origin (127.0.0.1 and an explicit port)")
    return {"private": [{"host": parts.hostname, "networks": [f"{parts.hostname}/32"], "schemes": ["http"], "ports": [parts.port], "label": "target-origin"}]}
