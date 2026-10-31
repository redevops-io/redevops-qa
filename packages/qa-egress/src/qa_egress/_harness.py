# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The single place in this package that imports the harness neutral module (``agent_harness.qa``).

Every other module imports harness names from here, so the import boundary is one file. If ``agent_harness.qa`` is not
importable the pinned tree named in ``pins.toml`` is put on ``sys.path`` through the bridge's documented helper
(``redevops_qa_bridge.deps.prepare_paths``) and the import is retried. Nothing is vendored or copied; the gateway enforces the
harness's own pure policy and adds no rule of its own to what the policy decides, only refusals the policy can never lift.
"""
from __future__ import annotations

import importlib


def _load():
    try:
        return importlib.import_module("agent_harness.qa")
    except ModuleNotFoundError as first:
        if first.name not in ("agent_harness", "agent_harness.qa"):
            raise
        try:
            from redevops_qa_bridge import deps as bridge_deps
            from redevops_qa_bridge.pins import load_pins
            bridge_deps.prepare_paths(load_pins())
            return importlib.import_module("agent_harness.qa")
        except Exception as second:
            raise ImportError(
                "agent_harness.qa is not importable: install the pinned agent-harness or set QA_PIN_HARNESS_QA_PATH "
                f"(pins.toml names the exact commit); fallback through the bridge failed with {type(second).__name__}"
            ) from first


_load()

from agent_harness.qa import canon, egress, errors                                          # noqa: E402,F401
from agent_harness.qa.clock import SystemClock                                                # noqa: E402,F401
from agent_harness.qa.egress import (AddressClass, AllowEntry, EgressDecision, EgressGuard, EgressPolicy,   # noqa: E402,F401
                                     EgressVerdict, NoResolver, Reason, Refused, Resolver, StaticResolver,
                                     address_text, classify_address, host_port_url, is_metadata_address, parse_target)
from agent_harness.qa.errors import QAError, RedactionFailed, SpecInvalid                      # noqa: E402,F401
from agent_harness.qa.ports import Clock, Redactor                                             # noqa: E402,F401
from agent_harness.qa.redaction import PatternRedactor, RedactionConfig                        # noqa: E402,F401
