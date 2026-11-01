# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Access to the two pinned upstreams (``runtime_contracts``, ``agent_harness.qa``) through ``pins.toml``, exactly as the bridge does it.

``bootstrap`` puts the pinned trees on ``sys.path`` and imports both; ``verified_bootstrap`` also proves they are the pinned commits and
trees. Nothing is installed, downloaded or copied. A pin that does not verify is an ``EnvironmentFault``, never a skip."""
from __future__ import annotations

import os
from typing import Any, Dict, NamedTuple

from .errors import EnvironmentFault


class Upstreams(NamedTuple):
    pins: Any
    contracts: Any            # runtime_contracts.qa
    harness: Any              # agent_harness.qa


HARNESS_MODULES = ("blobs", "clock", "egress", "hooks", "policy", "records", "redaction", "runner", "specstore", "verifier", "integrity", "receipts")


def bootstrap() -> Upstreams:
    try:
        import importlib
        from redevops_qa_bridge import deps
        from redevops_qa_bridge.pins import load_pins
        pins = load_pins()
        deps.prepare_paths(pins)
        harness = deps.neutral_qa()
        for name in HARNESS_MODULES:
            importlib.import_module(f"agent_harness.qa.{name}")
        return Upstreams(pins, deps.contracts_qa(), harness)
    except EnvironmentFault:
        raise
    except Exception as exc:
        raise EnvironmentFault("DEPENDENCY_UNAVAILABLE", f"the pinned runtime-contracts and agent-harness cannot be loaded ({type(exc).__name__}: {exc}); "
                               "pins.toml names the exact commits; set REDEVOPS_QA_PINS or QA_PIN_CONTRACTS_PATH and QA_PIN_HARNESS_QA_PATH") from exc


def verified_bootstrap() -> Upstreams:
    up = bootstrap()
    try:
        from redevops_qa_bridge import deps
        deps.verify_pins(up.pins)
    except Exception as exc:
        raise EnvironmentFault("PIN_MISMATCH", f"the loaded dependencies are not the pinned ones ({type(exc).__name__}: {exc})") from exc
    return up


def pin_summary(up: Upstreams) -> Dict[str, str]:
    """Versions and commits of the pinned upstreams, for the lock and the bundle (plain strings, no paths)."""
    return {"contracts": up.pins.contracts.version, "contracts_commit": up.pins.contracts.commit, "harness": up.pins.harness_qa.version,
            "harness_commit": up.pins.harness_qa.commit, "pin_set": up.pins.pin_set}


def child_environment_keys() -> Dict[str, str]:
    """The only variables a child process inherits from this one: where the pins and the browser are, and what to import from."""
    keep = ("REDEVOPS_QA_PINS", "REDEVOPS_QA_PIN_SET", "QA_PIN_CONTRACTS_PATH", "QA_PIN_HARNESS_QA_PATH", "PLAYWRIGHT_BROWSERS_PATH")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    if "REDEVOPS_QA_PINS" not in env:
        try:                                         # a checkout finds pins.toml from the bridge; a child started elsewhere gets the path explicitly
            from redevops_qa_bridge.pins import find_pins_file
            env["REDEVOPS_QA_PINS"] = str(find_pins_file().resolve())
        except Exception:
            pass
    return env
