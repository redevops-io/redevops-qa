# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``qa_egress``: the enforcement point for the harness egress policy.

* :class:`EgressGateway` / :class:`GatewayServer`: a forward proxy (standard library, asyncio) that decides every request,
  redirect hop and tunnel with the harness policy, connects only to the pinned address and keeps decision records;
* :func:`build_launch_config`: the Chromium flags and Playwright settings that make the gateway the browser's only way out;
* :class:`SystemResolver`: the one place a name is resolved in production.
"""
from .decider import Decider, GuardDecider
from .gateway import EgressGateway, Refusal
from .launch import (CONTEXT_OPTIONS, FORBIDDEN_PREFIXES, LOOPBACK_NOT_BYPASSED, LaunchConfig, build_launch_config,
                     policy_off_config)
from .limits import GatewayLimits
from .records import GatewayRecord, Ledger
from .resolver import SystemResolver
from .server import GatewayServer

__version__ = "0.1.0.dev0"

__all__ = ["EgressGateway", "GatewayServer", "GatewayLimits", "GatewayRecord", "Ledger", "Decider", "GuardDecider", "Refusal",
           "SystemResolver", "LaunchConfig", "build_launch_config", "policy_off_config", "LOOPBACK_NOT_BYPASSED",
           "FORBIDDEN_PREFIXES", "CONTEXT_OPTIONS", "__version__"]
