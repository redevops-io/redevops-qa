# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``python -m qa_egress --config FILE``: run the gateway from operator configuration until interrupted.

The configuration is one JSON file the operator owns (never a page, a spec or a model output)::

    {"listen": {"host": "127.0.0.1", "port": 3128},
     "policy": {"allow": ["https://example.org"], "private": [{"host": "app", "networks": ["10.0.0.0/24"],
                "schemes": ["http"], "ports": [8080]}], "max_redirects": 5},
     "limits": {"max_response_bytes": 8388608}}

``policy`` is the harness ``EgressPolicy.from_config`` form. Names are resolved by the system resolver, once per decision.
On exit the run's ``EgressSummary`` is written to standard output as JSON.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
from pathlib import Path
from typing import List, Optional

from ._harness import EgressPolicy
from .gateway import EgressGateway
from .limits import GatewayLimits
from .resolver import SystemResolver


async def _run(config: dict) -> dict:
    listen = config.get("listen", {})
    gateway = EgressGateway(EgressPolicy.from_config(config.get("policy", {})), SystemResolver(),
                            limits=GatewayLimits.from_config(config.get("limits", {})), host=listen.get("host", "127.0.0.1"),
                            port=int(listen.get("port", 3128)), log=lambda line: print(line, file=sys.stderr, flush=True))
    await gateway.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    await gateway.stop()
    return gateway.ledger.summary_event()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="qa_egress", description="ReDevOps QA egress gateway")
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args(argv)
    config = json.loads(args.config.read_text(encoding="utf-8"))
    print(json.dumps(asyncio.run(_run(config)), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
