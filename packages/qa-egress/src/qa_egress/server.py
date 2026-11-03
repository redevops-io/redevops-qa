# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Run the gateway on its own event loop in a background thread (for tests and for embedding), with thread-safe snapshots."""
from __future__ import annotations

import asyncio
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

from ._harness import EgressPolicy, Resolver
from .gateway import EgressGateway
from .records import GatewayRecord


class GatewayServer:
    """``with GatewayServer(policy, resolver) as gw: ...``. ``gw.port`` is where it listens (loopback unless a host is given).
    Everything else is passed to :class:`EgressGateway`."""

    def __init__(self, policy: EgressPolicy, resolver: Resolver, gateway_class: type = EgressGateway, **kwargs: Any) -> None:
        self._make = lambda: gateway_class(policy, resolver, **kwargs)
        self._gateway: Optional[EgressGateway] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._error: Optional[BaseException] = None
        self._stopped = threading.Event()

    # -- lifecycle -------------------------------------------------------------------------------------------------
    def start(self, timeout: float = 10.0) -> "GatewayServer":
        self._thread = threading.Thread(target=self._run, name="qa-egress", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout):
            raise TimeoutError("the egress gateway did not start")
        if self._error is not None:
            raise self._error
        return self

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            self._gateway = self._make()
            loop.run_until_complete(self._gateway.start())
        except BaseException as exc:                 # reported to start()
            self._error = exc
            self._ready.set()
            loop.close()
            return
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            loop.run_until_complete(self._gateway.stop())
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(loop.shutdown_default_executor())
            loop.close()
            self._stopped.set()

    def stop(self, timeout: float = 10.0) -> None:
        if self._loop is None or self._thread is None:
            return
        if not self._stopped.is_set():
            self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout)
        if self._thread.is_alive():
            raise TimeoutError("the egress gateway did not stop")

    @property
    def running(self) -> bool:
        """True while the gateway thread is alive and has not been stopped (a stopped or crashed gateway answers nothing; its event loop is closed)."""
        return self._thread is not None and self._thread.is_alive() and not self._stopped.is_set()

    def __enter__(self) -> "GatewayServer":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # -- access ----------------------------------------------------------------------------------------------------
    @property
    def gateway(self) -> EgressGateway:
        assert self._gateway is not None
        return self._gateway

    @property
    def port(self) -> int:
        return self.gateway.port

    def _call(self, fn: Callable[[], Any]) -> Any:
        assert self._loop is not None
        done: "asyncio.Future[Any]" = asyncio.run_coroutine_threadsafe(self._wrap(fn), self._loop)       # type: ignore[assignment]
        return done.result(10)

    @staticmethod
    async def _wrap(fn: Callable[[], Any]) -> Any:
        return fn()

    def records(self) -> Tuple[GatewayRecord, ...]:
        return self._call(self.gateway.ledger.records)

    def drain_records(self) -> Tuple[GatewayRecord, ...]:
        return self._call(self.gateway.ledger.drain)

    def events(self) -> List[Dict[str, Any]]:
        return [event for record in self.records() for event in record.evidence_events()]

    def summary(self) -> Dict[str, Any]:
        return self._call(self.gateway.ledger.summary_event)

    def counts(self) -> Dict[str, int]:
        return self._call(lambda: dict(self.gateway.ledger.counts))

    def active_connections(self) -> int:
        return self._call(lambda: self.gateway.active_connections)

    def wait_idle(self, timeout: float = 5.0) -> None:
        """Wait until no client connection is in flight (so a record exists for every request a test made)."""
        import time
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.active_connections() == 0:
                time.sleep(0.02)                  # the record is added right after the connection ends
                if self.active_connections() == 0:
                    return
            time.sleep(0.01)
        raise TimeoutError("connections still in flight")
