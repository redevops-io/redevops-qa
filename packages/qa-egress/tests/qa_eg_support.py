# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Support for the gateway tests: fake upstream servers on loopback, a scripted resolver, a raw HTTP client. Only loopback
sockets are opened; every name is mapped by the fake resolver and no test resolves a name for real."""
from __future__ import annotations

import socket
import socketserver
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from qa_egress import EgressGateway, GatewayLimits, GatewayServer

from agent_harness.qa.egress import AllowEntry, EgressPolicy


def canary_value(tag: str) -> str:
    """A canary secret built at run time (no credential-shaped literal is written in this repository)."""
    import hashlib
    return "".join(["RDQA", "-CANARY-", hashlib.sha256(tag.encode()).hexdigest()[:20]])


class ScriptedResolver:
    """A fake resolver: answers per name, optionally a different answer on each call (DNS rebinding), and logs the calls.
    ``answers[name]`` is a list of answers; each answer is a list of address texts, an exception to raise, or any other
    object returned as is. The last answer repeats."""

    def __init__(self, table: Optional[Dict[str, Sequence[Any]]] = None) -> None:
        self.table: Dict[str, List[Any]] = {k: list(v) for k, v in (table or {}).items()}
        self.calls: List[str] = []
        self._lock = threading.Lock()

    def set(self, name: str, *answers: Any) -> None:
        with self._lock:
            self.table[name] = list(answers)

    def resolve(self, host: str) -> Any:
        with self._lock:
            self.calls.append(host)
            try:
                answers = self.table[host]
            except KeyError:
                raise LookupError("unknown host") from None
            answer = answers.pop(0) if len(answers) > 1 else answers[0]
        if isinstance(answer, BaseException):
            raise answer
        return answer


@dataclass
class Reply:
    raw: bytes
    status: Optional[int]
    headers: Dict[str, str]
    body: bytes
    closed_by_peer: bool = True

    @property
    def text(self) -> str:
        return self.raw.decode("latin-1")

    @property
    def reason(self) -> str:
        return self.headers.get("x-egress-reason", "")

    @property
    def denied(self) -> bool:
        return self.status == 403 and self.headers.get("x-egress-decision") == "denied"


def parse_reply(raw: bytes) -> Reply:
    head, sep, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = None
    if lines and lines[0].startswith(b"HTTP/"):
        parts = lines[0].split(b" ")
        if len(parts) > 1 and parts[1].isdigit():
            status = int(parts[1])
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        headers.setdefault(name.decode("latin-1").strip().lower(), value.decode("latin-1").strip())
    return Reply(raw=raw, status=status, headers=headers, body=body)


def raw_request(port: int, data: bytes, *, timeout: float = 5.0, read_limit: int = 1 << 22, shutdown_write: bool = False) -> Reply:
    """Send bytes to the gateway on loopback and read until it closes (or the limit or timeout). Never raises on a reset."""
    chunks: List[bytes] = []
    total = 0
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendall(data)
            if shutdown_write:
                sock.shutdown(socket.SHUT_WR)
            while total < read_limit:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        except (ConnectionResetError, BrokenPipeError, socket.timeout):
            pass
    return parse_reply(b"".join(chunks))


def get(port: int, url: str, *, headers: Sequence[Tuple[str, str]] = (), method: str = "GET", body: bytes = b"", **kw: Any) -> Reply:
    lines = [f"{method} {url} HTTP/1.1"] + [f"{k}: {v}" for k, v in headers]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return raw_request(port, ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body, **kw)


# ----------------------------------------------------------------------------------------------------------------
# the fake upstream
# ----------------------------------------------------------------------------------------------------------------

@dataclass
class Seen:
    request_line: str
    headers: Dict[str, str]
    raw_head: bytes
    body: bytes


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: "Upstream" = self.server            # type: ignore[assignment]
        self.request.settimeout(5)
        buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                buf += chunk
        except OSError:
            return
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(b":")
            headers[name.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()
        want = int(headers.get("content-length", "0") or 0)
        body = rest
        try:
            while len(body) < want:
                chunk = self.request.recv(65536)
                if not chunk:
                    break
                body += chunk
        except OSError:
            pass
        seen = Seen(lines[0].decode("latin-1"), headers, head, body)
        with server.lock:
            server.seen.append(seen)
        path = lines[0].split(b" ")[1].decode("latin-1") if len(lines[0].split(b" ")) > 1 else "/"
        route = server.routes.get(path.split("?")[0], server.default)
        try:
            route(self.request, seen)
        except OSError:
            pass


class Upstream(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.lock = threading.Lock()
        self.seen: List[Seen] = []
        self.routes: Dict[str, Callable[[socket.socket, Seen], None]] = {}
        self.default: Callable[[socket.socket, Seen], None] = ok("hello")
        self.thread = threading.Thread(target=lambda: self.serve_forever(0.02), daemon=True)

    @property
    def port(self) -> int:
        return self.server_address[1]

    def paths(self) -> List[str]:
        with self.lock:
            return [s.request_line.split(" ")[1] for s in self.seen if len(s.request_line.split(" ")) > 1]

    def __enter__(self) -> "Upstream":
        self.thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)


def ok(body: str = "hello", status: str = "200 OK", extra: Sequence[str] = ()) -> Callable[[socket.socket, Seen], None]:
    data = body.encode()

    def route(sock: socket.socket, seen: Seen) -> None:
        head = [f"HTTP/1.1 {status}", f"Content-Length: {len(data)}", "Connection: close", *extra]
        sock.sendall(("\r\n".join(head) + "\r\n\r\n").encode() + data)
    return route


def raw_response(data: bytes) -> Callable[[socket.socket, Seen], None]:
    def route(sock: socket.socket, seen: Seen) -> None:
        sock.sendall(data)
    return route


def redirect(location: str, code: int = 302) -> Callable[[socket.socket, Seen], None]:
    return raw_response(f"HTTP/1.1 {code} Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("latin-1"))


def echo_headers(sock: socket.socket, seen: Seen) -> None:
    body = seen.raw_head
    sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)


def stream(total: int, with_length: bool, chunk: int = 8192) -> Callable[[socket.socket, Seen], None]:
    def route(sock: socket.socket, seen: Seen) -> None:
        head = "HTTP/1.1 200 OK\r\nConnection: close\r\n" + (f"Content-Length: {total}\r\n" if with_length else "") + "\r\n"
        sock.sendall(head.encode())
        sent = 0
        piece = b"x" * chunk
        while sent < total:
            n = min(chunk, total - sent)
            try:
                sock.sendall(piece[:n])
            except OSError:
                return
            sent += n
    return route


def stall(seconds: float) -> Callable[[socket.socket, Seen], None]:
    def route(sock: socket.socket, seen: Seen) -> None:
        time.sleep(seconds)
    return route


def websocket_echo(sock: socket.socket, seen: Seen) -> None:
    sock.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n")
    sock.settimeout(3)
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                return
            sock.sendall(data)
    except OSError:
        return


class _RawHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: "RawUpstream" = self.server            # type: ignore[assignment]
        with server.lock:
            server.connections += 1
        self.request.settimeout(5)
        try:
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                with server.lock:
                    server.received += len(data)
                if server.mode == "echo":
                    self.request.sendall(data)
        except OSError:
            return


class RawUpstream(socketserver.ThreadingTCPServer):
    """A byte-level upstream for tunnels: ``echo`` sends back what it receives, ``silent`` only reads."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, mode: str = "echo") -> None:
        super().__init__(("127.0.0.1", 0), _RawHandler)
        self.mode = mode
        self.lock = threading.Lock()
        self.connections = 0
        self.received = 0
        self.thread = threading.Thread(target=lambda: self.serve_forever(0.02), daemon=True)

    @property
    def port(self) -> int:
        return self.server_address[1]

    def __enter__(self) -> "RawUpstream":
        self.thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)


# ----------------------------------------------------------------------------------------------------------------
# a gateway for the tests
# ----------------------------------------------------------------------------------------------------------------

def private_entry(host: str, port: int, *, schemes: Sequence[str] = ("http", "ws"), net: str = "127.0.0.1/32") -> AllowEntry:
    return AllowEntry(host=host, networks=(net,), schemes=tuple(schemes), ports=(port,), private_ok=True)


def make_gateway(upstream_port: int, resolver: Optional[ScriptedResolver] = None, *, names: Sequence[str] = ("app.test",),
                 limits: Optional[GatewayLimits] = None, policy: Optional[EgressPolicy] = None,
                 gateway_class: type = EgressGateway, **kwargs: Any) -> Tuple[GatewayServer, ScriptedResolver]:
    resolver = resolver or ScriptedResolver({name: [["127.0.0.1"]] for name in names})
    if policy is None:
        policy = EgressPolicy(entries=tuple(private_entry(n, upstream_port) for n in names))
    server = GatewayServer(policy, resolver, gateway_class=gateway_class, limits=limits or GatewayLimits(
        read_timeout_s=2.0, connect_timeout_s=2.0, dns_timeout_s=2.0, upstream_header_timeout_s=3.0, idle_timeout_s=3.0,
        total_timeout_s=8.0, tunnel_total_timeout_s=8.0), **kwargs)
    return server, resolver


# ----------------------------------------------------------------------------------------------------------------
# the connection seam: only loopback sockets are ever opened, whatever address a decision pinned
# ----------------------------------------------------------------------------------------------------------------

class SpyOpener:
    """Stands in for the gateway's connector. It records every ``(address, port)`` the gateway asked to connect to and maps a
    (fake, usually private) address to a loopback port; an address with no mapping is refused without any socket. The peer it
    reports is the address it was asked for, unless ``claim`` says otherwise (to simulate a connection that went elsewhere)."""

    def __init__(self, table: Dict[str, int], claim: Optional[str] = None, delay: float = 0.0) -> None:
        self.table, self.claim, self.delay = dict(table), claim, delay
        self.calls: List[Tuple[str, int]] = []

    async def __call__(self, address: str, port: int):
        import asyncio
        self.calls.append((address, port))
        if self.delay:
            await asyncio.sleep(self.delay)
        target = self.table.get(address)
        if target is None:
            raise ConnectionRefusedError("no mapping for this address in the test")
        reader, writer = await asyncio.open_connection("127.0.0.1", target)
        return reader, writer, self.claim if self.claim is not None else address
