# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The egress gateway: a forward proxy on asyncio (standard library only) that every browser request goes through.

It is the **enforcement point** for the harness egress policy, which only decides. For each request or connection the gateway
asks the policy (through a :class:`~qa_egress.decider.Decider`, by default the harness ``EgressGuard`` with an injected
resolver), refuses what is not allowed, and otherwise connects **only to the address the decision pinned**: there is no
second name resolution anywhere. Then it checks that the connection really reached that address.

What it handles
  * ``http://`` requests in absolute form, one request per connection (``Connection: close`` both ways), hop-by-hop headers
    removed, ``Host`` taken from the decided URL;
  * ``CONNECT host:port`` for ``https`` (and ``wss``): judged as an ``https`` target, then an opaque byte tunnel;
  * a WebSocket upgrade in absolute form (``ws://`` or ``http://`` with ``Upgrade: websocket``), judged as ``ws``;
  * every redirect answer: the ``Location`` is decided again from scratch (relative forms resolved, downgrade and the redirect
    count enforced) *before* the answer reaches the client, and a refused hop is answered ``403``.
Everything else is refused: other methods, origin-form requests, ``https://`` in a plain request, request bodies with a
transfer coding, malformed or oversized heads, extra bytes after a request.

What it will not do whatever a decider says (``_enforce``, ``_assert_connectable``): connect to a metadata or link-local
address, to the unspecified address, a multicast address or an IPv4-mapped or transition address.

Bounds: head size and lines, URI length, request body, response bytes, tunnel bytes, concurrent connections, and a timeout for
the head, the connection, name resolution, the upstream answer, idleness and the whole request.

Nothing from a request (path, query, header, body, cookie) is ever written into a record, an event, a counter or a log line;
the decision holds scheme, host, port, the addresses and reason codes only, and a log line passes the harness redactor first.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Set, Tuple

from ._harness import (AddressClass, Clock, EgressDecision, EgressPolicy, EgressVerdict, PatternRedactor, Reason, Redactor,
                       Refused, Resolver, SystemClock, classify_address, is_metadata_address, parse_target, egress)
from .decider import Decider, GuardDecider
from .limits import GatewayLimits
from .records import GatewayRecord, Ledger

Opener = Callable[[str, int], Awaitable[Tuple[asyncio.StreamReader, asyncio.StreamWriter, str]]]

TOKEN = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
ALLOWED_METHODS = (b"GET", b"HEAD", b"POST", b"PUT", b"PATCH", b"DELETE", b"OPTIONS")
REDIRECT_CODES = (301, 302, 303, 307, 308)
HOP_BY_HOP = frozenset({"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te",
                        "trailer", "transfer-encoding", "upgrade", "expect"})
#: never connected to, whatever the policy or a decider said
NEVER_CONNECT = frozenset({AddressClass.METADATA, AddressClass.LINK_LOCAL, AddressClass.UNSPECIFIED, AddressClass.MULTICAST,
                           AddressClass.MAPPED, AddressClass.TRANSITION})
_REASON_TEXT = re.compile(r"[ -~]{1,64}")
_DIGITS = re.compile(r"[0-9]{1,10}")
_STATUS = {200: "OK", 400: "Bad Request", 403: "Forbidden", 405: "Method Not Allowed", 408: "Request Timeout",
           413: "Payload Too Large", 414: "URI Too Long", 431: "Request Header Fields Too Large", 501: "Not Implemented",
           502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout", 505: "HTTP Version Not Supported"}


class Refusal(Exception):
    """Ends a request with an answer of the gateway's own. ``code`` is a short constant (never request content)."""

    def __init__(self, status: int, code: str, *, limit: Optional[str] = None, outcome: str = "refused",
                 decision: Optional[EgressDecision] = None, denied: bool = False) -> None:
        super().__init__(code)
        self.status, self.code, self.limit, self.outcome, self.decision, self.denied = status, code, limit, outcome, decision, denied


class _Done(Exception):
    """The peer went away before there was anything to answer."""


@dataclass
class _Request:
    method: str
    target: str
    version: str
    headers: List[Tuple[str, str, str]]          # (lower name, name as sent, value)
    prefix: bytes                                 # bytes that arrived after the head

    def values(self, name: str) -> List[str]:
        return [v for lower, _, v in self.headers if lower == name]


class _State:
    def __init__(self, started_ms: int) -> None:
        self.started_ms = started_ms
        self.kind = "malformed"
        self.outcome = "aborted"
        self.status: Optional[int] = None
        self.bytes_up = 0
        self.bytes_down = 0
        self.decision: Optional[EgressDecision] = None
        self.redirect_decision: Optional[EgressDecision] = None
        self.limit: Optional[str] = None
        self.reason: Optional[str] = None


class _Redirects:
    """The redirects the gateway let through, so the length of a chain can be counted across the requests a browser makes."""

    def __init__(self, size: int, ttl_s: float) -> None:
        self._items: "OrderedDict[Tuple[str, str], Tuple[int, str, float]]" = OrderedDict()
        self._size, self._ttl = size, ttl_s

    def put(self, client: str, key: str, hop: int, scheme: str, now: float) -> None:
        self._items[(client, key)] = (hop, scheme, now + self._ttl)
        while len(self._items) > self._size:
            self._items.popitem(last=False)

    def take(self, client: str, key: str, now: float) -> Optional[Tuple[int, str]]:
        found = self._items.pop((client, key), None)
        if found is None or found[2] < now:
            return None
        return found[0], found[1]


def url_key(url: str) -> str:
    """A comparable form of an absolute URL: scheme, normalised host, port, path and query (no fragment)."""
    target = parse_target(url)
    rest = url[url.index("//") + 2:]
    end = next((i for i, ch in enumerate(rest) if ch in "/?#"), len(rest))
    tail = rest[end:].split("#", 1)[0]
    if not tail.startswith("/"):
        tail = "/" + tail
    return f"{target.origin}{tail}"


def _tail(url: str) -> str:
    """The origin-form request target (path and query) of an absolute URL."""
    rest = url[url.index("//") + 2:]
    end = next((i for i, ch in enumerate(rest) if ch in "/?#"), len(rest))
    tail = rest[end:].split("#", 1)[0]
    return tail if tail.startswith("/") else "/" + tail


async def _default_opener(address: str, port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
    reader, writer = await asyncio.open_connection(address, port)
    peer = writer.get_extra_info("peername")
    return reader, writer, str(peer[0]) if peer else ""


class EgressGateway:
    def __init__(self, policy: EgressPolicy, resolver: Resolver, *, limits: Optional[GatewayLimits] = None,
                 clock: Optional[Clock] = None, redactor: Optional[Redactor] = None, host: str = "127.0.0.1", port: int = 0,
                 opener: Optional[Opener] = None, decider: Optional[Decider] = None,
                 log: Optional[Callable[[str], None]] = None) -> None:
        self.limits = limits if limits is not None else GatewayLimits()
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._decider: Decider = decider if decider is not None else GuardDecider(policy, resolver, self.limits)
        self._policy_id = policy.policy_id
        self._host, self._port = host, port
        self._opener: Opener = opener if opener is not None else _default_opener
        self._redactor: Redactor = redactor if redactor is not None else PatternRedactor()
        self._log_fn = log
        self.ledger = Ledger(self.limits.max_records, self.limits.max_denied_hosts, self._policy_id)
        self._redirects = _Redirects(self.limits.redirect_memory, self.limits.redirect_ttl_s)
        self._server: Optional[asyncio.AbstractServer] = None
        self._tasks: Set[asyncio.Task] = set()
        self._writers: Set[asyncio.StreamWriter] = set()
        self._active = 0

    # ---------------------------------------------------------------------------------------------------------------
    # lifecycle
    # ---------------------------------------------------------------------------------------------------------------
    async def start(self) -> None:
        self._server = await asyncio.start_server(self._on_client, self._host, self._port, limit=1 << 16)
        self._port = self._server.sockets[0].getsockname()[1]

    @property
    def port(self) -> int:
        return self._port

    @property
    def active_connections(self) -> int:
        return self._active

    async def stop(self) -> None:
        """Stop listening, cancel every connection in flight, close every socket this gateway opened."""
        if self._server is not None:
            self._server.close()
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        for writer in list(self._writers):
            self._close(writer)
        if self._server is not None:
            await self._server.wait_closed()
            self._server = None

    # ---------------------------------------------------------------------------------------------------------------
    # logging (a line passes the harness redactor first; a refusal to redact drops the line)
    # ---------------------------------------------------------------------------------------------------------------
    def _log(self, event: str, **fields: Any) -> None:
        if self._log_fn is None:
            return
        line = " ".join([event] + [f"{k}={v}" for k, v in sorted(fields.items())])
        try:
            out = self._redactor.redact(line.encode("utf-8", errors="replace"), "text/plain").decode("utf-8")
        except Exception:
            self.ledger.counts["log_dropped"] += 1
            return
        try:
            self._log_fn(out)
        except Exception:
            self.ledger.counts["log_dropped"] += 1

    # ---------------------------------------------------------------------------------------------------------------
    # plumbing
    # ---------------------------------------------------------------------------------------------------------------
    def _now_ms(self) -> int:
        return self._clock.monotonic_ms()

    def _track(self, writer: asyncio.StreamWriter) -> asyncio.StreamWriter:
        self._writers.add(writer)
        return writer

    def _close(self, writer: Optional[asyncio.StreamWriter]) -> None:
        if writer is None:
            return
        self._writers.discard(writer)
        try:
            writer.close()
        except Exception:
            pass

    async def _send(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        writer.write(data)
        await asyncio.wait_for(writer.drain(), self.limits.idle_timeout_s)

    async def _answer(self, writer: asyncio.StreamWriter, st: _State, refusal: Refusal) -> None:
        body = b"egress refused\n"
        lines = [f"HTTP/1.1 {refusal.status} {_STATUS.get(refusal.status, 'Error')}", "Connection: close",
                 "Content-Type: text/plain; charset=utf-8", f"Content-Length: {len(body)}",
                 f"X-Egress-Reason: {refusal.code}"]
        if refusal.denied:
            lines.append("X-Egress-Decision: denied")
        try:
            await self._send(writer, ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)
            st.status = refusal.status
        except Exception:
            pass

    # ---------------------------------------------------------------------------------------------------------------
    # the bounds, one method each
    # ---------------------------------------------------------------------------------------------------------------
    def _at_capacity(self) -> bool:
        return self._active >= self.limits.max_connections

    def _response_over_cap(self, size: int) -> bool:
        return size > self.limits.max_response_bytes

    def _tunnel_over_cap(self, size: int) -> bool:
        return size > self.limits.max_tunnel_bytes

    def _request_body_over_cap(self, size: int) -> bool:
        return size > self.limits.max_request_body_bytes

    # ---------------------------------------------------------------------------------------------------------------
    # one client connection
    # ---------------------------------------------------------------------------------------------------------------
    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self._tasks.add(task)
        self._track(writer)
        self.ledger.counts["connections"] += 1
        st = _State(self._now_ms())
        try:
            if self._at_capacity():
                st.kind, st.outcome, st.limit = "malformed", "limit", "connections"
                await self._answer(writer, st, Refusal(503, "OVER_CAPACITY", limit="connections", outcome="limit"))
                return
            self._active += 1
            try:
                await self._serve(reader, writer, st)
            finally:
                self._active -= 1
        except asyncio.CancelledError:
            st.outcome = "aborted"
            raise
        except Exception:
            st.outcome = "aborted"
            self._log("connection_error")
        finally:
            self._close(writer)
            if st.kind != "malformed" or st.status is not None or st.limit is not None or st.reason is not None:
                self._log("request", kind=st.kind, outcome=st.outcome, status=st.status, limit=st.limit, reason=st.reason,
                          host=st.decision.host if st.decision is not None else None,
                          verdict=st.decision.verdict.value if st.decision is not None else None)
                self.ledger.add(GatewayRecord(
                    seq=self.ledger.next_seq(), kind=st.kind, outcome=st.outcome, status=st.status, bytes_up=st.bytes_up,
                    bytes_down=st.bytes_down, duration_ms=max(0, self._now_ms() - st.started_ms), decision=st.decision,
                    redirect_decision=st.redirect_decision, limit=st.limit, reason=st.reason))
            self._tasks.discard(task)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, st: _State) -> None:
        try:
            req = await self._read_request(reader, st)
            if req.method == "CONNECT":
                st.kind = "connect"
                await self._connect_flow(req, reader, writer, st)
            else:
                st.kind = "http"
                async with asyncio.timeout(self.limits.total_timeout_s) as budget:
                    await self._http_flow(req, reader, writer, st, budget)
        except _Done:
            st.outcome = "aborted"
        except Refusal as refusal:
            st.outcome = refusal.outcome
            st.limit = refusal.limit
            st.reason = refusal.code
            if refusal.decision is not None:
                st.decision = refusal.decision
            await self._answer(writer, st, refusal)
        except TimeoutError:                       # the total budget of a plain request
            st.outcome, st.limit, st.reason = "limit", "total_timeout", "TOTAL_TIMEOUT"
            await self._answer(writer, st, Refusal(504, "TOTAL_TIMEOUT"))

    # ---------------------------------------------------------------------------------------------------------------
    # reading and parsing the request head
    # ---------------------------------------------------------------------------------------------------------------
    async def _read_request(self, reader: asyncio.StreamReader, st: _State) -> _Request:
        buf = bytearray()
        try:
            async with asyncio.timeout(self.limits.read_timeout_s):
                while True:
                    end = buf.find(b"\r\n\r\n")
                    if end >= 0:
                        break
                    if len(buf) > self.limits.max_header_bytes:
                        raise Refusal(431, "HEADER_TOO_LARGE", limit="header_bytes", outcome="limit")
                    chunk = await reader.read(4096)
                    if not chunk:
                        if buf:
                            raise Refusal(400, "TRUNCATED_HEAD")
                        raise _Done()
                    buf += chunk
        except TimeoutError:
            raise Refusal(408, "READ_TIMEOUT", limit="read_timeout", outcome="limit") from None
        if end > self.limits.max_header_bytes:
            raise Refusal(431, "HEADER_TOO_LARGE", limit="header_bytes", outcome="limit")
        st.bytes_up += len(buf)
        return self._parse(bytes(buf[:end]), bytes(buf[end + 4:]))

    def _parse(self, head: bytes, prefix: bytes) -> _Request:
        lines = head.split(b"\r\n")
        if any(b"\n" in line or b"\r" in line or b"\x00" in line for line in lines):
            raise Refusal(400, "MALFORMED_HEAD")
        first = lines[0].split(b" ")
        if len(first) != 3:
            raise Refusal(400, "MALFORMED_REQUEST_LINE")
        method, target, version = first
        if TOKEN.fullmatch(method) is None or method != method.upper():
            raise Refusal(400, "MALFORMED_METHOD")
        if len(target) > self.limits.max_uri_chars:
            raise Refusal(414, "URI_TOO_LONG", limit="uri", outcome="limit")
        if version not in (b"HTTP/1.1", b"HTTP/1.0"):
            raise Refusal(505, "VERSION_NOT_SUPPORTED")
        try:
            text = target.decode("ascii")
        except UnicodeDecodeError:
            raise Refusal(400, "NON_ASCII_TARGET") from None
        if len(lines) - 1 > self.limits.max_header_lines:
            raise Refusal(431, "TOO_MANY_HEADERS", limit="header_lines", outcome="limit")
        headers: List[Tuple[str, str, str]] = []
        for line in lines[1:]:
            if not line or line[:1] in (b" ", b"\t"):
                raise Refusal(400, "MALFORMED_HEADER")
            name, sep, value = line.partition(b":")
            if not sep or TOKEN.fullmatch(name) is None:
                raise Refusal(400, "MALFORMED_HEADER")
            value = value.strip(b" \t")
            if any((c < 0x20 and c != 0x09) or c == 0x7F for c in value):
                raise Refusal(400, "MALFORMED_HEADER")
            headers.append((name.decode("ascii").lower(), name.decode("ascii"), value.decode("latin-1")))
        return _Request(method=method.decode("ascii"), target=text, version=version.decode("ascii"), headers=headers,
                        prefix=prefix)

    # ---------------------------------------------------------------------------------------------------------------
    # decisions and what is refused whatever they say
    # ---------------------------------------------------------------------------------------------------------------
    @staticmethod
    def _denial(source: EgressDecision, reason: Reason) -> EgressDecision:
        return EgressDecision(verdict=EgressVerdict.DENY, reasons=(reason.value,), purpose=source.purpose, hop=source.hop,
                              policy_id=source.policy_id, scheme=source.scheme, host=source.host, port=source.port,
                              host_kind=source.host_kind, addresses=source.addresses,
                              address_classes=source.address_classes, resolved=True, odd_form=source.odd_form)

    def _enforce(self, decision: EgressDecision) -> EgressDecision:
        """What the gateway adds to a decision: only refusals. A metadata or link-local address among the addresses, or no
        pinned address to connect to, turns an ALLOW into a DENY; nothing ever turns a DENY into an ALLOW."""
        if not decision.allowed:
            return decision
        for text in decision.addresses:
            try:
                if is_metadata_address(ipaddress.ip_address(text)):
                    return self._denial(decision, Reason.DENY_METADATA_ADDRESS)
            except ValueError:
                return self._denial(decision, Reason.DENY_RESOLVER_BAD_ANSWER)
        if decision.pinned_address is None or decision.port is None or decision.host is None:
            return self._denial(decision, Reason.DENY_NO_ADDRESSES)
        return decision

    @staticmethod
    def _assert_connectable(address: str) -> None:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            raise Refusal(403, Reason.DENY_RESOLVER_BAD_ANSWER.value, denied=True) from None
        cls = classify_address(parsed)
        if cls in (AddressClass.METADATA, AddressClass.LINK_LOCAL):
            raise Refusal(403, Reason.DENY_METADATA_ADDRESS.value, denied=True)
        if cls in NEVER_CONNECT:
            raise Refusal(403, Reason.DENY_ADDRESS_NOT_PUBLIC.value, denied=True)

    def _deny_refusal(self, decision: EgressDecision) -> Refusal:
        return Refusal(403, decision.reasons[0] if decision.reasons else "DENIED", outcome="denied", decision=decision, denied=True)

    async def _connect(self, decision: EgressDecision) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to the pinned address and nowhere else, then check the peer is that address."""
        try:
            address, port, _name = decision.connect_target()
        except PermissionError:
            raise self._deny_refusal(self._denial(decision, Reason.DENY_NO_ADDRESSES)) from None
        self._assert_connectable(address)
        try:
            reader, writer, peer = await asyncio.wait_for(self._opener(address, port), self.limits.connect_timeout_s)
        except asyncio.TimeoutError:
            raise Refusal(504, "CONNECT_TIMEOUT", limit="connect_timeout", outcome="limit", decision=decision) from None
        except OSError:
            raise Refusal(502, "CONNECT_FAILED", outcome="upstream_error", decision=decision) from None
        self._track(writer)
        if not decision.permits_peer(peer):                        # the connection did not go where the decision pinned it
            self._close(writer)
            raise self._deny_refusal(self._denial(decision, Reason.DENY_PEER_MISMATCH))
        return reader, writer

    # ---------------------------------------------------------------------------------------------------------------
    # plain HTTP (and WebSocket upgrade)
    # ---------------------------------------------------------------------------------------------------------------
    @staticmethod
    def _content_length(req: _Request) -> int:
        values = {v.strip() for v in req.values("content-length")}
        if not values:
            return 0
        if len(values) != 1:
            raise Refusal(400, "CONFLICTING_CONTENT_LENGTH")
        (value,) = values
        if _DIGITS.fullmatch(value) is None:
            raise Refusal(400, "BAD_CONTENT_LENGTH")
        return int(value)

    @staticmethod
    def _connection_tokens(headers: Sequence[Tuple[str, str, str]]) -> Set[str]:
        return {t.strip().lower() for lower, _, v in headers if lower == "connection" for t in v.split(",") if t.strip()}

    async def _http_flow(self, req: _Request, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, st: _State,
                         budget: Any) -> None:
        if req.method.encode() not in ALLOWED_METHODS:
            raise Refusal(405, "METHOD_NOT_ALLOWED")
        if req.target.startswith("/") or req.target == "*":
            raise Refusal(400, "NOT_A_PROXY_REQUEST")
        if req.values("transfer-encoding"):
            raise Refusal(501, "TRANSFER_CODING_UNSUPPORTED")
        length = self._content_length(req)
        if self._request_body_over_cap(length):
            raise Refusal(413, "REQUEST_TOO_LARGE", limit="request_body", outcome="limit")
        upgrade = [v.strip().lower() for v in req.values("upgrade")]
        websocket = False
        if upgrade:
            if upgrade != ["websocket"] or "upgrade" not in self._connection_tokens(req.headers) or req.method != "GET":
                raise Refusal(400, "UPGRADE_UNSUPPORTED")
            websocket = True
            st.kind = "upgrade"
        judged = req.target
        if websocket and judged[:5].lower() == "http:":
            judged = "ws:" + judged[5:]
        now = asyncio.get_running_loop().time()
        hop, previous_scheme = 0, None
        try:
            memory = self._redirects.take(self._peer(writer), url_key(judged), now)
        except Refused:
            memory = None
        if memory is not None:
            hop, previous_scheme = memory
        decision = self._enforce(await self._decider.decide_url(
            judged, purpose="redirect" if hop else ("upgrade" if websocket else "proxy-request"), hop=hop,
            previous_scheme=previous_scheme))
        st.decision = decision
        if not decision.allowed:
            raise self._deny_refusal(decision)
        if decision.scheme in ("https", "wss") or (decision.scheme == "ws" and not websocket):
            raise Refusal(400, "USE_CONNECT" if decision.scheme in ("https", "wss") else "UPGRADE_REQUIRED", decision=decision)
        if len(req.prefix) > length:
            raise Refusal(400, "PIPELINING_UNSUPPORTED", decision=decision)

        up_reader, up_writer = await self._connect(decision)
        try:
            await self._forward(req, reader, up_writer, decision, length, websocket, st)
            await self._relay_response(req, writer, up_reader, up_writer, reader, decision, websocket, st, budget, judged, hop)
        finally:
            self._close(up_writer)

    @staticmethod
    def _peer(writer: asyncio.StreamWriter) -> str:
        peer = writer.get_extra_info("peername")
        return str(peer[0]) if peer else ""

    async def _forward(self, req: _Request, reader: asyncio.StreamReader, up: asyncio.StreamWriter, decision: EgressDecision,
                       length: int, websocket: bool, st: _State) -> None:
        default = {"http": 80, "ws": 80, "https": 443, "wss": 443}[decision.scheme]
        shown = f"[{decision.host}]" if decision.host_kind == "IPV6" else decision.host
        host_header = shown if decision.port == default else f"{shown}:{decision.port}"
        connection_named = self._connection_tokens(req.headers)
        lines = [f"{req.method} {_tail(req.target)} HTTP/1.1", f"Host: {host_header}"]
        for lower, name, value in req.headers:
            if lower == "host" or lower in HOP_BY_HOP or lower.startswith("proxy-") or lower in connection_named \
                    or lower == "content-length":
                continue
            lines.append(f"{name}: {value}")
        if length or req.method in ("POST", "PUT", "PATCH"):
            lines.append(f"Content-Length: {length}")
        lines += ["Connection: Upgrade", "Upgrade: websocket"] if websocket else ["Connection: close"]
        await self._send(up, ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", errors="replace") + req.prefix[:length])
        remaining = length - len(req.prefix)
        while remaining > 0:
            try:
                chunk = await asyncio.wait_for(reader.read(min(65536, remaining)), self.limits.idle_timeout_s)
            except asyncio.TimeoutError:
                raise Refusal(408, "IDLE_TIMEOUT", limit="idle_timeout", outcome="limit", decision=decision) from None
            if not chunk:
                raise _Done()
            st.bytes_up += len(chunk)
            remaining -= len(chunk)
            await self._send(up, chunk)

    async def _read_upstream_head(self, up_reader: asyncio.StreamReader, decision: EgressDecision) -> Tuple[bytes, bytes]:
        buf = bytearray()
        try:
            async with asyncio.timeout(self.limits.upstream_header_timeout_s):
                while True:
                    end = buf.find(b"\r\n\r\n")
                    if end >= 0:
                        break
                    if len(buf) > self.limits.max_response_header_bytes:
                        raise Refusal(502, "UPSTREAM_HEADER_TOO_LARGE", limit="response_header_bytes", outcome="limit",
                                      decision=decision)
                    chunk = await up_reader.read(4096)
                    if not chunk:
                        raise Refusal(502, "UPSTREAM_CLOSED", outcome="upstream_error", decision=decision)
                    buf += chunk
        except TimeoutError:
            raise Refusal(504, "UPSTREAM_TIMEOUT", limit="upstream_timeout", outcome="limit", decision=decision) from None
        if end > self.limits.max_response_header_bytes:
            raise Refusal(502, "UPSTREAM_HEADER_TOO_LARGE", limit="response_header_bytes", outcome="limit", decision=decision)
        return bytes(buf[:end]), bytes(buf[end + 4:])

    def _parse_response(self, head: bytes, decision: EgressDecision) -> Tuple[int, str, List[Tuple[str, str, str]]]:
        lines = head.split(b"\r\n")
        bad = Refusal(502, "UPSTREAM_MALFORMED", outcome="upstream_error", decision=decision)
        if any(b"\n" in line or b"\r" in line or b"\x00" in line for line in lines):
            raise bad
        parts = lines[0].split(b" ", 2)
        if len(parts) < 2 or parts[0] not in (b"HTTP/1.1", b"HTTP/1.0") or not re.fullmatch(rb"[0-9]{3}", parts[1]):
            raise bad
        code = int(parts[1])
        if code < 200 and code != 101:
            raise bad
        reason = parts[2].decode("latin-1") if len(parts) == 3 else ""
        reason = reason if _REASON_TEXT.fullmatch(reason) else _STATUS.get(code, "Status")
        headers: List[Tuple[str, str, str]] = []
        if len(lines) - 1 > self.limits.max_header_lines:
            raise Refusal(502, "UPSTREAM_TOO_MANY_HEADERS", limit="response_header_bytes", outcome="limit", decision=decision)
        for line in lines[1:]:
            name, sep, value = line.partition(b":")
            if not sep or TOKEN.fullmatch(name) is None or any((c < 0x20 and c != 0x09) or c == 0x7F for c in value):
                raise bad
            headers.append((name.decode("ascii").lower(), name.decode("ascii"), value.strip(b" \t").decode("latin-1")))
        return code, reason, headers

    async def _check_redirect(self, code: int, headers: List[Tuple[str, str, str]], judged: str, decision: EgressDecision,
                              hop: int, writer: asyncio.StreamWriter, st: _State) -> None:
        """A redirect answer: its target is decided again from scratch before the client ever sees the answer. A refused hop
        is answered 403 here and the redirect is never relayed; an allowed one is remembered, to count the chain."""
        if code not in REDIRECT_CODES:
            return
        locations = [v for lower, _, v in headers if lower == "location"]
        if not locations:
            return
        if len(locations) != 1 or not locations[0]:
            st.redirect_decision = self._denial(decision, Reason.DENY_REDIRECT_LOCATION)
            raise Refusal(403, Reason.DENY_REDIRECT_LOCATION.value, outcome="refused", denied=True)
        follow = self._enforce(await self._decider.decide_redirect(judged, locations[0], hop=hop + 1, previous=decision))
        st.redirect_decision = follow
        if not follow.allowed:
            raise Refusal(403, follow.reasons[0] if follow.reasons else "DENIED", outcome="refused", denied=True)
        try:
            absolute = egress.resolve_location(judged, locations[0])
            self._redirects.put(self._peer(writer), url_key(absolute), hop + 1, decision.scheme,
                                asyncio.get_running_loop().time())
        except Refused:
            pass

    async def _relay_response(self, req: _Request, writer: asyncio.StreamWriter, up_reader: asyncio.StreamReader,
                              up_writer: asyncio.StreamWriter, reader: asyncio.StreamReader, decision: EgressDecision,
                              websocket: bool, st: _State, budget: Any, judged: str, hop: int) -> None:
        head, rest = await self._read_upstream_head(up_reader, decision)
        code, reason, headers = self._parse_response(head, decision)
        st.bytes_down += len(head) + 4
        await self._check_redirect(code, headers, judged, decision, hop, writer, st)
        named = {t for lower, _, v in headers if lower == "connection" for t in (x.strip().lower() for x in v.split(","))}
        lengths = {v.strip() for lower, _, v in headers if lower == "content-length"}
        if len(lengths) > 1 or any(_DIGITS.fullmatch(v) is None for v in lengths):
            raise Refusal(502, "UPSTREAM_BAD_CONTENT_LENGTH", outcome="upstream_error", decision=decision)
        if lengths and self._response_over_cap(int(next(iter(lengths)))) and not websocket:
            raise Refusal(502, "RESPONSE_TOO_LARGE", limit="response_bytes", outcome="limit", decision=decision)
        out = [f"HTTP/1.1 {code} {reason}"]
        for lower, name, value in headers:
            if lower in HOP_BY_HOP - {"transfer-encoding"} or lower.startswith("proxy-") or lower in named:
                continue
            out.append(f"{name}: {value}")
        upgraded = code == 101 and websocket
        out += ["Connection: Upgrade", "Upgrade: websocket"] if upgraded else ["Connection: close"]
        await self._send(writer, ("\r\n".join(out) + "\r\n\r\n").encode("latin-1", errors="replace"))
        st.status = code
        if upgraded:
            budget.reschedule(asyncio.get_running_loop().time() + self.limits.tunnel_total_timeout_s)
            st.outcome = "tunnelled"
            await self._pipe(st, reader, writer, up_reader, up_writer, early=b"", rest=rest)
            return
        # the body: raw bytes (any chunk framing included) until the upstream closes, counted against the bound
        sent = len(rest)
        if rest:
            if self._response_over_cap(sent):
                st.outcome, st.limit = "limit", "response_bytes"
                return
            await self._send(writer, rest)
            st.bytes_down += sent
        st.outcome = "relayed"
        if req.method == "HEAD" or code in (204, 304):
            return
        while True:
            try:
                chunk = await asyncio.wait_for(up_reader.read(65536), self.limits.idle_timeout_s)
            except asyncio.TimeoutError:
                st.outcome, st.limit = "limit", "idle_timeout"
                return
            if not chunk:
                return
            sent += len(chunk)
            if self._response_over_cap(sent):
                st.outcome, st.limit = "limit", "response_bytes"           # the answer is cut here; the connection ends
                return
            st.bytes_down += len(chunk)
            await self._send(writer, chunk)

    # ---------------------------------------------------------------------------------------------------------------
    # CONNECT
    # ---------------------------------------------------------------------------------------------------------------
    @staticmethod
    def _authority(target: str) -> Tuple[str, int]:
        if target.startswith("["):
            close = target.find("]")
            if close == -1 or target[close + 1:close + 2] != ":":
                raise Refusal(400, "BAD_AUTHORITY")
            host, port_text = target[1:close], target[close + 2:]
        else:
            host, sep, port_text = target.rpartition(":")
            if not sep or ":" in host:
                raise Refusal(400, "BAD_AUTHORITY")
        if not host or _DIGITS.fullmatch(port_text) is None:
            raise Refusal(400, "BAD_AUTHORITY")
        return host, int(port_text)

    async def _connect_flow(self, req: _Request, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, st: _State) -> None:
        host, port = self._authority(req.target)
        decision = self._enforce(await self._decider.decide_connect(host, port))
        st.decision = decision
        if not decision.allowed:
            raise self._deny_refusal(decision)
        up_reader, up_writer = await self._connect(decision)
        try:
            await self._send(writer, b"HTTP/1.1 200 Connection Established\r\n\r\n")
            st.status = 200
            st.outcome = "tunnelled"
            await self._pipe(st, reader, writer, up_reader, up_writer, early=req.prefix, rest=b"")
        finally:
            self._close(up_writer)

    async def _pipe(self, st: _State, c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter,
                    u_reader: asyncio.StreamReader, u_writer: asyncio.StreamWriter, *, early: bytes, rest: bytes) -> None:
        """Copy both ways under the byte, idle and total bounds; end when either side ends or a bound is hit."""
        moved = {"up": 0, "down": 0}

        async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter, way: str, first: bytes) -> None:
            data = first
            while True:
                if data:
                    moved[way] += len(data)
                    if self._tunnel_over_cap(moved["up"] + moved["down"]):
                        raise Refusal(502, "TUNNEL_TOO_LARGE", limit="tunnel_bytes", outcome="limit")
                    dst.write(data)
                    await asyncio.wait_for(dst.drain(), self.limits.idle_timeout_s)
                try:
                    data = await asyncio.wait_for(src.read(65536), self.limits.idle_timeout_s)
                except asyncio.TimeoutError:
                    raise Refusal(504, "IDLE_TIMEOUT", limit="idle_timeout", outcome="limit") from None
                if not data:
                    return

        tasks = [asyncio.ensure_future(copy(c_reader, u_writer, "up", early)),
                 asyncio.ensure_future(copy(u_reader, c_writer, "down", rest))]
        try:
            done, pending = await asyncio.wait(tasks, timeout=self.limits.tunnel_total_timeout_s,
                                               return_when=asyncio.FIRST_COMPLETED)
            if not done:
                st.outcome, st.limit = "limit", "total_timeout"
            for task in pending:               # a tunnel does not outlive one of its sides
                task.cancel()
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            st.bytes_up += moved["up"]
            st.bytes_down += moved["down"]
        for task in tasks:
            if task.done() and not task.cancelled() and task.exception() is not None:
                exc = task.exception()
                if isinstance(exc, Refusal):
                    st.outcome, st.limit = exc.outcome, exc.limit
                else:
                    st.outcome = "aborted"
