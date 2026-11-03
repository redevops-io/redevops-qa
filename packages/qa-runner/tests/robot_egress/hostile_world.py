# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The hostile LOOPBACK world of the Robot egress experiments: listeners that count what reaches them (the count the experiments read), a resolver that answers every name with
127.0.0.1, and an 'allowed origin' that answers /ok and redirects /redirect. Everything binds to the loopback interface of this machine and nothing here connects anywhere else."""
from __future__ import annotations

import http.server
import os
import socket
import struct
import threading
import urllib.parse
from typing import Dict, List, Optional


class _Listener:
    def __init__(self, kind: int, host: str, port: int = 0, stream: bool = True, quick: bool = False):
        self.quick = quick
        self.sock = socket.socket(kind, socket.SOCK_STREAM if stream else socket.SOCK_DGRAM)
        self.sock.bind((host, port) if kind != socket.AF_UNIX else host)
        if stream:
            self.sock.listen(512)
        self.sock.settimeout(0.1)
        self.hits: List[bytes] = []
        self.stream = stream
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return self.sock.getsockname()[1]

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self.stream:
                    conn, _ = self.sock.accept()
                    conn.settimeout(0.05)
                    try:
                        self.hits.append(b"" if self.quick else conn.recv(64))
                    except OSError:
                        self.hits.append(b"")
                    conn.close()
                else:
                    data, _ = self.sock.recvfrom(512)
                    self.hits.append(data)
            except (socket.timeout, BlockingIOError):
                continue
            except OSError:
                return

    def close(self) -> None:
        self._stop.set()
        self.thread.join(timeout=2)
        self.sock.close()


class _Resolver(_Listener):
    """A UDP resolver that answers any A query with 127.0.0.1 (the 'name that resolves to a forbidden address')."""

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(512)
            except (socket.timeout, BlockingIOError):
                continue
            except OSError:
                return
            self.hits.append(data)
            reply = data[:2] + b"\x81\x80" + data[4:6] + b"\x00\x01\x00\x00\x00\x00" + data[12:] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton("127.0.0.1")
            try:
                self.sock.sendto(reply, peer)
            except OSError:
                pass


class _Origin(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256

    def __init__(self):
        self.requests: List[str] = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                owner.requests.append(self.path)
                parts = urllib.parse.urlsplit(self.path)
                if parts.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", urllib.parse.parse_qs(parts.query)["to"][0])
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        super().__init__(("127.0.0.1", 0), Handler)


class World:
    """Every listener the experiments use. ``ports`` is what the hostile library is told (``world.json``)."""

    TCP = ("direct", "ip_literal_http", "dns_rebind_target", "resolver_tcp", "redirect", "subprocess_curl", "subprocess_python", "subprocess_bash", "ctypes_connect", "raw_syscall", "thread",
           "import_time", "proxy_env", "fast_open", "fast_open_sendmsg", "race")

    def __init__(self, tmp: str):
        self.tmp = tmp
        self.tcp: Dict[str, _Listener] = {name: _Listener(socket.AF_INET, "127.0.0.1", quick=(name == "race")) for name in self.TCP}
        self.udp = _Listener(socket.AF_INET, "127.0.0.1", stream=False)
        self.resolver = _Resolver(socket.AF_INET, "127.0.0.1", stream=False)
        self.udp6 = _Listener(socket.AF_INET6, "::1", stream=False)
        self.ipv6 = _Listener(socket.AF_INET6, "::1")                    # a machine without IPv6 loopback fails here, loudly: the experiment is not silently dropped
        self.unix_stream_path = os.path.join(tmp, "hostile-stream.sock")
        self.unix_dgram_path = os.path.join(tmp, "hostile-dgram.sock")
        self.unix_stream = _Listener(socket.AF_UNIX, self.unix_stream_path)
        self.unix_dgram = _Listener(socket.AF_UNIX, self.unix_dgram_path, stream=False)
        self.unix_dgram_pair_path = os.path.join(tmp, "hostile-dgram-pair.sock")
        self.unix_dgram_pair = _Listener(socket.AF_UNIX, self.unix_dgram_pair_path, stream=False)
        self.origin = _Origin()
        self.origin_thread = threading.Thread(target=self.origin.serve_forever, daemon=True)
        self.origin_thread.start()
        self.allowed_port = self.origin.server_address[1]
        self.shadow: Optional[_Listener] = None
        try:
            self.shadow = _Listener(socket.AF_INET, "127.0.0.2", self.allowed_port)      # the allowed PORT on another loopback address
        except OSError:
            self.shadow = None

    @property
    def ports(self) -> Dict[str, int]:
        out = {name: l.port for name, l in self.tcp.items()}
        out.update(udp=self.udp.port, udp6=self.udp6.port, resolver_udp=self.resolver.port, ipv6=self.ipv6.port)
        return out

    def hits(self, key: str) -> int:
        """How many connections or datagrams reached the listener of this experiment."""
        special = {"udp": self.udp, "udp6": self.udp6, "resolver_udp": self.resolver, "ipv6": self.ipv6, "unix_stream": self.unix_stream, "unix_dgram": self.unix_dgram,
                   "unix_dgram_pair": self.unix_dgram_pair, "shadow": self.shadow}
        listener = special[key] if key in special else self.tcp[key]
        return 0 if listener is None else len(listener.hits)

    def close(self) -> None:
        for l in list(self.tcp.values()) + [self.udp, self.udp6, self.resolver, self.ipv6, self.unix_stream, self.unix_dgram, self.unix_dgram_pair] + ([self.shadow] if self.shadow else []):
            l.close()
        self.origin.shutdown()
        self.origin.server_close()
