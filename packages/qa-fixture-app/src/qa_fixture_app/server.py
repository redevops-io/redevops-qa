# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""HTTP transport for the fixture app: loopback only, no Date header, no clock, request log, clean shutdown."""
from __future__ import annotations

import ipaddress
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping, Optional, Tuple
from urllib.parse import parse_qs

from .app import MAX_BODY_BYTES, FixtureApp, Handler, Request, Response
from .requestlog import RequestLog

SERVER_NAME = "qa-fixture-app"
DEFAULT_HOST = "127.0.0.1"


class NotLoopback(ValueError):
    """The requested bind address is not a loopback address. There is no option to override this."""


def check_loopback(host: str) -> str:
    """Accept a literal IPv4 loopback address (127.0.0.0/8) or ``::1`` and nothing else (no name, no wildcard, no other address)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise NotLoopback("bind address %r is not a literal loopback address (use 127.0.0.1 or ::1)" % host) from None
    if (ip.version == 4 and ip.is_loopback) or ip == ipaddress.ip_address("::1"):
        return host
    raise NotLoopback("bind address %s is not a loopback address; the fixture app only listens on loopback" % host)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: "_HTTPServer"

    def version_string(self) -> str:
        return SERVER_NAME

    # The standard library adds a Date header in send_response (a clock) and writes a log line to stderr; neither is wanted.
    def send_response(self, code: int, message: Optional[str] = None) -> None:
        self.send_response_only(code, message)
        self.send_header("Server", SERVER_NAME)

    def log_message(self, format: str, *args: object) -> None:
        pass

    def log_request(self, code: object = "-", size: object = "-") -> None:
        pass

    def _serve(self) -> None:
        method = self.command
        length_header = self.headers.get("Content-Length") or "0"
        length = int(length_header) if length_header.isdigit() else 0
        body = b""
        if length:
            # An oversized body is never read into memory; the app answers 413 and the connection is closed.
            body = self.rfile.read(min(length, MAX_BODY_BYTES + 1))
        headers = {k.lower(): v for k, v in self.headers.items()}
        request = Request(method=method, target=self.path, headers=headers, body=body)
        response = self.server.fixture.handle(request)
        data = response.body
        self.send_response(response.status)
        for name, value in response.headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(data)
        self.close_connection = True
        form_keys = sorted(parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)) if method == "POST" else []
        self.server.log.record(method, self.path, headers.get("host", ""), response.status, "cookie" in headers, form_keys, length)

    # Every method is routed through the app (unknown ones get 405 or 404) so that it is also logged; that includes CONNECT, which a
    # browser sends to a proxy and which therefore shows up in the log as a request for another host and port.
    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = _serve


class _HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = os.name != "nt"        # on Windows SO_REUSEADDR would allow another process to share the port
    fixture: FixtureApp
    log: RequestLog


class _HTTPServer6(_HTTPServer):
    address_family = socket.AF_INET6


class FixtureServer:
    """A running (or startable) fixture app. Use as a context manager, or call ``start`` and ``stop``."""

    def __init__(self, httpd: _HTTPServer, fixture: FixtureApp, log: RequestLog):
        self._httpd = httpd
        self.fixture = fixture
        self.log = log
        self._thread: Optional[threading.Thread] = None
        self._closed = False

    @property
    def host(self) -> str:
        return self._httpd.server_address[0]

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def defect(self) -> str:
        return self.fixture.defect

    @property
    def url(self) -> str:
        return "http://%s:%d" % (("[%s]" % self.host) if ":" in self.host else self.host, self.port)

    @property
    def request_count(self) -> int:
        return self.log.count

    def start(self) -> "FixtureServer":
        """Serve in a background thread (joined by ``stop``)."""
        self._thread = threading.Thread(target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05}, name="qa-fixture-app")
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        """Serve in the calling thread until ``shutdown`` is called from another thread (or a signal handler's helper thread)."""
        self._httpd.serve_forever(poll_interval=0.05)

    def shutdown(self) -> None:
        """Make ``serve_forever`` return. Only valid while serving, and never from the serving thread itself."""
        self._httpd.shutdown()

    def close(self) -> None:
        """Release the socket and the request log. Idempotent."""
        if not self._closed:
            self._closed = True
            self._httpd.server_close()
            self.log.close()

    def stop(self) -> None:
        """Stop a server started with ``start`` and release everything. Idempotent."""
        if self._thread is not None:
            self._httpd.shutdown()
            self._thread.join()
            self._thread = None
        self.close()

    def __enter__(self) -> "FixtureServer":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()


def create_server(defect: str = "none", host: str = DEFAULT_HOST, port: int = 0, request_log: Optional[str] = None,
                  extra_routes: Optional[Mapping[Tuple[str, str], Handler]] = None) -> FixtureServer:
    """Create the app, bind it and return the (not yet serving) server.

    ``defect``: one of ``qa_fixture_app.DEFECTS``. ``host``: a loopback literal only (``NotLoopback`` otherwise). ``port``: 0 asks the
    operating system for a free port (read it back from ``.port``). ``request_log``: path of the JSON-lines file to write (truncated),
    or None for no file. ``extra_routes``: the extension point, see the README.
    """
    check_loopback(host)
    fixture = FixtureApp(defect, extra_routes)             # validates the defect before anything is bound or created
    cls = _HTTPServer6 if ":" in host else _HTTPServer
    httpd = cls((host, port), _Handler)
    if not _is_loopback_address(httpd.server_address[0]):          # belt and braces: what was bound is what was meant
        httpd.server_close()
        raise NotLoopback("bound to a non-loopback address %s" % httpd.server_address[0])
    log = RequestLog(request_log, httpd.server_address[1])
    httpd.fixture = fixture
    httpd.log = log
    return FixtureServer(httpd, fixture, log)


def _is_loopback_address(host: str) -> bool:
    try:
        check_loopback(host)
        return True
    except NotLoopback:
        return False
