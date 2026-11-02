# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Loopback servers for the egress tests: a page server (the allowed origin; its page tries to reach another loopback port) and a counting listener (the
'forbidden' origin: it must never see a connection)."""
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class CountingListener:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.connections = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        self.sock.settimeout(0.1)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            self.connections += 1
            conn.close()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(2)
        self.sock.close()


class PageServer:
    """Serves ``/health`` and a page whose markup and script try to reach ``target_port`` on loopback."""

    def __init__(self, target_port):
        port = target_port

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/health":
                    body, kind = json.dumps({"status": "ok"}).encode(), "application/json"
                else:
                    body = ("<!doctype html><html><head><title>hostile</title></head><body><h1>page</h1>"
                            f"<img src='http://127.0.0.1:{port}/pixel.png'>"
                            f"<script>fetch('http://127.0.0.1:{port}/x', {{mode: 'no-cors'}}).catch(function(){{}});</script>"
                            "</body></html>").encode()
                    kind = "text/html"
                self.send_response(200)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(2)
