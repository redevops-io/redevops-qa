# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Minimal stand-in server. It listens on a configured port, answers a configured health path with ``ok`` and echoes the method,
the path and the headers of every other request as JSON, so that a rewrite or a method restriction can be asserted from the
outside. It uses only the standard library, writes nothing and makes no outgoing connection."""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 65536


def make_handler(health_path):
    class Handler(BaseHTTPRequestHandler):
        server_version = "standin/1"
        protocol_version = "HTTP/1.1"

        def _answer(self):
            length = int(self.headers.get("Content-Length") or 0)
            body_len = len(self.rfile.read(min(length, MAX_BODY))) if length else 0
            path = self.path
            if path.split("?", 1)[0] == health_path:
                payload, ctype = b"ok", "text/plain"
            else:
                headers = {}
                for name, value in self.headers.items():
                    headers[name.lower()] = headers[name.lower()] + ", " + value if name.lower() in headers else value
                payload = json.dumps({"method": self.command, "path": path, "headers": headers, "body_length": body_len}, sort_keys=True).encode()
                ctype = "application/json"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(0 if self.command == "HEAD" else len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _answer

        def log_message(self, fmt, *args):
            return

    return Handler


def make_server(port, health_path="/health", host="0.0.0.0"):
    return ThreadingHTTPServer((host, port), make_handler(health_path))


def main():
    port = int(os.environ.get("STANDIN_PORT", "8080"))
    health = os.environ.get("STANDIN_HEALTH_PATH", "/health")
    if not 1 <= port <= 65535 or not health.startswith("/"):
        sys.exit(2)
    make_server(port, health).serve_forever()


if __name__ == "__main__":
    main()
