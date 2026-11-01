# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A tiny static fixture site served from loopback by the test itself. Nothing here is fetched from anywhere."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Tuple

PAGES: Dict[str, Tuple[str, bytes]] = {}


def page(path: str, body: str, ctype: str = "text/html; charset=utf-8") -> None:
    PAGES[path] = (ctype, body.encode("utf-8"))


page("/login", """<!doctype html><html lang="en"><head><title>Sign in</title></head><body>
<h1>Sign in</h1>
<form onsubmit="event.preventDefault(); document.getElementById('msg').textContent = 'Welcome back'; return false;">
<label for="email">Email</label><input id="email" data-testid="email" type="text">
<label for="pw">Password</label><input id="pw" data-testid="password" type="password">
<label><input type="checkbox" id="rem"> Remember me</label>
<button type="submit" data-testid="submit">Submit</button>
</form><p id="msg" role="status"></p></body></html>""")
page("/dup", """<!doctype html><title>Dup</title><button>Save</button><button>Save</button><button>Cancel</button>""")
page("/hidden", """<!doctype html><title>Hidden</title><button style="display:none">Ghost</button><button>Visible</button>""")
page("/delayed", """<!doctype html><title>Delayed</title><div id="c"></div>
<script>setTimeout(function () { document.getElementById('c').innerHTML = '<button>Later</button>'; }, 400);</script>""")
page("/overlay", """<!doctype html><title>Overlay</title><button>Under</button>
<div role="dialog" aria-modal="true" style="position:fixed;left:0;top:0;right:0;bottom:0;background:#fff">Consent required</div>""")
page("/storage", """<!doctype html><title>Storage</title><p id="o"></p>
<script>var n = (parseInt(localStorage.getItem('visits') || '0', 10)) + 1; localStorage.setItem('visits', String(n));
document.cookie = 'v=' + n; document.getElementById('o').textContent = 'visits=' + n + ' jar=' + document.cookie;</script>""")
page("/popup", """<!doctype html><title>Popup</title><a href="/home" target="_blank">Open</a>""")
page("/download", """<!doctype html><title>Download</title><a href="/file.bin" download>Get</a>""")
page("/file.bin", "binary-ish", "application/octet-stream")
page("/home", """<!doctype html><title>Home</title><h1>Welcome</h1>""")
page("/subres", """<!doctype html><title>Subresources</title>
<img src="/pixel.png" alt="local"><script>fetch('/api/ok').catch(function () {});</script>""")
page("/pixel.png", "x", "image/png")
page("/api/ok", "{}", "application/json")
page("/redirect", "", "text/html")


class Handler(BaseHTTPRequestHandler):
    server_version = "fixture"

    def log_message(self, *args):          # silence
        pass

    def do_GET(self):
        self.server.log.append((self.command, self.path, self.headers.get("Host", "")))
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", self.server.redirect_to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        found = PAGES.get(self.path.split("?")[0])
        if found is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        ctype, body = found
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        if self.path.startswith("/file.bin"):
            self.send_header("Content-Disposition", 'attachment; filename="f.bin"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FixtureServer:
    def __init__(self) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.log = []
        self.httpd.redirect_to = "/home"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    @property
    def log(self) -> List[Tuple[str, str, str]]:
        return self.httpd.log

    def url(self, path: str, host: str = "127.0.0.1") -> str:
        return f"http://{host}:{self.port}{path}"

    def __enter__(self) -> "FixtureServer":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
