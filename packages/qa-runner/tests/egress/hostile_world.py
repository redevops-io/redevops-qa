# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Loopback only. Three listeners and one hostile page.

* ``A`` is the ALLOWED origin: it serves the hostile page (and answers ``/redir`` with a redirect to B).
* ``B`` is a hostile TCP origin on another loopback port. It records every request line it receives; the egress policy never lists it, so a protected browser must not reach it.
* ``U`` is a UDP listener on loopback that counts datagrams (a WebRTC STUN attempt, QUIC or anything else that goes around a TCP proxy ends here).

The page tries to reach B (and U) in every way a page can: image, prefetch, preconnect, iframe, script, fetch to B by number, by the name ``localhost``, by an IPv6 literal, by the decimal and hex
spellings of 127.0.0.1 and by a name that cannot be resolved; a redirect from A, a beacon, a WebSocket, an EventSource, a worker, ``window.open``, a form post and a WebRTC STUN request.
The page is the one of the audit's egress experiment (QA_PROD_00 section 5.3), promoted here to a test."""
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: every path of B that the page tries to reach and that a browser without the protections DOES reach (so a protected run that shows none of them is not an empty result). The fetch to the IPv6
#: literal and to the unresolvable name are tried too; B listens on IPv4 only and the name cannot resolve, so they are not on this list (the gateway log shows the attempts).
PATHS = ("/img", "/prefetch", "/iframe", "/script.js", "/fetch-nocors", "/fetch-localhost-name", "/fetch-decimal-ip", "/fetch-hex-ip", "/redirected", "/beacon", "/ws", "/sse",
         "/worker-fetch", "/window-open", "/form-post")

PAGE = """<!doctype html><title>hostile</title><body>
<img src="http://127.0.0.1:PB/img">
<link rel=prefetch href="http://127.0.0.1:PB/prefetch"><link rel=preconnect href="http://127.0.0.1:PB">
<iframe src="http://127.0.0.1:PB/iframe"></iframe>
<script src="http://127.0.0.1:PB/script.js"></script>
<img src="https://127.0.0.1:PB/tls.png">
<script>
const B='http://127.0.0.1:PB';
fetch(B+'/fetch-nocors',{mode:'no-cors'}).catch(()=>{});
fetch('http://localhost:PB/fetch-localhost-name',{mode:'no-cors'}).catch(()=>{});
fetch('http://[::1]:PB/fetch-ipv6',{mode:'no-cors'}).catch(()=>{});
fetch('http://2130706433:PB/fetch-decimal-ip',{mode:'no-cors'}).catch(()=>{});
fetch('http://0x7f.0.0.1:PB/fetch-hex-ip',{mode:'no-cors'}).catch(()=>{});
fetch('http://hostile.invalid:PB/fetch-unresolvable-name',{mode:'no-cors'}).catch(()=>{});
fetch('/redir',{mode:'no-cors',redirect:'follow'}).catch(()=>{});
navigator.sendBeacon(B+'/beacon','x');
try{new WebSocket('ws://127.0.0.1:PB/ws')}catch(e){}
try{new EventSource(B+'/sse')}catch(e){}
try{const w=new Worker(URL.createObjectURL(new Blob(["fetch('http://127.0.0.1:PB/worker-fetch',{mode:'no-cors'}).catch(()=>{})"])))}catch(e){}
try{window.open(B+'/window-open')}catch(e){}
try{const pc=new RTCPeerConnection({iceServers:[{urls:'stun:127.0.0.1:PU'}]});pc.createDataChannel('x');pc.createOffer().then(o=>pc.setLocalDescription(o)).catch(()=>{})}catch(e){}
try{const f=document.createElement('form');f.method='POST';f.action=B+'/form-post';f.target='_blank';document.body.appendChild(f);f.submit()}catch(e){}
fetch('http://127.0.0.1:PA/allowed-self').catch(()=>{});
</script></body>"""


WEBSOCKET_LINE = "try{new WebSocket('ws://127.0.0.1:PB/ws')}catch(e){}\n"
assert WEBSOCKET_LINE in PAGE
#: the same page without the WebSocket attempt. In the orchestrated lane (both egress layers) a WebSocket to a refused origin keeps the page from finishing its load, and the navigation
#: step times out (the lane is INCONCLUSIVE, never a pass); without it the lane runs to the end, which is what the lane test needs to show the allowed origin working.
PAGE_WITHOUT_WEBSOCKET = PAGE.replace(WEBSOCKET_LINE, "")

#: pages that can only make a TCP CONNECTION to the hostile origin, with no HTTP request line that the origin could count (a TLS ClientHello is not an HTTP request): an image over https and a secure
#: WebSocket. A ``<link rel=preconnect>`` is NOT such a row: the pinned Chromium opened no connection for it even with every protection off (probed with the hint in the head, over http and https, with
#: ``crossorigin`` and added by script: 0 connections), so a row for it could not show anything. The main page keeps its preconnect lines; the connection count covers them.
HTTPS_PAGE = '<!doctype html><title>https</title><body><img src="https://127.0.0.1:PB/tls.png"></body>'
WSS_PAGE = "<!doctype html><title>wss</title><body><script>try{new WebSocket('wss://127.0.0.1:PB/ws')}catch(e){}</script></body>"


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    on_accept = None

    def get_request(self):
        """Every ACCEPTED connection, before any request line is read: a bare TCP connect, a preconnect and a TLS ClientHello are connections too, and none of them is an HTTP request line."""
        conn = super().get_request()
        if self.on_accept is not None:
            self.on_accept()
        return conn


class HostileWorld:
    def __init__(self, page=PAGE):
        self.page = page
        self.b_hits = []
        self.b_connections = 0
        self.a_seen = []
        self.udp_datagrams = []
        self._lock = threading.Lock()

    # -- the listeners --------------------------------------------------------------------------------------------------------------------
    def __enter__(self):
        world = self

        class HostileB(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                with world._lock:
                    world.b_hits.append(self.path.split("?", 1)[0])
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

            do_POST = do_GET

        class AllowedA(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                with world._lock:
                    world.a_seen.append(self.path.split("?", 1)[0])
                if self.path == "/redir":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{world.b_port}/redirected")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == "/health":
                    body, kind = b'{"status":"ok"}', "application/json"
                else:
                    body = world.page.replace("PB", str(world.b_port)).replace("PU", str(world.udp_port)).replace("PA", str(world.a_port)).encode()
                    kind = "text/html"
                self.send_response(200)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._b = _Server(("127.0.0.1", 0), HostileB)
        self._b.on_accept = self._count_connection
        self._a = _Server(("127.0.0.1", 0), AllowedA)
        self.b_port = self._b.server_address[1]
        self.a_port = self._a.server_address[1]
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind(("127.0.0.1", 0))
        self._udp.settimeout(0.2)
        self.udp_port = self._udp.getsockname()[1]
        self._stop = threading.Event()
        self._threads = [threading.Thread(target=self._b.serve_forever, daemon=True), threading.Thread(target=self._a.serve_forever, daemon=True),
                         threading.Thread(target=self._udp_loop, daemon=True)]
        for t in self._threads:
            t.start()
        return self

    def _count_connection(self):
        with self._lock:
            self.b_connections += 1

    def _udp_loop(self):
        while not self._stop.is_set():
            try:
                data, _ = self._udp.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self.udp_datagrams.append(len(data))

    def __exit__(self, *exc):
        self._stop.set()
        for server in (self._a, self._b):
            server.shutdown()
            server.server_close()
        self._udp.close()
        for t in self._threads:
            t.join(3)

    # -- what happened ----------------------------------------------------------------------------------------------------------------------
    @property
    def origin(self):
        return f"http://127.0.0.1:{self.a_port}"

    def reset(self):
        with self._lock:
            self.b_hits.clear()
            self.b_connections = 0
            self.a_seen.clear()
            self.udp_datagrams.clear()

    def snapshot(self):
        with self._lock:
            return {"b_hits": frozenset(self.b_hits), "b_connections": self.b_connections, "a_seen": frozenset(self.a_seen), "udp": len(self.udp_datagrams)}
