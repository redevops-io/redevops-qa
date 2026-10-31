# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Fixtures for the real-browser lane. Nothing here skips: a missing Selenium, browser or driver executable makes the tests that need
them fail with a clear message, so the lane cannot go green without a browser. The lane runs in its own CI job and is not collected
by the offline suite (the repository's pytest configuration excludes ``browser`` directories)."""
import http.server
import os
import threading

import pytest

PAGES = {
    "/": (b"<!doctype html><title>Home</title><h1 id='title'>Hello   world</h1><input name='user' id='user'>"
          b"<button data-testid='go' onclick=\"document.getElementById('out').textContent='Clicked '+document.getElementById('user').value\">Go</button>"
          b"<p id='out'></p><p id='cookie'></p><script>document.getElementById('cookie').textContent='cookie:'+document.cookie;</script>"),
    "/set-cookie": b"<!doctype html><title>Cookie</title><script>document.cookie='qa=1; path=/';</script><p id='done'>set</p>",
    "/redirect": None,
}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://redirect-target.invalid/")
            self.end_headers()
            return
        body = PAGES.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="session")
def site():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
    thread.join(5)


@pytest.fixture(scope="session")
def selenium_installed():
    try:
        import importlib.metadata as md
        import selenium  # noqa: F401
        version = md.version("selenium")
    except Exception as exc:
        pytest.fail(f"Selenium is not importable in the real-browser lane ({type(exc).__name__})")
    assert version == "4.52.0", f"the lane is pinned to Selenium 4.52.0, found {version}"
    return version


@pytest.fixture(scope="session")
def chrome_paths(selenium_installed):
    driver, binary = os.environ.get("QA_CHROMEDRIVER_PATH", ""), os.environ.get("QA_CHROME_BINARY", "")
    for name, path in (("QA_CHROMEDRIVER_PATH", driver), ("QA_CHROME_BINARY", binary)):
        if not (path and os.path.isfile(path) and os.access(path, os.X_OK)):
            pytest.fail(f"{name} must name an executable file for the real-browser lane (got {path!r}); the lane never downloads a browser")
    return driver, binary
