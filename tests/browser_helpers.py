# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Helpers of the browser-step tests: a mini bundle whose installation carries a browser pin (the real ``qa_runner/browser_pin.py`` in a synthetic wheel, with a stand-in ``playwright``
package that records ``install-deps`` calls), and a local HTTP server for the stand-in archives."""
from __future__ import annotations

import contextlib
import http.server
import importlib
import sys
import threading
import time
from pathlib import Path

from bundle_helpers import ROOT, bb, host_target, make_kit_wheel, make_wheel

RUNNER_SRC = ROOT / "packages" / "qa-runner" / "src"
for p in (str(RUNNER_SRC), str(ROOT / "packages" / "qa-runner" / "tests")):
    if p not in sys.path:
        sys.path.insert(0, p)

from qr_browser_fake import FakeBrowser, make_fake_browser   # noqa: E402,F401

STUB_PLAYWRIGHT = """import json, os, sys
log = os.environ.get("STUB_LOG")
browsers = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
listing = sorted(os.listdir(browsers)) if browsers and os.path.isdir(browsers) else None
if log:
    with open(log, "a") as fh:
        fh.write(json.dumps({"argv": sys.argv[1:], "browsers": browsers, "listing": listing}) + "\\n")
sys.exit(int(os.environ.get("STUB_EXIT", "0")))
"""


def pin_module():
    return importlib.import_module("qa_runner.browser_pin")


def make_runner_wheel(directory: Path, lock_bytes: bytes, *, ship_lock: bool = True) -> Path:
    name, version = "redevops_qa_testbrowser", "1.0"
    dist = f"{name}-{version}"
    files = {
        "qa_runner/__init__.py": b"",
        "qa_runner/browser_pin.py": (RUNNER_SRC / "qa_runner" / "browser_pin.py").read_bytes(),
        "playwright/__init__.py": b"",
        "playwright/__main__.py": STUB_PLAYWRIGHT.encode(),
        f"{dist}.dist-info/METADATA": f"Metadata-Version: 2.1\nName: {name.replace('_', '-')}\nVersion: {version}\n".encode(),
        f"{dist}.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{dist}.dist-info/top_level.txt": b"qa_runner\nplaywright\n",
    }
    if ship_lock:
        files[f"{dist}.data/data/share/redevops-qa/browser.lock.json"] = lock_bytes
    for lic in ("LICENSE.md", "LICENSE", "LICENSE-COMMONS-CLAUSE"):
        files[f"{dist}.dist-info/licenses/{lic}"] = f"licence text {lic}\n".encode()
    files[f"{dist}.dist-info/RECORD"] = ("\n".join(bb.record_line(n, d) for n, d in sorted(files.items())) + f"\n{dist}.dist-info/RECORD,,\n").encode()
    out = directory / f"{dist}-py3-none-any.whl"
    bb.write_wheel(out, files, 1_700_000_000)
    return out


def make_browser_bundle(out_dir: Path, fake: FakeBrowser, *, lock_bytes: bytes | None = None, name: str = "redevops-qa-bundle-test", ship_lock_in_wheel: bool = True) -> Path:
    lock = lock_bytes if lock_bytes is not None else fake.lock_bytes
    wheels = out_dir / "wheels"
    wheels.mkdir(parents=True)
    entries = [bb.WheelEntry(make_wheel(wheels, "1.0"), "first-party", "test"), bb.WheelEntry(make_kit_wheel(wheels), "first-party", "test"),
               bb.WheelEntry(make_runner_wheel(wheels, lock, ship_lock=ship_lock_in_wheel), "first-party", "test")]
    return bb.assemble(out_dir, name=name, entries=entries, target=host_target(), epoch=1_700_000_000, label="", version="1.0", commit="0" * 40, pins_info=None, licences_from={}, build_tools={},
                       readme_template=(ROOT / "bundle" / "README.md").read_text(encoding="utf-8"), browser_lock=lock)


@contextlib.contextmanager
def serve(directory: Path, delay: float = 0.0):
    """A loopback HTTP server for a directory; ``delay`` seconds of silence before each response (a slow host)."""
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(directory), **k)

        def do_GET(self):
            time.sleep(delay)
            super().do_GET()

        def log_message(self, *a):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()
