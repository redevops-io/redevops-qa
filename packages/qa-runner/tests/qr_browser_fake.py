# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A small stand-in for the three Chromium archives and a lock for them, so the pin logic is tested without a browser and without a network.

The expected tree is written down here from the archive specifications, NOT derived by the code under test: unpacking is checked against an independent description.
"""
from __future__ import annotations

import hashlib
import json
import warnings
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

from qa_runner import browser_pin as bp

REGISTRY = json.dumps({"browsers": [{"name": "chromium", "revision": "1000", "browserVersion": "9.9.9.9"}]}).encode()
REVISION = "1000"
VERSION = "9.9.9.9"

# archive file -> (install directory, playwright name, [(zip entry, mode, content)], [explicit directory entries])
SPECS: Dict[str, Tuple[str, str, List[Tuple[str, int, bytes]], List[str]]] = {
    "chrome-linux64.zip": ("chromium-1000", "chromium",
                           [("chrome-linux64/chrome", 0o755, b"#!/bin/sh\necho fake chrome\n"), ("chrome-linux64/resources.pak", 0o644, b"resources" * 100),
                            ("chrome-linux64/locales/en.pak", 0o644, b"english"), ("chrome-linux64/private.key", 0o600, b"not shared")],
                           ["chrome-linux64/", "chrome-linux64/locales/"]),
    "chrome-headless-shell-linux64.zip": ("chromium_headless_shell-1000", "chromium-headless-shell",
                                          [("chrome-headless-shell-linux64/chrome-headless-shell", 0o755, b"#!/bin/sh\necho fake headless shell\n"),
                                           ("chrome-headless-shell-linux64/icudtl.dat", 0o644, b"icu")], []),
    "ffmpeg-linux.zip": ("ffmpeg-1000", "ffmpeg", [("ffmpeg-linux", 0o755, b"#!/bin/sh\necho fake ffmpeg\n"), ("COPYING.LGPLv2.1", 0o644, b"licence")], []),
}


def write_zip(path: Path, entries: List[Tuple[str, int, bytes]], dirs: List[str]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for d in dirs:
            info = zipfile.ZipInfo(d, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o40755 << 16) | 0x10
            zf.writestr(info, b"")
        for name, mode, content in entries:
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with warnings.catch_warnings():                       # a duplicate entry name is a case the tests write on purpose
                warnings.simplefilter("ignore")
                zf.writestr(info, content)


def expected_tree() -> Tuple[Dict[str, int], Dict[str, Tuple[int, int, str]]]:
    dirs: Dict[str, int] = {}
    files: Dict[str, Tuple[int, int, str]] = {}
    for _file, (install, _name, entries, _dirs) in SPECS.items():
        dirs[install] = 0o755
        files[f"{install}/{bp.MARKER}"] = (0o644, 0, hashlib.sha256(b"").hexdigest())
        for name, mode, content in entries:
            files[f"{install}/{name}"] = (mode, len(content), hashlib.sha256(content).hexdigest())
            parts = name.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                dirs[install + "/" + "/".join(parts[:i])] = 0o755
    return dirs, files


@dataclass
class FakeBrowser:
    archives_dir: Path
    lock_bytes: bytes
    lock: bp.Lock
    doc: dict

    def install(self, browsers: Path) -> None:
        """A correct installation by the code under test (stage and commit from the archives directory)."""
        staging = browsers.parent / ".fake-staging"
        browsers.mkdir(exist_ok=True)
        bp.stage(self.lock, browsers, staging, mirror=str(self.archives_dir))
        bp.commit(self.lock, browsers, staging)


def make_lock_doc(archives_dir: Path, *, revision: str = REVISION, version: str = VERSION, registry: bytes = REGISTRY, pw_version: str = "1.0.0") -> dict:
    dirs, files = expected_tree()
    archives = []
    for file, (install, name, _entries, _d) in SPECS.items():
        path = archives_dir / file
        archives.append({"name": name, "dir": install, "file": file, "urls": [f"https://example.invalid/first/{file}", f"https://example.invalid/second/{file}"],
                         "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size})
    return {"schema": bp.LOCK_SCHEMA, "schema_version": bp.LOCK_VERSION, "target": {"platform": bp.TARGET_PLATFORM},
            "playwright": {"version": pw_version, "browsers_json_sha256": hashlib.sha256(registry).hexdigest()},
            "browser": {"name": "chromium", "revision": revision, "browser_version": version}, "archives": archives,
            "tree": {"directories": {k: format(v, "04o") for k, v in dirs.items()}, "files": {k: [format(v[0], "04o"), v[1], v[2]] for k, v in files.items()}},
            "tree_sha256": bp.tree_digest(dirs, files)}


def make_fake_browser(base: Path) -> FakeBrowser:
    archives_dir = base / "archives"
    archives_dir.mkdir(parents=True)
    for file, (_install, _name, entries, dirs) in SPECS.items():
        write_zip(archives_dir / file, entries, dirs)
    doc = make_lock_doc(archives_dir)
    data = bp.render_lock(doc).encode("utf-8")
    return FakeBrowser(archives_dir, data, bp.parse_lock(data), doc)
