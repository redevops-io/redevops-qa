#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Make ``bundle/browser.lock.json`` (a maintainer tool: run it when the pinned Playwright version changes, review the diff, commit the result).

    python tools/make_browser_lock.py --wheel PLAYWRIGHT.whl --dry-run FILE --archives DIR --tree DIR --out FILE

Inputs, all of them produced on a Linux x86_64 machine with the pinned Playwright installed:

* ``--wheel``      the pinned Playwright wheel (its ``browsers.json`` gives the revision and the browser version; its sha256 is recorded);
* ``--dry-run``    the output of ``python -m playwright install --dry-run chromium`` (the install locations and download URLs Playwright itself prints);
* ``--archives``   a directory holding the archives those URLs serve, under their file names (the tool records their sha256 and size);
* ``--tree``       a ``PLAYWRIGHT_BROWSERS_PATH`` directory that ``python -m playwright install chromium`` wrote (the tool records every directory and file of the install directories).

It refuses to write a lock unless unpacking each archive with ``qa_runner.browser_pin`` (the unpacking ``install-browser.sh`` uses) gives exactly the tree Playwright's own
installer wrote: the lock then describes both ways of installing. Nothing is downloaded and nothing is executed from the inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "qa-runner" / "src"))
from qa_runner import browser_pin as bp                     # noqa: E402

BROWSERS_JSON = "playwright/driver/package/browsers.json"


class ToolError(Exception):
    pass


def parse_dry_run(text: str) -> list:
    """Blocks of ``Title (playwright NAME vREV)`` with ``Install location:`` and ``Download url:`` / ``Download fallback N:`` lines."""
    blocks = []
    cur = None
    for line in text.splitlines():
        m = re.match(r"^(.+) \(playwright ([A-Za-z0-9_-]+) v(\d+)\)\s*$", line)
        if m:
            cur = {"name": m.group(2), "revision": m.group(3), "urls": [], "location": None}
            blocks.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+Install location:\s+(\S+)\s*$", line)
        if m:
            cur["location"] = m.group(1)
        m = re.match(r"^\s+Download (?:url|fallback \d+):\s+(\S+)\s*$", line)
        if m:
            cur["urls"].append(m.group(1))
    return blocks


def make_lock(wheel: Path, dry_run_text: str, archives_dir: Path, tree: Path) -> dict:
    with zipfile.ZipFile(wheel) as zf:
        browsers_json_bytes = zf.read(BROWSERS_JSON)
        meta = next(n for n in zf.namelist() if re.fullmatch(r"[^/]+\.dist-info/METADATA", n))
        version = re.search(r"^Version: (.+)$", zf.read(meta).decode("utf-8"), re.M).group(1).strip()
    registry = {b["name"]: b for b in json.loads(browsers_json_bytes)["browsers"]}
    chromium = registry["chromium"]
    blocks = parse_dry_run(dry_run_text)
    if not blocks:
        raise ToolError("the dry-run output has no browser blocks")
    archives = []
    for b in blocks:
        reg = registry.get(b["name"])
        if reg is None or str(reg["revision"]) != b["revision"]:
            raise ToolError(f"{b['name']} v{b['revision']} is not what the wheel's browsers.json says ({reg and reg['revision']})")
        if not b["urls"] or not b["location"]:
            raise ToolError(f"{b['name']} has no install location or download URL in the dry-run output")
        files = {u.rsplit("/", 1)[-1] for u in b["urls"]}
        if len(files) != 1:
            raise ToolError(f"the URLs of {b['name']} do not end in one file name")
        fname = files.pop()
        path = archives_dir / fname
        data_hash = bp.sha256_file(path)
        archives.append({"name": b["name"], "dir": Path(b["location"]).name, "file": fname, "urls": b["urls"], "sha256": data_hash, "size": path.stat().st_size})
    install_dirs = [a["dir"] for a in archives]
    dirs, files = bp.scan_tree(tree, install_dirs)
    doc = {"schema": bp.LOCK_SCHEMA, "schema_version": bp.LOCK_VERSION, "target": {"platform": bp.TARGET_PLATFORM},
           "playwright": {"version": version, "browsers_json_sha256": hashlib.sha256(browsers_json_bytes).hexdigest()},
           "browser": {"name": "chromium", "revision": str(chromium["revision"]), "browser_version": chromium["browserVersion"]},
           "archives": archives,
           "tree": {"directories": {k: format(v, "04o") for k, v in dirs.items()}, "files": {k: [format(v[0], "04o"), v[1], v[2]] for k, v in files.items()}},
           "tree_sha256": bp.tree_digest(dirs, files)}
    lock = bp.parse_lock(bp.render_lock(doc).encode("utf-8"))
    # the equivalence proof: unpack every archive the way install-browser.sh does and compare with what Playwright's installer wrote
    with tempfile.TemporaryDirectory(prefix="browser-lock-") as tmp:
        staging = Path(tmp)
        for a in lock.archives:
            (staging / a.dir).mkdir()
            bp.os.chmod(staging / a.dir, lock.directories[a.dir])
            bp.extract_archive(archives_dir / a.file, staging / a.dir, a, lock)
            marker = staging / a.dir / bp.MARKER
            marker.touch()
            marker.chmod(lock.files[f"{a.dir}/{bp.MARKER}"][0])
        problems = bp.verify_tree(staging, lock)
        if problems:
            raise ToolError("unpacking the archives does not give the tree Playwright's installer wrote: " + bp.summarise(problems))
    return doc


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="make_browser_lock.py", description=__doc__.split("\n\n")[0])
    p.add_argument("--wheel", required=True)
    p.add_argument("--dry-run", required=True)
    p.add_argument("--archives", required=True)
    p.add_argument("--tree", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    try:
        doc = make_lock(Path(args.wheel), Path(args.dry_run).read_text(encoding="utf-8"), Path(args.archives), Path(args.tree))
    except (ToolError, bp.LockError, OSError, KeyError, zipfile.BadZipFile) as exc:
        print(f"make_browser_lock: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    out = Path(args.out)
    with open(out, "x", encoding="utf-8", newline="\n") as fh:
        fh.write(bp.render_lock(doc))
    lock = bp.load_lock(out)
    print(f"wrote {out}: Chromium {lock.browser_version} (revision {lock.revision}), {len(lock.files)} files, {len(lock.directories)} directories, tree sha256 {lock.tree_sha256}")
    for a in lock.archives:
        print(f"  {a.file}: sha256 {a.sha256} size {a.size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
