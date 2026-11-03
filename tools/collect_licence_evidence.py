#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Make the two tables of facts that third_party/adapter-license-matrix.yaml points at (``third_party/evidence/*.json``) from a Playwright wheel.

    python tools/collect_licence_evidence.py node-sections --wheel PLAYWRIGHT.whl --node-version 24.22.1 --out FILE        (offline)
    python tools/collect_licence_evidence.py npm-inlined   --wheel PLAYWRIGHT.whl --retrieved-on YYYY-MM-DD --out FILE    (network: the public npm registry)
    python tools/collect_licence_evidence.py import-candidates --tarball PLAYWRIGHT-REPO.tar.gz --tag v1.64.1 --retrieved-on YYYY-MM-DD --out FILE   (the repository tarball of the tag; no network if given)
    python tools/collect_licence_evidence.py inventory --wheel WHEEL.whl [--matrix FILE]                                  (offline: prints the candidate licence-bearing files and which are covered)

``node-sections`` reads ``playwright/driver/LICENSE`` (the Node.js licence file the wheel carries) and records, for each of the externally maintained libraries it lists, the name, the place
in the Node.js source tree, the sha256 of its section and the licence its own text names (``NODE_CLASSES``, read by hand and checked here against the words of the section: a classification
that its section does not support stops the tool). ``npm-inlined`` reads the two sidecar notice files of the Playwright driver (``utilsBundle.js.LICENSE``, ``serverRegistry.js.LICENSE``) and,
for every ``name@version`` in them, the registry entry of that exact version, the published tarball (checked against the registry's integrity value, read in memory and never unpacked to
disk), and the licence files inside it, and records whether the notice text contains the tarball's licence file. ``tools/check_adapter_licenses.py --wheelhouse`` recomputes both from the wheels
of a built bundle and fails when they differ. The output is deterministic apart from the retrieval date you give. Nothing here is a legal classification.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, List, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_adapter_licenses as cal      # noqa: E402

NODE_LICENSE_MEMBER = "playwright/driver/LICENSE"
NPM_MEMBERS = ("playwright/driver/package/lib/utilsBundle.js.LICENSE", "playwright/driver/package/lib/serverRegistry.js.LICENSE")
#: the licence each section of the Node.js LICENSE file names for its component, read from the file for v24.22.1 (see third_party/evidence/node-24.22.1-licence-sections.json)
NODE_CLASSES: Dict[str, str] = {
    "Acorn": "MIT", "c-ares": "MIT", "merve": "MIT", "ittapi": "BSD-3-Clause", "amaro": "MIT", "swc": "Apache-2.0", "ICU": "Unicode-3.0", "libuv": "MIT", "LIEF": "Apache-2.0",
    "llhttp": "MIT", "corepack": "MIT", "undici": "MIT", "postject": "MIT", "OpenSSL": "Apache-2.0", "Punycode.js": "MIT", "V8": "BSD-3-Clause", "SipHash": "CC0-1.0",
    "zlib": "Zlib", "simdjson": "Apache-2.0", "simdutf": "MIT", "ada": "MIT", "minimatch": "BlueOak-1.0.0", "npm": "Artistic-2.0", "GYP": "BSD-3-Clause",
    "inspector_protocol": "BSD-3-Clause", "jinja2": "BSD-3-Clause", "markupsafe": "BSD-3-Clause", "cpplint.py": "BSD-3-Clause", "gypi_to_gn.py": "BSD-3-Clause",
    "gtest": "BSD-3-Clause", "nghttp2": "MIT", "large_pages": "MIT", "caja": "Apache-2.0", "brotli": "MIT", "zstd": "BSD-3-Clause", "HdrHistogram": "CC0-1.0 OR BSD-2-Clause",
    "node-heapdump": "ISC", "rimraf": "ISC", "uvwasi": "MIT", "ngtcp2": "MIT", "nghttp3": "MIT", "node-fs-extra": "MIT", "on-exit-leak-free": "MIT", "sonic-boom": "MIT",
}
SUPPORT = cal.NODE_SPDX_SUPPORT


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def node_sections(wheel: Path, node_version: str) -> dict:
    with zipfile.ZipFile(wheel) as zf:
        raw = zf.read(NODE_LICENSE_MEMBER)
    text = raw.decode("utf-8")
    sections = cal.node_license_sections(text)
    names = [s["name"] for s in sections]
    if sorted(names) != sorted(NODE_CLASSES):
        raise SystemExit(f"the licence file lists {sorted(set(names) ^ set(NODE_CLASSES))} differently from NODE_CLASSES: read the new sections before classifying them")
    hits = list(cal._NODE_ITEM.finditer(text))
    for i, sec in enumerate(sections):
        body = re.sub(r"\s+", " ", text[hits[i].start(): hits[i + 1].start() if i + 1 < len(hits) else len(text)].lower())
        spdx = NODE_CLASSES[sec["name"]]
        if not any(all(word in body for word in alt) for alt in SUPPORT[spdx]):
            raise SystemExit(f"{sec['name']}: its section does not contain the words that support {spdx}")
        sec["spdx"] = spdx
    return {"schema": cal.NODE_TABLE_SCHEMA, "node_version": node_version, "source_member": NODE_LICENSE_MEMBER, "license_file_sha256": sha256_bytes(raw), "count": len(sections),
            "note": "the list of externally maintained libraries in the Node.js LICENSE file of this version; location_class is about the path in the source tree only and does not say what is linked into the executable",
            "sections": sections}


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "redevops-qa-licence-evidence"})
    with urllib.request.urlopen(req, timeout=60) as response:     # noqa: S310 (https URL built from the registry)
        return response.read()


_LIC_FILE = re.compile(r"(^|/)(licen[sc]e|copying)([-._][^/]*)?$", re.I)


def npm_inlined(wheel: Path, retrieved_on: str) -> dict:
    sections: Dict[tuple, tuple] = {}
    with zipfile.ZipFile(wheel) as zf:
        for member in NPM_MEMBERS:
            for key, (_kind, digest) in cal.npm_notice_sections(zf.read(member).decode("utf-8", "replace")).items():
                sections[(key, member.rsplit("/", 1)[-1])] = (member.rsplit("/", 1)[-1], digest, zf.read(member).decode("utf-8", "replace"))
    rows: List[dict] = []
    cache: Dict[str, tuple] = {}
    for skey in sorted(sections):
        key = skey[0]
        name, version = key.rsplit("@", 1)
        url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@").replace("/", "%2f") + "/" + version
        if key not in cache:
            meta = json.loads(_get(url))
            cache[key] = (meta, _get(meta["dist"]["tarball"]))
        meta, tarball = cache[key]
        integrity = meta["dist"].get("integrity", "")
        verified = integrity.startswith("sha512-") and base64.b64encode(hashlib.sha512(tarball).digest()).decode() == integrity[7:]
        files: Dict[str, str] = {}
        contents: Dict[str, str] = {}
        with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tf:
            for m in tf.getmembers():
                if m.isfile() and _LIC_FILE.search(m.name) and m.name.count("/") <= 1:
                    data = tf.extractfile(m).read()
                    rel = m.name.split("/", 1)[1] if "/" in m.name else m.name
                    files[rel] = sha256_bytes(data)
                    contents[rel] = data.decode("utf-8", "replace")
        licence = meta.get("license")
        if isinstance(licence, dict):
            licence = licence.get("type")
        if licence is None and meta.get("licenses"):
            licence = " OR ".join(str(x.get("type", "?")) for x in meta["licenses"])
        norm = lambda t: re.sub(r"\s+", " ", t).strip().lower()      # noqa: E731
        notice_text = norm(sections[skey][2].split("%% " + key + " NOTICES AND INFORMATION BEGIN HERE", 1)[1].split("\nEND OF " + key, 1)[0])
        contained = sorted(f for f, t in contents.items() if norm(t) in notice_text)
        rows.append({"package": key, "notice_file": sections[skey][0], "notice_section_sha256": sections[skey][1], "registry_license": licence, "registry_url": url,
                     "tarball_sha256": sha256_bytes(tarball), "tarball_sha512_verified": bool(verified), "licence_files_in_tarball": dict(sorted(files.items())),
                     "notice_text_contains_tarball_licence_file": contained})
        print(f"{key}: {licence} integrity={verified} files={sorted(files)} contained={contained}", file=sys.stderr)
    return {"schema": cal.NPM_TABLE_SCHEMA, "retrieved_on": retrieved_on, "source_members": list(NPM_MEMBERS), "count": len(rows), "distinct": len({r["package"] for r in rows}),
            "derived_digests": cal.npm_table_digests({"packages": rows}),
            "note": "one row per notice section (chokidar and readdirp have a section in both sidecar files); for each npm package inlined into the Playwright driver: the registry entry of that exact version, its tarball (checked against the registry's sha512 integrity value) and whether the notice text of the wheel contains the licence file of the tarball",
            "packages": rows}


#: the packages of Playwright's repository whose output ends up in the wheel (playwright-core, what it inlines from utils and isomorphic, and the five vite applications)
WHEEL_PACKAGE_DIRS = ("playwright-core", "utils", "isomorphic", "web", "trace-viewer", "html-reporter", "recorder", "dashboard", "injected", "protocol", "playwright-client")
SELF_NAMES = ("playwright", "playwright-core", "@playwright/test")
_IMPORT = re.compile(r"""(?:from\s+|import\s*\(\s*|require\s*\(\s*|import\s+)['"]([^'"./][^'"]*)['"]""")


def import_candidates(tarball: Path, tag: str, retrieved_on: str) -> dict:
    """The bare package names imported by the sources of WHEEL_PACKAGE_DIRS (not their tests) that the repository's package-lock.json resolves, with the version, licence field and whether it is a
    development dependency. This follows import statements: it says what Playwright's sources reach for, not what a bundler inlined."""
    raw = tarball.read_bytes()
    found: Dict[str, set] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        lock_member = next(m for m in tf.getmembers() if m.name.count("/") == 1 and m.name.endswith("/package-lock.json"))
        lock_bytes = tf.extractfile(lock_member).read()
        lock = json.loads(lock_bytes)["packages"]
        resolved = {k.split("node_modules/", 1)[1]: v for k, v in lock.items() if k.startswith("node_modules/") and k.count("node_modules/") == 1}
        for m in tf.getmembers():
            if not m.isfile():
                continue
            parts = m.name.split("/", 1)[1].split("/")
            if len(parts) < 3 or parts[0] != "packages" or parts[1] not in WHEEL_PACKAGE_DIRS or not m.name.endswith((".ts", ".tsx", ".js", ".mjs", ".mts", ".jsx")) or "/tests/" in m.name or "/test/" in m.name:
                continue
            for spec in _IMPORT.findall(tf.extractfile(m).read().decode("utf-8", "replace")):
                bits = spec.split("/")
                name = "/".join(bits[:2]) if spec.startswith("@") else bits[0]
                if name in resolved and name not in SELF_NAMES:
                    found.setdefault(name, set()).add(parts[1])
    pk = [{"name": n, "version": resolved[n].get("version"), "license": resolved[n].get("license"), "dev": bool(resolved[n].get("dev")), "imported_by": sorted(found[n])} for n in sorted(found)]
    return {"schema": cal.IMPORT_TABLE_SCHEMA, "tag": tag, "retrieved_on": retrieved_on, "repository_tarball_sha256": sha256_bytes(raw), "package_lock_sha256": sha256_bytes(lock_bytes), "count": len(pk),
            "package_dirs": list(WHEEL_PACKAGE_DIRS), "note": "bare package names imported by the sources of those directories (tests excluded) that package-lock.json resolves; follows import statements, not what a bundler inlined", "packages": pk}


def inventory_report(wheel: Path, matrix_path: Path) -> int:
    import yaml
    matrix = yaml.safe_load(matrix_path.read_text(encoding="utf-8"))
    inv = matrix.get("inventory") or {}
    import fnmatch
    with zipfile.ZipFile(wheel) as zf:
        hits = cal.scan_wheel_inventory(zf, inv.get("own_holders") or [])
    pats = []
    for comp in matrix["components"]:
        for rec in comp.get("shipped_wheels") or []:
            if cal._wheel_key(wheel.name) == (cal._norm(rec["name"]), str(rec["version"])):
                pats = cal._inventory_patterns(comp, rec)
    unc = 0
    for path, (holders, marks) in sorted(hits.items()):
        covered = any(fnmatch.fnmatchcase(path, p) for p in pats)
        unc += not covered
        print(("covered   " if covered else "UNCOVERED ") + path + "  " + str(holders[:3]) + " " + str(marks[:3]))
    print(f"{len(hits)} candidate files, {unc} uncovered. Best effort: a file without a header is not found; this does not show that the inventory is complete.")
    return 1 if unc else 0


def main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("node-sections")
    a.add_argument("--wheel", type=Path, required=True)
    a.add_argument("--node-version", required=True)
    a.add_argument("--out", type=Path, required=True)
    b = sub.add_parser("npm-inlined")
    b.add_argument("--wheel", type=Path, required=True)
    b.add_argument("--retrieved-on", required=True)
    b.add_argument("--out", type=Path, required=True)
    c = sub.add_parser("import-candidates")
    c.add_argument("--tarball", type=Path, required=True)
    c.add_argument("--tag", required=True)
    c.add_argument("--retrieved-on", required=True)
    c.add_argument("--out", type=Path, required=True)
    d = sub.add_parser("inventory")
    d.add_argument("--wheel", type=Path, required=True)
    d.add_argument("--matrix", type=Path, default=cal.DEFAULT_MATRIX)
    args = ap.parse_args(list(argv))
    if args.cmd == "inventory":
        return inventory_report(args.wheel, args.matrix)
    if args.cmd == "import-candidates":
        data = import_candidates(args.tarball, args.tag, args.retrieved_on)
        args.out.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"{args.out}: {data['count']} packages")
        return 0
    data = node_sections(args.wheel, args.node_version) if args.cmd == "node-sections" else npm_inlined(args.wheel, args.retrieved_on)
    args.out.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{args.out}: {data['count']} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
