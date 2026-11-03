#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Check a built redevops-qa bundle directory: what is in it is what its own records say, and what its text says is not more than what was done.

    python -I tools/check_bundle.py BUNDLE_DIR [--allow-test-target]

Standard library only; it reads the directory and nothing else, and it does not import the builder (a check that shared the builder's code would share its mistakes).
Exit status 0 when there is no finding, 1 otherwise, 2 for a usage error. Findings: ``code where: message``.

Checked: the file set against SHA256SUMS (every file listed once, nothing unlisted, every digest right); BUNDLE.json (schema, target, one Python minor and one platform,
wheels with digests, the browser record, the licence statements); requirements.lock (every wheel exactly once, ``name==version`` as in its file name, a ``--hash`` that is
the file's sha256, no other requirement); the wheels themselves (a METADATA whose name and version are the file name's; no wheel outside the manifest); the pinned-upstreams
wheel (pins.toml byte for byte, the pinned trees under .pinned next to it); the text of README.md and BUNDLE.json against a list of claims this release does not make.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, NamedTuple, Sequence

REQUIRED_FILES = ("BUNDLE.json", "README.md", "SHA256SUMS", "requirements.lock", "install.sh", "install-browser.sh", "uninstall.sh")
PINNED_DIST = "redevops_qa_pinned_upstreams"
FAMILY_LICENCE_FILES = ("LICENSE.md", "LICENSE", "LICENSE-COMMONS-CLAUSE")
#: text a bundle must never carry (case-insensitive): a command that names the other project on the package index, and claims that are not made
FORBIDDEN = ("pip install agent-harness", "pip install agent_harness", "tamper-proof", "tamper proof", "tamperproof", "reproducible build", "bit-for-bit", "soc 2", "soc2", "cis benchmark",
             "audited", "qa demo site")
#: phrases that must be there
REQUIRED_TEXT = ("AGPL-3.0-or-later with the Commons Clause", "not open source", "plain AGPL-3.0-or-later", "downloaded", "not hashed", "Node.js", "private staging only")


class Finding(NamedTuple):
    code: str
    where: str
    message: str

    def __str__(self) -> str:
        return f"{self.code} {self.where}: {self.message}"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _wheel_nv(filename: str):
    m = re.fullmatch(r"([A-Za-z0-9_.]+)-([A-Za-z0-9_.!+]+)-([A-Za-z0-9_.]+)-([A-Za-z0-9_.]+)-([A-Za-z0-9_.]+)\.whl", filename)
    return (_canon(m.group(1)), m.group(2)) if m else None


def check_bundle(root: Path, *, allow_test_target: bool = False) -> List[Finding]:
    root = Path(root)
    out: List[Finding] = []
    if not root.is_dir():
        return [Finding("NOT_A_DIRECTORY", str(root), "no such directory")]
    for f in REQUIRED_FILES:
        if not (root / f).is_file():
            out.append(Finding("MISSING_FILE", f, "a bundle has this file"))
    if not (root / "wheelhouse").is_dir():
        out.append(Finding("MISSING_FILE", "wheelhouse", "a bundle has a wheelhouse directory"))
    if out:
        return out
    files = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    # --- SHA256SUMS
    listed: Dict[str, str] = {}
    for n, line in enumerate((root / "SHA256SUMS").read_text(encoding="utf-8").splitlines(), 1):
        digest, sep, rel = line.partition("  ")
        if not sep or not re.fullmatch(r"[0-9a-f]{64}", digest) or not rel:
            out.append(Finding("SUMS_FORMAT", f"SHA256SUMS:{n}", "not '<sha256>  <path>'"))
            continue
        if rel in listed:
            out.append(Finding("SUMS_DUPLICATE", rel, "listed twice"))
        listed[rel] = digest
    for rel in sorted(files - set(listed) - {"SHA256SUMS"}):
        out.append(Finding("SUMS_UNLISTED", rel, "a file of the bundle that SHA256SUMS does not list"))
    for rel in sorted(set(listed) - files):
        out.append(Finding("SUMS_MISSING", rel, "listed in SHA256SUMS but not in the bundle"))
    for rel in sorted(files & set(listed)):
        if _sha256(root / rel) != listed[rel]:
            out.append(Finding("SUMS_MISMATCH", rel, "the file does not have the listed sha256"))
    # --- BUNDLE.json
    try:
        manifest = json.loads((root / "BUNDLE.json").read_text(encoding="utf-8"))
    except ValueError as exc:
        return out + [Finding("MANIFEST_INVALID", "BUNDLE.json", f"not JSON ({exc})")]
    if manifest.get("schema") != "redevops-qa/bundle" or manifest.get("schema_version") != "1.0":
        out.append(Finding("MANIFEST_SCHEMA", "BUNDLE.json", "schema must be redevops-qa/bundle 1.0"))
    target = manifest.get("target") or {}
    if not allow_test_target and target != {"python": "3.12", "python_tag": "cp312", "platform": "linux-x86_64"}:
        out.append(Finding("TARGET", "BUNDLE.json", "a release bundle is for CPython 3.12 on linux-x86_64 and nothing else"))
    if set(target) != {"python", "python_tag", "platform"}:
        out.append(Finding("TARGET", "BUNDLE.json", "target names a python, a python_tag and a platform"))
    if root.name != manifest.get("name"):
        out.append(Finding("NAME", "BUNDLE.json", "the directory name is not the bundle name"))
    browser = manifest.get("browser") or {}
    if browser.get("hashed_by_this_bundle") is not False or browser.get("fetched_at_install") is not True:
        out.append(Finding("BROWSER_RECORD", "BUNDLE.json", "the browser is downloaded at install time and is not hashed by the bundle; the record must say so"))
    lic = manifest.get("licences") or {}
    if "agent_harness" not in lic or "runtime_contracts" not in lic or "redevops_qa_packages" not in lic or "third_party" not in lic:
        out.append(Finding("LICENCES", "BUNDLE.json", "the licence record names the family packages, runtime-contracts, agent-harness and the third-party wheels separately"))
    if "private staging only" not in str(lic.get("third_party_staging", "")).lower() or "owner decision" not in str(lic.get("third_party_staging", "")):
        out.append(Finding("LICENCES", "BUNDLE.json", "the licence record says the third-party wheels are private staging only and that public distribution requires an owner decision"))
    if any(w.get("name") == "playwright" for w in manifest.get("wheels") or []):
        note = str((lic.get("third_party_notes") or {}).get("playwright", ""))
        if "Node.js" not in note or "npm" not in note:
            out.append(Finding("LICENCES", "BUNDLE.json", "the Playwright wheel contains a Node.js runtime and inlined npm packages; the licence record must say so"))
    # --- wheels and the lock
    entries = manifest.get("wheels") or []
    on_disk = {p.name for p in (root / "wheelhouse").iterdir()}
    names = [w.get("filename") for w in entries]
    if len(set(names)) != len(names):
        out.append(Finding("WHEELS_DUPLICATE", "BUNDLE.json", "a wheel is listed twice"))
    for extra in sorted(on_disk - set(names)):
        out.append(Finding("WHEEL_UNLISTED", f"wheelhouse/{extra}", "not in the manifest"))
    for missing in sorted(set(names) - on_disk):
        out.append(Finding("WHEEL_MISSING", f"wheelhouse/{missing}", "in the manifest but not in the wheelhouse"))
    lock_lines = [l for l in (root / "requirements.lock").read_text(encoding="utf-8").replace("\\\n", " ").splitlines() if l.strip() and not l.lstrip().startswith("#")]
    locked: Dict[str, str] = {}
    for l in lock_lines:
        m = re.fullmatch(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9._!+]+)\s+--hash=sha256:([0-9a-f]{64})\s*", l)
        if not m:
            out.append(Finding("LOCK_LINE", "requirements.lock", f"not 'name==version --hash=sha256:<hex>': {l[:80]!r}"))
            continue
        key = f"{_canon(m.group(1))}=={m.group(2)}"
        if key in locked:
            out.append(Finding("LOCK_DUPLICATE", "requirements.lock", f"{key} appears twice"))
        locked[key] = m.group(3)
    seen = set()
    for w in entries:
        fn = w.get("filename", "")
        path = root / "wheelhouse" / fn
        nv = _wheel_nv(fn)
        if nv is None or fn != Path(fn).name:
            out.append(Finding("WHEEL_NAME", fn, "not a wheel file name"))
            continue
        key = f"{nv[0]}=={nv[1]}"
        seen.add(key)
        if not path.is_file():
            continue
        digest = _sha256(path)
        if w.get("sha256") != digest:
            out.append(Finding("WHEEL_DIGEST", fn, "the manifest's sha256 is not the file's"))
        if locked.get(key) != digest:
            out.append(Finding("LOCK_DIGEST", fn, "requirements.lock has no --hash that is this file's sha256"))
        try:
            with zipfile.ZipFile(path) as zf:
                if w.get("kind") == "first-party":
                    have = {n.rsplit("/", 1)[-1] for n in zf.namelist() if "/licenses/" in n and ".dist-info/" in n}
                    if not set(FAMILY_LICENCE_FILES) <= have:
                        out.append(Finding("WHEEL_LICENCE", fn, f"a first-party wheel carries the family licence texts in its dist-info/licenses ({', '.join(FAMILY_LICENCE_FILES)}); missing: {', '.join(sorted(set(FAMILY_LICENCE_FILES) - have))}"))
                meta = [n for n in zf.namelist() if re.fullmatch(r"[^/]+\.dist-info/METADATA", n)]
                if len(meta) != 1:
                    out.append(Finding("WHEEL_METADATA", fn, "exactly one dist-info/METADATA is expected"))
                else:
                    text = zf.read(meta[0]).decode("utf-8", "replace").split("\n\n", 1)[0]
                    got_name = re.search(r"^Name: (.+)$", text, re.M)
                    got_ver = re.search(r"^Version: (.+)$", text, re.M)
                    if not got_name or not got_ver or _canon(got_name.group(1).strip()) != nv[0] or got_ver.group(1).strip() != nv[1]:
                        out.append(Finding("WHEEL_METADATA", fn, "METADATA name and version are not the file name's"))
        except zipfile.BadZipFile:
            out.append(Finding("WHEEL_BAD", fn, "not a zip file"))
    for key in sorted(set(locked) - seen):
        out.append(Finding("LOCK_EXTRA", "requirements.lock", f"{key} has no wheel in the manifest"))
    if not allow_test_target:
        kinds = {w.get("kind") for w in entries}
        if not {"first-party", "pinned-upstreams", "third-party"} <= kinds:
            out.append(Finding("WHEEL_KINDS", "BUNDLE.json", "a release bundle holds first-party, pinned-upstreams and third-party wheels"))
        pinned = [w for w in entries if w.get("kind") == "pinned-upstreams"]
        pins = manifest.get("pins") or {}
        if len(pinned) != 1 or not pins:
            out.append(Finding("PINS_RECORD", "BUNDLE.json", "one pinned-upstreams wheel and a pins record are expected"))
        else:
            out += _check_pinned_wheel(root / "wheelhouse" / pinned[0]["filename"], pins)
    # --- text
    text_files = {f: (root / f).read_text(encoding="utf-8", errors="replace") for f in ("README.md", "BUNDLE.json")}
    for f, text in text_files.items():
        low = text.lower()
        for bad in FORBIDDEN:
            if bad in low:
                out.append(Finding("FORBIDDEN_TEXT", f, f"contains {bad!r}"))
        if re.search(r"(?<!not )(?<!is not )open[- ]source", low) and "not open source" not in low:
            out.append(Finding("FORBIDDEN_TEXT", f, "calls the bundle open source"))
    readme = text_files["README.md"]
    for phrase in REQUIRED_TEXT:
        if phrase not in readme:
            out.append(Finding("README_MISSING_TEXT", "README.md", f"must say {phrase!r}"))
    return out


def _check_pinned_wheel(path: Path, pins: dict) -> List[Finding]:
    out: List[Finding] = []
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            pins_entries = [n for n in names if n.endswith(".data/data/share/redevops-qa/pins.toml")]
            if len(pins_entries) != 1:
                return [Finding("PINNED_WHEEL", path.name, "exactly one share/redevops-qa/pins.toml is expected")]
            if hashlib.sha256(zf.read(pins_entries[0])).hexdigest() != pins.get("pins_toml_sha256"):
                out.append(Finding("PINNED_WHEEL", path.name, "pins.toml inside is not the one the manifest records"))
            base = pins_entries[0][: -len("pins.toml")]
            try:
                listing = json.loads(zf.read(base + "pinned-files.json"))["files"]
            except (KeyError, ValueError):
                out.append(Finding("PINNED_WHEEL", path.name, "pinned-files.json is missing or unreadable"))
            else:
                actual = {n[len(base):]: hashlib.sha256(zf.read(n)).hexdigest() for n in names if n.startswith(base + ".pinned/")}
                if listing != actual:
                    out.append(Finding("PINNED_WHEEL", path.name, "pinned-files.json does not list exactly the files of the pinned trees with their sha256"))
            for part in ("runtime-contracts", "agent-harness"):
                if not any(f"/share/redevops-qa/.pinned/" in n and f"/{part}/" in n for n in names):
                    out.append(Finding("PINNED_WHEEL", path.name, f"no pinned tree of {part}"))
    except zipfile.BadZipFile:
        out.append(Finding("WHEEL_BAD", path.name, "not a zip file"))
    return out


def main(argv: Sequence[str] = ()) -> int:
    args = list(argv) if argv else sys.argv[1:]
    allow = "--allow-test-target" in args
    paths = [a for a in args if not a.startswith("--")]
    if len(paths) != 1:
        print("usage: check_bundle.py BUNDLE_DIR [--allow-test-target]", file=sys.stderr)
        return 2
    findings = check_bundle(Path(paths[0]), allow_test_target=allow)
    for f in findings:
        print(f)
    print(f"check_bundle: {'OK' if not findings else str(len(findings)) + ' finding(s)'}")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
