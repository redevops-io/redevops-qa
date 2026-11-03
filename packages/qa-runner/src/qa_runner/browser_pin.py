# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The browser pin: what ``bundle/browser.lock.json`` says the installed Chromium is, and the code that checks an installation against it.

Standard library only (``install-browser.sh`` runs it with the installation's own interpreter, ``doctor`` and ``run`` import it). Two things are pinned, for ONE Playwright
version on Linux x86_64:

* the archives the Playwright installer downloads for ``chromium`` (Chrome for Testing, Chrome Headless Shell, FFmpeg): file name, URLs, size and sha256. ``stage`` downloads
  exactly these archives and refuses one whose sha256 or size is not the pinned one BEFORE anything is unpacked;
* the installed tree: every directory (mode) and file (mode, size, sha256) of the three install directories ``playwright install chromium`` writes below
  ``PLAYWRIGHT_BROWSERS_PATH``. ``verify`` compares a browsers directory with it: a changed, missing or extra file, a changed mode, a link, a missing install directory.

What this does not cover, and says so: the operating system libraries the browser loads (apt, ``--with-deps``), anything outside the three install directories, the Playwright
CDN being reachable, and a change made after the check (``verify`` is a check at one moment, not a guard). ``DEPENDENCIES_VALIDATED`` is a zero-byte marker Playwright writes itself
the first time it launches the browser; it is the only file allowed in an install directory that the lock does not list, and only when it is empty.

Command line (used by ``bundle/install-browser.sh``)::

    python -I -m qa_runner.browser_pin verify --lock FILE --browsers DIR [--json]
    python -I -m qa_runner.browser_pin stage  --lock FILE --browsers DIR --staging DIR [--mirror BASE]
    python -I -m qa_runner.browser_pin commit --lock FILE --browsers DIR --staging DIR
    python -I -m qa_runner.browser_pin urls   --lock FILE [--fallbacks-only]

Exit status: 0 ok; 1 the check or the install failed (the message names what was expected and what was found); 2 usage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

LOCK_NAME = "browser.lock.json"
LOCK_SCHEMA = "redevops-qa/browser-lock"
LOCK_VERSION = "1.0"
TARGET_PLATFORM = "linux-x86_64"
MARKER = "INSTALLATION_COMPLETE"                 # written by Playwright (and by ``stage``) when an install directory is complete; part of the pinned tree
OPTIONAL_MARKERS = ("DEPENDENCIES_VALIDATED",)     # written by Playwright on first launch; allowed (empty) beside the pinned files
_HEX = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_MODE = re.compile(r"[0-7]{4}")
CHUNK = 1 << 20
USER_AGENT = "redevops-qa-install-browser"


class LockError(ValueError):
    """The lock file is unusable (unreadable, wrong schema, inconsistent)."""


class InstallError(RuntimeError):
    """The browser could not be installed as pinned; nothing was left behind by the failing step."""


@dataclass(frozen=True)
class Archive:
    name: str                     # the Playwright browser name (chromium, chromium-headless-shell, ffmpeg)
    dir: str                      # the install directory below PLAYWRIGHT_BROWSERS_PATH (chromium-1248, ...)
    file: str                     # the archive's file name
    urls: Tuple[str, ...]         # the URLs Playwright downloads it from, in its order
    sha256: str
    size: int


@dataclass(frozen=True)
class Lock:
    digest: str                                   # sha256 of the lock file's bytes
    playwright_version: str
    browsers_json_sha256: str                     # sha256 of playwright/driver/package/browsers.json of the pinned Playwright wheel
    revision: str
    browser_version: str
    archives: Tuple[Archive, ...]
    directories: Dict[str, int]                   # relative path -> permission bits
    files: Dict[str, Tuple[int, int, str]]        # relative path -> (permission bits, size, sha256)
    tree_sha256: str

    def dirs(self) -> List[str]:
        return [a.dir for a in self.archives]

    def files_under(self, install_dir: str) -> int:
        return sum(1 for p in self.files if p.startswith(install_dir + "/"))


@dataclass(frozen=True)
class Problem:
    code: str          # NOT_INSTALLED | MISSING | CHANGED | SIZE | MODE | EXTRA | TYPE
    path: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code} {self.path}: {self.detail}"


# ------------------------------------------------------------------------------------------------------------------------------------- the lock file
def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise LockError(f"duplicate key {k!r}")
        out[k] = v
    return out


def tree_digest(directories: Dict[str, int], files: Dict[str, Tuple[int, int, str]]) -> str:
    doc = {"directories": {k: format(v, "04o") for k, v in sorted(directories.items())},
           "files": {k: [format(v[0], "04o"), v[1], v[2]] for k, v in sorted(files.items())}}
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _safe_rel(path: str) -> bool:
    return bool(path) and not path.startswith("/") and "\\" not in path and "\x00" not in path and all(p not in ("", ".", "..") for p in path.split("/"))


def parse_lock(data: bytes) -> Lock:
    """Parse and validate a lock file; anything that is not exactly the documented shape raises ``LockError``."""
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError) as exc:
        raise LockError(f"not JSON ({type(exc).__name__}: {str(exc)[:80]})") from None
    if not isinstance(doc, dict) or doc.get("schema") != LOCK_SCHEMA or doc.get("schema_version") != LOCK_VERSION:
        raise LockError(f"not a {LOCK_SCHEMA} {LOCK_VERSION} document")
    if doc.get("target") != {"platform": TARGET_PLATFORM}:
        raise LockError(f"the lock is for {TARGET_PLATFORM} and nothing else")
    pw, br = doc.get("playwright"), doc.get("browser")
    if not (isinstance(pw, dict) and isinstance(pw.get("version"), str) and pw["version"] and isinstance(pw.get("browsers_json_sha256"), str) and _HEX.fullmatch(pw["browsers_json_sha256"])):
        raise LockError("playwright needs a version and the sha256 of its browsers.json")
    if not (isinstance(br, dict) and br.get("name") == "chromium" and isinstance(br.get("revision"), str) and br["revision"].isdigit() and isinstance(br.get("browser_version"), str) and br["browser_version"]):
        raise LockError("browser needs the name chromium, a numeric revision and a browser_version")
    archives: List[Archive] = []
    raw_archives = doc.get("archives")
    if not isinstance(raw_archives, list) or not raw_archives:
        raise LockError("archives is a non-empty list")
    for a in raw_archives:
        if not (isinstance(a, dict) and set(a) == {"name", "dir", "file", "urls", "sha256", "size"}):
            raise LockError("an archive has exactly: name, dir, file, urls, sha256, size")
        if not (isinstance(a["name"], str) and _NAME.fullmatch(a["name"]) and isinstance(a["dir"], str) and _NAME.fullmatch(a["dir"]) and isinstance(a["file"], str)
                and _NAME.fullmatch(a["file"]) and a["file"].endswith(".zip")):
            raise LockError(f"an archive has a name, dir or file that is not a plain name: {str(a.get('file'))[:40]!r}")
        if not (isinstance(a["urls"], list) and a["urls"] and all(isinstance(u, str) and u.startswith("https://") and u.rsplit("/", 1)[-1] == a["file"] for u in a["urls"])):
            raise LockError(f"the urls of {a['file']} are https URLs that end in the archive's file name")
        if not (isinstance(a["sha256"], str) and _HEX.fullmatch(a["sha256"]) and isinstance(a["size"], int) and not isinstance(a["size"], bool) and a["size"] > 0):
            raise LockError(f"{a['file']} needs a sha256 and a positive size")
        archives.append(Archive(a["name"], a["dir"], a["file"], tuple(a["urls"]), a["sha256"], a["size"]))
    if len({a.dir for a in archives}) != len(archives) or len({a.file for a in archives}) != len(archives):
        raise LockError("two archives share an install directory or a file name")
    tree = doc.get("tree")
    if not (isinstance(tree, dict) and set(tree) == {"directories", "files"} and isinstance(tree["directories"], dict) and isinstance(tree["files"], dict)):
        raise LockError("tree has directories and files")
    dirs: Dict[str, int] = {}
    for rel, mode in tree["directories"].items():
        if not (_safe_rel(rel) and isinstance(mode, str) and _MODE.fullmatch(mode)):
            raise LockError(f"a directory entry is not a safe relative path with a four-digit octal mode: {rel[:60]!r}")
        dirs[rel] = int(mode, 8)
    files: Dict[str, Tuple[int, int, str]] = {}
    for rel, ent in tree["files"].items():
        if not (_safe_rel(rel) and isinstance(ent, list) and len(ent) == 3 and isinstance(ent[0], str) and _MODE.fullmatch(ent[0]) and isinstance(ent[1], int)
                and not isinstance(ent[1], bool) and ent[1] >= 0 and isinstance(ent[2], str) and _HEX.fullmatch(ent[2])):
            raise LockError(f"a file entry is not [mode, size, sha256] under a safe relative path: {rel[:60]!r}")
        files[rel] = (int(ent[0], 8), ent[1], ent[2])
    roots = {a.dir for a in archives}
    for rel in list(dirs) + list(files):
        if rel.split("/", 1)[0] not in roots or rel in roots and rel in files:
            raise LockError(f"{rel[:60]!r} is not below one of the install directories")
    for a in archives:
        if a.dir not in dirs:
            raise LockError(f"the install directory {a.dir} has no directory entry")
        if files.get(f"{a.dir}/{MARKER}", (0, -1, ""))[1] != 0:
            raise LockError(f"the install directory {a.dir} must list an empty {MARKER}")
    parents = {p.rsplit("/", 1)[0] for p in list(files) + list(dirs) if "/" in p}
    if parents - set(dirs):
        raise LockError(f"a directory is used but not listed: {sorted(parents - set(dirs))[0][:60]!r}")
    digest = tree_digest(dirs, files)
    if doc.get("tree_sha256") != digest:
        raise LockError("tree_sha256 is not the digest of the tree entries")
    return Lock(hashlib.sha256(data).hexdigest(), pw["version"], pw["browsers_json_sha256"], br["revision"], br["browser_version"], tuple(archives), dirs, files, digest)


def load_lock(path: os.PathLike) -> Lock:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise LockError(f"cannot read {path}: {type(exc).__name__}") from None
    return parse_lock(data)


def render_lock(doc: dict) -> str:
    """The canonical text of a lock document: sorted keys, two-space indent, one line per tree entry (a reviewable diff)."""
    def line(value) -> str:
        return json.dumps(value, sort_keys=True, ensure_ascii=True)
    head = {k: v for k, v in doc.items() if k != "tree"}
    text = json.dumps(head, indent=2, sort_keys=True, ensure_ascii=True)
    tree = doc["tree"]
    dirs = ",\n".join(f"      {line(k)}: {line(v)}" for k, v in sorted(tree["directories"].items()))
    files = ",\n".join(f"      {line(k)}: {line(v)}" for k, v in sorted(tree["files"].items()))
    body = '  "tree": {\n    "directories": {\n' + dirs + '\n    },\n    "files": {\n' + files + "\n    }\n  }"
    assert text.endswith("\n}")
    return text[:-2] + ",\n" + body + "\n}\n"


# ------------------------------------------------------------------------------------------------------------------------------------- reading a tree
def sha256_file(path: os.PathLike) -> str:
    with open(path, "rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def _walk(base: Path, rel: str) -> Iterator[Tuple[str, os.stat_result]]:
    """Every entry below ``base/rel`` (itself first), by lstat, never following a link, in a stable order."""
    top = base / rel
    yield rel, os.lstat(top)
    if not stat.S_ISDIR(os.lstat(top).st_mode):
        return
    with os.scandir(top) as it:
        entries = sorted(it, key=lambda e: e.name)
    for e in entries:
        child = f"{rel}/{e.name}"
        st = e.stat(follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            yield from _walk(base, child)
        else:
            yield child, st


def scan_tree(browsers: Path, install_dirs: Sequence[str]) -> Tuple[Dict[str, int], Dict[str, Tuple[int, int, str]]]:
    """The directories and files below the install directories as a lock lists them (used to MAKE a lock; ``verify_tree`` is the checker). Links and special files are refused."""
    dirs: Dict[str, int] = {}
    files: Dict[str, Tuple[int, int, str]] = {}
    for d in install_dirs:
        for rel, st in _walk(browsers, d):
            if stat.S_ISDIR(st.st_mode):
                dirs[rel] = stat.S_IMODE(st.st_mode)
            elif stat.S_ISREG(st.st_mode):
                if rel.rsplit("/", 1)[-1] in OPTIONAL_MARKERS and rel.count("/") == 1:
                    continue
                files[rel] = (stat.S_IMODE(st.st_mode), st.st_size, sha256_file(browsers / rel))
            else:
                raise LockError(f"{rel} is a link or a special file; the lock lists directories and regular files only")
    return dirs, files


def verify_tree(browsers: os.PathLike, lock: Lock, install_dirs: Optional[Sequence[str]] = None) -> List[Problem]:
    """Compare the install directories of ``browsers`` with the lock; return every difference (an empty list means the tree is exactly the pinned one).
    Files are hashed only when their size is the pinned size; nothing is followed through a link; nothing is written."""
    base = Path(browsers)
    problems: List[Problem] = []
    for d in (install_dirs if install_dirs is not None else lock.dirs()):
        try:
            top = os.lstat(base / d)
        except FileNotFoundError:
            problems.append(Problem("NOT_INSTALLED", d, "the install directory does not exist"))
            continue
        except OSError as exc:
            problems.append(Problem("NOT_INSTALLED", d, f"cannot be read ({type(exc).__name__})"))
            continue
        if not stat.S_ISDIR(top.st_mode):
            problems.append(Problem("TYPE", d, "is a link or not a directory; the pinned install directory is a real directory"))
            continue
        seen = set()
        try:
            for rel, st in _walk(base, d):
                seen.add(rel)
                mode = stat.S_IMODE(st.st_mode)
                if stat.S_ISDIR(st.st_mode):
                    want = lock.directories.get(rel)
                    if want is None:
                        problems.append(Problem("EXTRA", rel, "a directory the lock does not list"))
                    elif want != mode:
                        problems.append(Problem("MODE", rel, f"directory mode {mode:04o}, pinned {want:04o}"))
                elif stat.S_ISREG(st.st_mode):
                    entry = lock.files.get(rel)
                    if entry is None:
                        if rel.count("/") == 1 and rel.rsplit("/", 1)[-1] in OPTIONAL_MARKERS and st.st_size == 0:
                            continue
                        problems.append(Problem("EXTRA", rel, "a file the lock does not list"))
                        continue
                    want_mode, want_size, want_hash = entry
                    if st.st_size != want_size:
                        problems.append(Problem("SIZE", rel, f"{st.st_size} bytes, pinned {want_size}"))
                    elif sha256_file(base / rel) != want_hash:
                        problems.append(Problem("CHANGED", rel, f"sha256 differs from the pinned {want_hash}"))
                    if mode != want_mode:
                        problems.append(Problem("MODE", rel, f"mode {mode:04o}, pinned {want_mode:04o}"))
                else:
                    problems.append(Problem("TYPE", rel, "a link or a special file; the pinned tree has none"))
        except OSError as exc:
            problems.append(Problem("MISSING", d, f"the directory could not be read completely ({type(exc).__name__})"))
        for rel in sorted(list(lock.directories) + list(lock.files)):
            if rel.split("/", 1)[0] == d and rel not in seen:
                problems.append(Problem("MISSING", rel, "pinned but not there"))
    return problems


def summarise(problems: Sequence[Problem], limit: int = 5) -> str:
    counts: Dict[str, int] = {}
    for p in problems:
        counts[p.code] = counts.get(p.code, 0) + 1
    head = ", ".join(f"{n} {c}" for c, n in sorted(counts.items()))
    return f"{len(problems)} difference(s) from the pin ({head}): " + "; ".join(str(p) for p in problems[:limit]) + ("; ..." if len(problems) > limit else "")


# ------------------------------------------------------------------------------------------------------------------------------------- downloading
def archive_urls(archive: Archive, mirror: Optional[str]) -> List[str]:
    if mirror is None:
        return list(archive.urls)
    base = mirror
    if base.startswith("/"):
        base = Path(base).resolve().as_uri()
    if not re.match(r"(https?|file)://", base):
        raise InstallError(f"--mirror takes an http(s):// or file:// base URL or an absolute directory, not {base[:40]!r}")
    return [base.rstrip("/") + "/" + archive.file]


def fetch_archive(archive: Archive, dest: Path, mirror: Optional[str] = None, log: Callable[[str], None] = lambda s: None,
                  opener: Callable = urllib.request.urlopen) -> str:
    """Download ``archive`` to ``dest`` and return the URL that served the pinned bytes. A candidate whose size or sha256 is not the pinned one is discarded (and named in the error
    if no URL serves the pinned bytes); reading stops one byte past the pinned size, so a host cannot fill the disk."""
    attempts: List[str] = []
    for url in archive_urls(archive, mirror):
        log(f"downloading {archive.file} ({archive.size} bytes) from {url}")
        h = hashlib.sha256()
        got = 0
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with opener(req, timeout=120) as resp, open(dest, "wb") as out:
                while got <= archive.size:
                    chunk = resp.read(min(CHUNK, archive.size + 1 - got))
                    if not chunk:
                        break
                    h.update(chunk)
                    out.write(chunk)
                    got += len(chunk)
        except (OSError, urllib.error.URLError, ValueError) as exc:
            attempts.append(f"{url}: the download failed ({type(exc).__name__})")
            continue
        if got == archive.size and h.hexdigest() == archive.sha256:
            return url
        shown = "more than the pinned size" if got > archive.size else f"{got} bytes"
        attempts.append(f"{url}: expected sha256 {archive.sha256} ({archive.size} bytes), got sha256 {h.hexdigest()} ({shown})")
        try:
            dest.unlink()
        except OSError:
            pass
    raise InstallError(f"{archive.file} does not match its pin; nothing was unpacked or installed:\n  " + "\n  ".join(attempts))


def verify_archive(path: Path, archive: Archive) -> None:
    size = path.stat().st_size
    digest = sha256_file(path)
    if size != archive.size or digest != archive.sha256:
        raise InstallError(f"{archive.file} does not match its pin: expected sha256 {archive.sha256} ({archive.size} bytes), got sha256 {digest} ({size} bytes)")


def extract_archive(archive_path: Path, dest: Path, archive: Archive, lock: Lock) -> None:
    """Unpack a verified archive into ``dest`` (the install directory), the way the Playwright installer does: entry names as they are, modes from the zip, no link, nothing outside ``dest``,
    nothing the lock does not list. Directory modes are the zip's own (755 when the zip has no directory entry) and are set explicitly, whatever the umask."""
    with zipfile.ZipFile(archive_path) as zf:
        seen = set()
        for info in zf.infolist():
            name = info.filename
            rel_in = name.rstrip("/") if name.endswith("/") else name
            if not _safe_rel(rel_in):
                raise InstallError(f"{archive.file} has an entry with an unsafe name: {name[:60]!r}")
            rel = f"{archive.dir}/{rel_in}"
            unix = info.external_attr >> 16
            kind = stat.S_IFMT(unix)
            if info.is_dir():
                if rel not in lock.directories:
                    raise InstallError(f"{archive.file} has a directory the lock does not list: {rel}")
                path = dest / rel_in
                path.mkdir(parents=True, exist_ok=True)
                os.chmod(path, (unix & 0o7777) if kind == stat.S_IFDIR and unix & 0o777 else 0o755)
                continue
            if kind not in (0, stat.S_IFREG):
                raise InstallError(f"{archive.file} has an entry that is not a regular file or a directory: {name[:60]!r}")
            if rel not in lock.files or rel in seen:
                raise InstallError(f"{archive.file} has a file the lock does not list (or lists twice): {rel}")
            seen.add(rel)
            mode = (unix & 0o7777) if unix else 0o644
            if mode & 0o7000:
                raise InstallError(f"{archive.file} has a file with a setuid, setgid or sticky bit: {name[:60]!r}")
            path = dest / rel_in
            for parent in reversed(path.relative_to(dest).parents):
                if str(parent) != "." and not (dest / parent).exists():
                    (dest / parent).mkdir()
                    os.chmod(dest / parent, 0o755)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as out, zf.open(info) as src:
                shutil.copyfileobj(src, out, CHUNK)
                os.fchmod(out.fileno(), mode)


# ------------------------------------------------------------------------------------------------------------------------------------- installing
def stage(lock: Lock, browsers: Path, staging: Path, mirror: Optional[str] = None, log: Callable[[str], None] = lambda s: None,
          opener: Callable = urllib.request.urlopen) -> List[str]:
    """Download, verify and unpack every pinned archive into ``staging`` (which must not exist) and verify the staged tree against the lock; install directories that are already
    in ``browsers`` are verified in place and left alone, and one that does not match is an error (nothing is replaced). Returns the install directories staged. On any failure the
    staging directory is removed and ``browsers`` is as it was."""
    if os.path.lexists(staging):
        raise InstallError(f"{staging} already exists")
    staged: List[str] = []
    try:
        staging.mkdir(mode=0o700, parents=False)
        (staging / "downloads").mkdir(mode=0o700)
        for a in lock.archives:
            final = browsers / a.dir
            if os.path.lexists(final):
                bad = verify_tree(browsers, lock, [a.dir])
                if bad:
                    raise InstallError(f"{final} exists and is not the pinned build, so it was not touched: {summarise(bad)}. Remove that directory and run the browser step again.")
                log(f"{a.dir}: already installed and identical to the pin; nothing to download")
                continue
            archive_path = staging / "downloads" / a.file
            url = fetch_archive(a, archive_path, mirror, log, opener)
            verify_archive(archive_path, a)                     # the bytes on disk, once more, before anything is unpacked
            log(f"{a.file}: sha256 {a.sha256} matches the pin (served by {url})")
            (staging / a.dir).mkdir(mode=0o755)
            os.chmod(staging / a.dir, lock.directories[a.dir])
            extract_archive(archive_path, staging / a.dir, a, lock)
            marker = staging / a.dir / MARKER
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.fchmod(fd, lock.files[f"{a.dir}/{MARKER}"][0])
            os.close(fd)
            bad = verify_tree(staging, lock, [a.dir])
            if bad:
                raise InstallError(f"the unpacked {a.dir} is not the pinned tree: {summarise(bad)}")
            log(f"{a.dir}: {lock.files_under(a.dir)} files unpacked and identical to the pinned tree")
            staged.append(a.dir)
        shutil.rmtree(staging / "downloads")
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return staged


def commit(lock: Lock, browsers: Path, staging: Path) -> List[str]:
    """Move the staged install directories into ``browsers`` (one rename each, on the same file system); on a failure the ones already moved are removed again."""
    moved: List[str] = []
    try:
        for a in lock.archives:
            src = staging / a.dir
            if not os.path.lexists(src):
                continue
            os.rename(src, browsers / a.dir)
            moved.append(a.dir)
    except BaseException:
        for d in moved:
            shutil.rmtree(browsers / d, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return moved


def check_urls(lock: Lock, log: Callable[[str], None] = lambda s: None, *, fallbacks_only: bool = False, opener: Callable = urllib.request.urlopen) -> List[str]:
    """Download every URL the lock lists for every archive, one by one, and report whether each serves the pinned bytes (no file is kept). Returns the URLs that do not: an unreachable URL, a
    wrong size or a wrong sha256. ``fallbacks_only`` skips the first URL of each archive (the one the install uses, and the one the install already verified)."""
    import tempfile
    bad: List[str] = []
    with tempfile.TemporaryDirectory(prefix="browser-pin-urls-") as tmp:
        for a in lock.archives:
            for i, url in enumerate(a.urls):
                if fallbacks_only and i == 0:
                    continue
                single = Archive(a.name, a.dir, a.file, (url,), a.sha256, a.size)
                try:
                    fetch_archive(single, Path(tmp) / a.file, None, lambda s: None, opener)
                except InstallError as exc:
                    bad.append(url)
                    log(f"MISMATCH {url}: {str(exc).splitlines()[-1].strip()}")
                else:
                    log(f"same bytes {url}: sha256 {a.sha256} ({a.size} bytes)")
                    (Path(tmp) / a.file).unlink()
    return bad


# ------------------------------------------------------------------------------------------------------------------------------------- the command line
def main(argv: Optional[Sequence[str]] = None, out=None, err=None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    p = argparse.ArgumentParser(prog="python -m qa_runner.browser_pin", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="command", required=True)
    sp = sub.add_parser("urls", help="download every URL of the lock and say whether it serves the pinned bytes")
    sp.add_argument("--lock", required=True)
    sp.add_argument("--fallbacks-only", action="store_true")
    for name in ("verify", "stage", "commit"):
        sp = sub.add_parser(name)
        sp.add_argument("--lock", required=True)
        sp.add_argument("--browsers", required=True)
        if name != "verify":
            sp.add_argument("--staging", required=True)
        if name == "stage":
            sp.add_argument("--mirror", default=None)
        if name == "verify":
            sp.add_argument("--json", action="store_true")
    try:
        args = p.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return 2 if exc.code else 0
    try:
        lock = load_lock(args.lock)
    except LockError as exc:
        print(f"browser_pin: the lock file is not usable: {exc}", file=err)
        return 1
    if args.command == "urls":
        bad = check_urls(lock, lambda s: print(s, file=out), fallbacks_only=args.fallbacks_only)
        print(f"browser_pin: {len(bad)} URL(s) do not serve the pinned bytes" if bad else "browser_pin: every URL checked serves the pinned bytes", file=err if bad else out)
        return 1 if bad else 0
    browsers = Path(args.browsers)
    try:
        if args.command == "verify":
            problems = verify_tree(browsers, lock)
            if args.json:
                out.write(json.dumps({"ok": not problems, "problems": [vars(x) for x in problems]}, indent=2, sort_keys=True) + "\n")
            elif problems:
                print("browser_pin: " + summarise(problems, 20), file=err)
            else:
                print(f"browser_pin: {len(lock.files)} files in {len(lock.archives)} install directories are exactly the pinned Chromium {lock.browser_version} (Playwright revision {lock.revision}); "
                      f"lock sha256 {lock.digest}", file=out)
            return 1 if problems else 0
        staging = Path(args.staging)
        if args.command == "stage":
            for d in stage(lock, browsers, staging, args.mirror, lambda s: print(s, file=out)):
                print(f"staged {d}", file=out)
            return 0
        for d in commit(lock, browsers, staging):
            print(f"installed {d}", file=out)
        return 0
    except InstallError as exc:
        print(f"browser_pin: {exc}", file=err)
        return 1
    except OSError as exc:
        print(f"browser_pin: {type(exc).__name__}: {exc.strerror or exc}", file=err)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
