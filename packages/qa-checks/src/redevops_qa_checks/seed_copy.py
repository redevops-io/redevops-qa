# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``seed-copy``: make a *copy* of a manifest directory and apply one named, documented, deterministic transformation to the copy.

The tool exists to produce development variants with a known defect from a development corpus. Its rules, each a typed refusal:

* The input is a plain tree: regular files and directories only, no symbolic links, no special files, no version-control metadata
  (``.git`` and the like) anywhere in it. It is never modified: its digest is taken before and after the copy and a difference
  removes the copy and fails.
* The output is a new directory the tool creates itself inside a *work root* that the tool created (a directory carrying the
  tool's sentinel, owned by the user, not writable by others, not inside a version-control checkout and not inside the source
  tree). An existing output path is refused; nothing is ever written to a path under a directory the tool did not create.
* A path (source, work root or output) with a component that names a protected reference corpus (one of the reserved
  marker words in ``PROTECTED_MARKERS``) is refused, and so is a source tree that contains a marker file.
* The transformation comes from a small library of generic edits (replace a digest with a tag, remove a securityContext field,
  change a port, remove a probe, remove resource limits). Each has a name, a version, a description and a parameter schema,
  runs on YAML text line by line, is deterministic, and fails with ``NO_MATCH`` instead of changing nothing.
* What changed is recorded: a unified diff and a JSON record (source and output tree digests, the transformation, the files
  changed with before and after digests) are written next to the copy, and the copy carries a marker file saying it is a
  development variant.

Only the copy, the diff and the record are written. There is no option to write anywhere else and no option to edit in place.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .canonical import canonical_bytes, sha256_ref
from .errors import CheckError
from .manifests import MAX_FILES, MAX_TREE_BYTES, tree_digest

WORK_ROOT_SENTINEL = ".qa-seed-work-root"
WORK_ROOT_SCHEMA = "qa-checks/seed-work-root/1"
DEV_MARKER_FILE = ".qa-dev-variant"
RECORD_SCHEMA = "qa-checks/seed-record/1"
VCS_NAMES = frozenset({".git", ".hg", ".svn", ".bzr", "_darcs", ".fossil", ".gitmodules", "CVS"})
#: words that mark a path as a protected reference corpus (matched on whole path-component tokens, case-insensitively)
PROTECTED_MARKERS: Tuple[str, ...] = ("frozen", "sealed", "heldout", "held-out", "baseline-freeze", "pinned-head")
MARKER_FILES = frozenset({"FROZEN_HEAD", ".frozen-head", ".frozen", "SEALED", ".sealed"})
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_MARKER_RE = re.compile(r"(?:^|[^a-z0-9])(" + "|".join(re.escape(m) for m in sorted(PROTECTED_MARKERS, key=len, reverse=True)) + r")(?:$|[^a-z0-9])", re.I)
MAX_SEED_FILE_BYTES = 4 * 1024 * 1024


class SeedRefused(CheckError):
    """A typed refusal of ``seed-copy``; ``details['reason']`` is the stable reason code."""
    code = "SEED_REFUSED"

    def __init__(self, reason: str, message: str = "", **details: Any) -> None:
        super().__init__(message or reason, reason=reason, **details)
        self.reason = reason


# -- transformations -----------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Transformation:
    id: str
    version: str
    description: str
    params: Mapping[str, str]                     # parameter name -> description (all parameters are listed here)
    #: ``apply(text, params, skip, take) -> (new text, sites found, edits made)``: sites are numbered in file order; the sites with
    #: index in [skip, skip + take) are edited. The driver numbers sites across files in sorted path order.
    apply: Callable[[str, Mapping[str, Any], int, int], Tuple[str, int, int]]


_INDENT = re.compile(r"^(\s*)")


def _indent(line: str) -> int:
    return len(_INDENT.match(line).group(1).replace("\t", "    "))


def _line_sites(text: str, pattern: "re.Pattern[str]", rewrite: Callable[["re.Match[str]"], str], skip: int, take: int) -> Tuple[str, int, int]:
    out: List[str] = []
    idx = edits = 0
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        eol = line[len(body):]
        m = pattern.match(body)
        if m:
            if idx >= skip and edits < take:
                out.append(rewrite(m) + eol)
                edits += 1
            else:
                out.append(line)
            idx += 1
        else:
            out.append(line)
    return "".join(out), idx, edits


def _t_digest_to_tag(text: str, params: Mapping[str, Any], skip: int, take: int) -> Tuple[str, int, int]:
    tag = params["tag"]
    pat = re.compile(r"^(\s*(?:-\s*)?image:\s*[\"']?)([^\s\"'@#]+)@sha256:[0-9a-f]{64}([\"']?\s*(?:#.*)?)$")
    return _line_sites(text, pat, lambda m: f"{m.group(1)}{m.group(2)}:{tag}{m.group(3)}", skip, take)


def _block_length(lines: List[str], start: int) -> int:
    """Number of lines (the key line and its more-indented children) of the block starting at ``start``."""
    base = _indent(lines[start])
    end = start + 1
    while end < len(lines) and (not lines[end].strip() or _indent(lines[end]) > base):
        end += 1
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1
    return end - start


def _remove_key_in_blocks(text: str, parent_key: str, child_key: str, skip: int, take: int) -> Tuple[str, int, int]:
    """Remove ``child_key`` (with its children) from the ``parent_key`` blocks that contain it."""
    lines = text.splitlines(keepends=True)
    out: List[str] = []
    idx = edits = i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        if re.match(rf"^(\s*)(?:-\s*)?{re.escape(parent_key)}:\s*(?:#.*)?$", line.rstrip("\r\n")):
            base = _indent(line)
            j = i
            while j < len(lines) and (not lines[j].strip() or _indent(lines[j]) > base):
                j += 1
            block = lines[i:j]
            hit = next((k for k, bl in enumerate(block) if bl.strip() and re.match(rf"^\s*{re.escape(child_key)}:", bl)), None)
            if hit is not None:
                if idx >= skip and edits < take:
                    n = _block_length(block, hit)
                    block = block[:hit] + block[hit + n:]
                    edits += 1
                idx += 1
            out.extend(block)
            i = j
    return "".join(out), idx, edits


_SC_FIELDS = ("runAsNonRoot", "runAsUser", "runAsGroup", "allowPrivilegeEscalation", "readOnlyRootFilesystem", "privileged", "seccompProfile",
              "capabilities", "procMount", "seLinuxOptions")


def _t_remove_sc_field(text: str, params: Mapping[str, Any], skip: int, take: int) -> Tuple[str, int, int]:
    return _remove_key_in_blocks(text, "securityContext", params["field"], skip, take)


def _t_change_port(text: str, params: Mapping[str, Any], skip: int, take: int) -> Tuple[str, int, int]:
    frm, to = params["from_port"], params["to_port"]
    pat = re.compile(rf"^(\s*(?:-\s*)?(?:containerPort|port|targetPort|hostPort):\s*){frm}(\s*(?:#.*)?)$")
    return _line_sites(text, pat, lambda m: f"{m.group(1)}{to}{m.group(2)}", skip, take)


def _t_remove_probe(text: str, params: Mapping[str, Any], skip: int, take: int) -> Tuple[str, int, int]:
    key = params["probe"]
    lines = text.splitlines(keepends=True)
    out: List[str] = []
    idx = edits = i = 0
    while i < len(lines):
        if re.match(rf"^\s*(?:-\s*)?{re.escape(key)}:", lines[i]):
            if idx >= skip and edits < take:
                i += _block_length(lines, i)
                edits += 1
                idx += 1
                continue
            idx += 1
        out.append(lines[i])
        i += 1
    return "".join(out), idx, edits


def _t_remove_limits(text: str, params: Mapping[str, Any], skip: int, take: int) -> Tuple[str, int, int]:
    return _remove_key_in_blocks(text, "resources", "limits", skip, take)


LIBRARY: Mapping[str, Transformation] = {t.id: t for t in (
    Transformation("replace-digest-with-tag", "1.0.0",
                   "Replace an image reference pinned by digest (repo@sha256:...) with a tag (repo:TAG) on `image:` lines.",
                   {"tag": "the tag to use (not an empty string)", "occurrence": "1-based index of the site to change, or \"all\" (default 1)",
                    "path_prefix": "optional: only files whose path starts with this"}, _t_digest_to_tag),
    Transformation("remove-security-context-field", "1.0.0",
                   "Remove one field (and its children) from `securityContext:` blocks.",
                   {"field": "one of " + ", ".join(_SC_FIELDS), "occurrence": "1-based index of the block, or \"all\" (default 1)",
                    "path_prefix": "optional: only files whose path starts with this"}, _t_remove_sc_field),
    Transformation("change-port", "1.0.0",
                   "Change a port number on `containerPort`, `port`, `targetPort` and `hostPort` lines.",
                   {"from_port": "the port to find (1-65535)", "to_port": "the port to write (1-65535, different)",
                    "occurrence": "1-based index of the site, or \"all\" (default 1)", "path_prefix": "optional: only files whose path starts with this"},
                   _t_change_port),
    Transformation("remove-probe", "1.0.0",
                   "Remove a probe declaration (and its children).",
                   {"probe": "livenessProbe, readinessProbe or startupProbe", "occurrence": "1-based index of the site, or \"all\" (default 1)",
                    "path_prefix": "optional: only files whose path starts with this"}, _t_remove_probe),
    Transformation("remove-resource-limits", "1.0.0",
                   "Remove the `limits:` block from `resources:` blocks.",
                   {"occurrence": "1-based index of the block, or \"all\" (default 1)", "path_prefix": "optional: only files whose path starts with this"},
                   _t_remove_limits),
)}


def _check_params(t: Transformation, raw: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) - set(t.params):
        raise SeedRefused("PARAMS_INVALID", f"{t.id} takes {sorted(t.params)}")
    p = dict(raw)
    occ = p.get("occurrence", 1)
    if occ != "all" and (type(occ) is not int or isinstance(occ, bool) or occ < 1):
        raise SeedRefused("PARAMS_INVALID", "occurrence is a positive integer or \"all\"")
    prefix = p.get("path_prefix", "")
    if type(prefix) is not str or ".." in prefix.split("/") or prefix.startswith("/") or "\\" in prefix or "\x00" in prefix:
        raise SeedRefused("PARAMS_INVALID", "path_prefix is a relative path prefix")
    p["occurrence"], p["path_prefix"] = occ, prefix
    if t.id == "replace-digest-with-tag":
        tag = p.get("tag")
        if type(tag) is not str or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}", tag):
            raise SeedRefused("PARAMS_INVALID", "tag is a valid image tag")
    elif t.id == "remove-security-context-field":
        if p.get("field") not in _SC_FIELDS:
            raise SeedRefused("PARAMS_INVALID", "field is not one the library can remove")
    elif t.id == "change-port":
        a, b = p.get("from_port"), p.get("to_port")
        for v in (a, b):
            if type(v) is not int or isinstance(v, bool) or not 1 <= v <= 65535:
                raise SeedRefused("PARAMS_INVALID", "ports are integers from 1 to 65535")
        if a == b:
            raise SeedRefused("PARAMS_INVALID", "from_port and to_port must differ")
    elif t.id == "remove-probe":
        if p.get("probe") not in ("livenessProbe", "readinessProbe", "startupProbe"):
            raise SeedRefused("PARAMS_INVALID", "probe is livenessProbe, readinessProbe or startupProbe")
    return p


# -- paths ---------------------------------------------------------------------------------------------------------------------------------

def has_marker(path: Path) -> Optional[str]:
    for part in Path(os.path.abspath(path)).parts:
        m = _MARKER_RE.search(part)
        if m:
            return m.group(1).lower()
    return None


def _in_vcs_checkout(path: Path) -> bool:
    cur = Path(os.path.abspath(path))
    for p in [cur, *cur.parents]:
        if any((p / n).exists() or (p / n).is_symlink() for n in (".git", ".hg", ".svn")):
            return True
    return False


def files_digest(files: Sequence[Tuple[str, bytes, int]]) -> str:
    """The digest ``tree_digest`` gives a tree holding exactly these files (so bytes read can be compared with the tree on disk)."""
    h = hashlib.sha256()
    for rel, data, _mode in sorted(files, key=lambda t: t[0]):
        h.update(canonical_bytes([rel, sha256_ref(data)]))
        h.update(b"\n")
    return "sha256:" + h.hexdigest()


def _inside(child: Path, parent: Path) -> bool:
    try:
        Path(os.path.realpath(child)).relative_to(Path(os.path.realpath(parent)))
        return True
    except ValueError:
        return False


def create_work_root(path: Path) -> Path:
    """Create a new work root (mode 0700, with the tool's sentinel). The path must not exist; its parent must be a real directory."""
    p = Path(os.path.abspath(path))
    marker = has_marker(p)
    if marker:
        raise SeedRefused("OUTPUT_PROTECTED_MARKER", "the path names a protected corpus", marker=marker)
    if os.path.lexists(p):
        raise SeedRefused("OUTPUT_EXISTS", "the work root path already exists")
    parent = p.parent
    if not parent.is_dir() or parent.is_symlink():
        raise SeedRefused("WORK_ROOT_PARENT_INVALID", "the parent of the work root must be an existing real directory")
    if _in_vcs_checkout(parent):
        raise SeedRefused("WORK_ROOT_IN_VCS", "a work root is never created inside a version-control checkout")
    os.mkdir(p, 0o700)
    os.chmod(p, 0o700)
    (p / WORK_ROOT_SENTINEL).write_text(json.dumps({"schema": WORK_ROOT_SCHEMA, "uid": os.getuid()}), encoding="utf-8")
    return p


def check_work_root(path: Path) -> Path:
    p = Path(os.path.abspath(path))
    marker = has_marker(p)
    if marker:
        raise SeedRefused("OUTPUT_PROTECTED_MARKER", "the path names a protected corpus", marker=marker)
    try:
        st = os.lstat(p)
    except OSError:
        raise SeedRefused("WORK_ROOT_NOT_CREATED_BY_TOOL", "the work root does not exist") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
        raise SeedRefused("WORK_ROOT_NOT_CREATED_BY_TOOL", "the work root is not a private directory of this user")
    try:
        sentinel = json.loads((p / WORK_ROOT_SENTINEL).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SeedRefused("WORK_ROOT_NOT_CREATED_BY_TOOL", "the directory was not created by this tool") from None
    if not isinstance(sentinel, dict) or sentinel.get("schema") != WORK_ROOT_SCHEMA or sentinel.get("uid") != os.getuid():
        raise SeedRefused("WORK_ROOT_NOT_CREATED_BY_TOOL", "the directory was not created by this tool")
    if _in_vcs_checkout(p):
        raise SeedRefused("WORK_ROOT_IN_VCS", "the work root is inside a version-control checkout")
    return p


# -- reading the source ----------------------------------------------------------------------------------------------------------------------

def read_source(source: Path) -> List[Tuple[str, bytes, int]]:
    """``(relative path, bytes, mode)`` of every file of a plain tree, sorted by path. Refuses anything that is not a plain tree."""
    src = Path(os.path.abspath(source))
    marker = has_marker(src)
    if marker:
        raise SeedRefused("SOURCE_PROTECTED_MARKER", "the source path names a protected corpus", marker=marker)
    try:
        st = os.lstat(src)
    except OSError:
        raise SeedRefused("SOURCE_MISSING", "the source does not exist") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise SeedRefused("SOURCE_NOT_DIRECTORY", "the source is a real directory")
    files: List[Tuple[str, bytes, int]] = []
    total = 0
    stack = [(src, "")]
    while stack:
        d, pre = stack.pop()
        for name in sorted(os.listdir(d)):
            rel = f"{pre}/{name}" if pre else name
            full = d / name
            if name in VCS_NAMES:
                raise SeedRefused("SOURCE_HAS_VCS_METADATA", "the source contains version-control metadata", path=rel)
            if name in MARKER_FILES:
                raise SeedRefused("SOURCE_PROTECTED_MARKER", "the source contains a protected-corpus marker file", path=rel)
            s = os.lstat(full)
            if stat.S_ISLNK(s.st_mode):
                raise SeedRefused("SOURCE_HAS_SYMLINK", "the source contains a symbolic link", path=rel)
            if stat.S_ISDIR(s.st_mode):
                stack.append((full, rel))
            elif stat.S_ISREG(s.st_mode):
                if s.st_size > MAX_SEED_FILE_BYTES:
                    raise SeedRefused("SOURCE_TOO_LARGE", "a source file is too large", path=rel)
                total += s.st_size
                if total > MAX_TREE_BYTES or len(files) >= MAX_FILES:
                    raise SeedRefused("SOURCE_TOO_LARGE", "the source tree is too large")
                with open(full, "rb") as fh:
                    files.append((rel, fh.read(), 0o755 if s.st_mode & 0o111 else 0o644))
            else:
                raise SeedRefused("SOURCE_SPECIAL_FILE", "the source contains a file that is neither regular nor a directory", path=rel)
    files.sort(key=lambda t: t[0])
    return files


# -- the operation -----------------------------------------------------------------------------------------------------------------------------------

def seed_copy(source: Path, work_root: Path, name: str, transformation: str, params: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Copy ``source`` to ``work_root/name``, apply the transformation to the copy, write the diff and the record, return the record."""
    t = LIBRARY.get(transformation)
    if t is None:
        raise SeedRefused("TRANSFORMATION_UNKNOWN", "unknown transformation", transformation=str(transformation)[:60])
    p = _check_params(t, params or {})
    if type(name) is not str or not _NAME.fullmatch(name):
        raise SeedRefused("NAME_INVALID", "the output name is a short lower-case name")
    root = check_work_root(work_root)
    src = Path(os.path.abspath(source))
    out = root / name
    if has_marker(out):
        raise SeedRefused("OUTPUT_PROTECTED_MARKER", "the output path names a protected corpus")
    if os.path.lexists(out) or os.path.lexists(root / f"{name}.diff") or os.path.lexists(root / f"{name}.record.json"):
        raise SeedRefused("OUTPUT_EXISTS", "an output with this name already exists")
    if _inside(out, src) or _inside(root, src):
        raise SeedRefused("WORK_ROOT_INSIDE_SOURCE", "nothing is written inside a source tree")
    if _inside(src, root):
        raise SeedRefused("SOURCE_INSIDE_WORK_ROOT", "the source lies inside the work root")
    files = read_source(src)
    before = files_digest(files)                      # what was read; compared with the tree on disk after the copy
    prefix = p["path_prefix"]
    every = p["occurrence"] == "all"
    skip = 0 if every else p["occurrence"] - 1
    take = 10 ** 9 if every else 1
    changed: List[Dict[str, Any]] = []
    diffs: List[str] = []
    new_files: List[Tuple[str, bytes, int]] = []
    for rel, data, mode in files:
        new = data
        if take > 0 and rel.lower().endswith((".yaml", ".yml")) and (not prefix or rel.startswith(prefix)):
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            if text is not None:
                new_text, sites, edits = t.apply(text, p, skip, take)
                skip = max(0, skip - sites)
                take -= edits
                if edits and new_text != text:
                    new = new_text.encode("utf-8")
        if new != data:
            changed.append({"path": rel, "before_sha256": sha256_ref(data), "after_sha256": sha256_ref(new)})
            diffs.append("".join(difflib.unified_diff(data.decode("utf-8").splitlines(keepends=True), new.decode("utf-8").splitlines(keepends=True),
                                                      fromfile=f"a/{rel}", tofile=f"b/{rel}", n=3)))
        new_files.append((rel, new, mode))
    if not changed:
        raise SeedRefused("NO_MATCH", "the transformation matched nothing in the source", transformation=transformation)
    # create the copy: a new directory made by the tool, nothing else touched
    os.mkdir(out, 0o700)
    try:
        for rel, data, mode in new_files:
            target = out / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(data)
            os.chmod(target, mode)
            os.utime(target, (0, 0))
        record_core = {"schema": RECORD_SCHEMA, "dev": True, "transformation": {"id": t.id, "version": t.version, "description": t.description},
                       "params": {k: p[k] for k in sorted(p)}, "name": name, "source_tree_sha256": before, "files_changed": changed,
                       "files_total": len(new_files)}
        diff_text = "".join(diffs)
        marker_doc = {"dev": True, "note": "a development variant made by seed-copy; not part of any sealed or reference set",
                      "diff_sha256": sha256_ref(diff_text.encode("utf-8"))}
        (out / DEV_MARKER_FILE).write_text(json.dumps(marker_doc, sort_keys=True), encoding="utf-8")
        os.chmod(out / DEV_MARKER_FILE, 0o644)
        os.utime(out / DEV_MARKER_FILE, (0, 0))
        after_source = tree_digest(src)
        if after_source != before:
            raise SeedRefused("SOURCE_CHANGED_DURING_COPY", "the source changed while it was being copied")
        record = {**record_core, "output_tree_sha256": tree_digest(out), "diff_sha256": marker_doc["diff_sha256"]}
        (root / f"{name}.diff").write_text(diff_text, encoding="utf-8")
        (root / f"{name}.record.json").write_text(json.dumps(record, sort_keys=True, indent=1) + "\n", encoding="utf-8")
        return record
    except BaseException:
        _remove_own(out)
        for suffix in (".diff", ".record.json"):
            try:
                os.unlink(root / f"{name}{suffix}")
            except OSError:
                pass
        raise


def _remove_own(path: Path) -> None:
    """Remove a directory this call created (only ever the copy)."""
    for dirpath, dirnames, filenames in os.walk(path, topdown=False):
        for f in filenames:
            os.unlink(os.path.join(dirpath, f))
        for d in dirnames:
            os.rmdir(os.path.join(dirpath, d))
    os.rmdir(path)
