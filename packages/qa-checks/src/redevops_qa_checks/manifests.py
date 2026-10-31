# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Safe, read-only loading of rendered manifests.

* YAML goes through a ``SafeLoader`` subclass that refuses anchors and aliases (a fail-closed reading: an alias expansion can
  hide or multiply content), duplicate mapping keys, and custom tags; JSON goes through ``json`` with duplicate keys refused.
* Floats become decimal strings, timestamps become ISO strings, so parsed documents are plain JSON (integers, strings,
  booleans, ``None``, lists, mappings) and can be hashed and returned without loss.
* Parsed documents are deep-frozen (``FrozenMap`` / tuples): a check program cannot mutate what another program will read.
* Nothing is written, nothing is executed, there is no network and no cluster. Symbolic links, files outside the root and
  anything that is neither a regular file nor a directory are refused.

``load_tree`` is the render helper: it loads already-rendered manifests (``.yaml``, ``.yml``, ``.json``) from a directory in
sorted path order. It never runs a renderer.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterator, List, Optional, Tuple

import yaml

from .canonical import canonical_bytes, sha256_ref
from .errors import LimitExceeded, LoadRefused, PathRefused

MANIFEST_SUFFIXES = (".yaml", ".yml", ".json")
REFERENCE_API_VERSION = "qa-checks/reference-1"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_FILES = 4000
MAX_TREE_BYTES = 64 * 1024 * 1024
MAX_DOCS_PER_FILE = 2000
MAX_DEPTH = 40
MAX_NODES_PER_FILE = 400_000
_SKIP_DIRS = frozenset({".git"})


class FrozenMap(Mapping):
    """Immutable, hashable-by-identity mapping with deterministic (insertion) order."""

    __slots__ = ("_d",)

    def __init__(self, data: Dict[str, Any]) -> None:
        object.__setattr__(self, "_d", dict(data))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("FrozenMap is read-only")

    def __getitem__(self, key: str) -> Any:
        return self._d[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._d)

    def __len__(self) -> int:
        return len(self._d)

    def __repr__(self) -> str:
        return f"FrozenMap({self._d!r})"


def freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return FrozenMap({k: freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(v) for v in value)
    return value


# -- parsing --------------------------------------------------------------------------------------------------------------

class _StrictLoader(yaml.SafeLoader):
    """SafeLoader without aliases, without duplicate keys, with a node budget."""

    def compose_node(self, parent, index):                       # type: ignore[override]
        if self.check_event(yaml.events.AliasEvent):
            event = self.peek_event()
            raise yaml.constructor.ConstructorError(None, None, "aliases are refused", event.start_mark)
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):               # type: ignore[override]
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            try:
                dup = key in seen
            except TypeError:
                raise yaml.constructor.ConstructorError(None, None, "unhashable mapping key", key_node.start_mark)
            if dup:
                raise yaml.constructor.ConstructorError(None, None, f"duplicate mapping key {key!r}", key_node.start_mark)
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


class LoadProblem(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def _normalise(value: Any, budget: List[int], depth: int = 0) -> Any:
    budget[0] += 1
    if budget[0] > MAX_NODES_PER_FILE:
        raise LoadProblem("TOO_LARGE", "document node budget exceeded")
    if depth > MAX_DEPTH:
        raise LoadProblem("TOO_DEEP", "document is nested too deeply")
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        if value != value or value in (float("inf"), float("-inf")):
            raise LoadProblem("NON_FINITE_NUMBER", "nan or infinity")
        return repr(value)
    if isinstance(value, (_dt.datetime, _dt.date)):
        return value.isoformat()
    if isinstance(value, Mapping):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            if type(k) is not str:
                if type(k) in (int, bool) or k is None or isinstance(k, (_dt.date, float)):
                    k = str(k) if type(k) is not float else repr(k)    # YAML 1.1 scalars used as keys: keep, as text
                else:
                    raise LoadProblem("BAD_KEY", f"unsupported key type {type(k).__name__}")
            if k in out:
                raise LoadProblem("DUPLICATE_KEY", f"duplicate key {k!r}")
            out[k] = _normalise(v, budget, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [_normalise(v, budget, depth + 1) for v in value]
    raise LoadProblem("UNSUPPORTED_VALUE", f"type {type(value).__name__} is not plain data")


def parse_documents(text: str, *, as_json: bool = False) -> List[Any]:
    """Parse one file's text into a list of plain documents (``None`` documents dropped)."""
    try:
        if as_json:
            def refuse_dups(pairs):
                seen: Dict[str, Any] = {}
                for k, v in pairs:
                    if k in seen:
                        raise LoadProblem("DUPLICATE_KEY", f"duplicate key {k!r}")
                    seen[k] = v
                return seen
            def refuse_const(name):
                raise LoadProblem("NON_FINITE_NUMBER", name)
            raw = [json.loads(text, object_pairs_hook=refuse_dups, parse_constant=refuse_const)]
        else:
            raw = list(yaml.load_all(text, Loader=_StrictLoader))
    except LoadProblem:
        raise
    except yaml.YAMLError as exc:
        raise LoadProblem("YAML_REFUSED", str(exc).splitlines()[0] if str(exc) else "yaml error") from None
    except (ValueError, RecursionError) as exc:
        raise LoadProblem("PARSE_REFUSED", type(exc).__name__) from None
    if len(raw) > MAX_DOCS_PER_FILE:
        raise LoadProblem("TOO_MANY_DOCUMENTS", f"more than {MAX_DOCS_PER_FILE} documents in one file")
    budget = [0]
    return [_normalise(d, budget) for d in raw if d is not None]


# -- model ----------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Manifest:
    source: str                 # path relative to the load root (posix)
    index: int                  # document index within the file
    doc: FrozenMap

    @property
    def api_version(self) -> str:
        v = self.doc.get("apiVersion")
        return v if type(v) is str else ""

    @property
    def kind(self) -> str:
        v = self.doc.get("kind")
        return v if type(v) is str else ""

    @property
    def metadata(self) -> Mapping:
        m = self.doc.get("metadata")
        return m if isinstance(m, Mapping) else FrozenMap({})

    @property
    def name(self) -> str:
        v = self.metadata.get("name")
        return v if type(v) is str else ""

    @property
    def namespace(self) -> str:
        v = self.metadata.get("namespace")
        return v if type(v) is str else ""

    @property
    def labels(self) -> Mapping:
        v = self.metadata.get("labels")
        return v if isinstance(v, Mapping) else FrozenMap({})

    def identity(self) -> Tuple[str, str, str, str]:
        return (self.api_version, self.kind, self.namespace, self.name)


@dataclass(frozen=True)
class Reference:
    """A declared-context document (``apiVersion: qa-checks/reference-1``): data a check reads next to the manifests, such as
    a declared image map or resource budget. It describes the subject's declared context; it is never an assertion's
    expected value and a check program has no way to be given one."""
    source: str
    kind: str
    name: str
    spec: FrozenMap


@dataclass(frozen=True)
class LoadError:
    source: str
    code: str
    detail: str


@dataclass(frozen=True)
class ManifestSet:
    manifests: Tuple[Manifest, ...] = ()
    references: Tuple[Reference, ...] = ()
    errors: Tuple[LoadError, ...] = ()
    files: Tuple[Tuple[str, str], ...] = ()          # (relative path, sha256 ref) of every loaded file
    ignored_files: int = 0

    def by_kind(self, kind: str) -> Tuple[Manifest, ...]:
        return tuple(m for m in self.manifests if m.kind == kind)

    def reference(self, kind: str) -> Optional[Reference]:
        found = [r for r in self.references if r.kind == kind]
        return found[0] if len(found) == 1 else None

    def references_of(self, kind: str) -> Tuple[Reference, ...]:
        return tuple(r for r in self.references if r.kind == kind)

    def merged(self, other: "ManifestSet") -> "ManifestSet":
        return ManifestSet(manifests=_sorted_manifests(self.manifests + other.manifests),
                           references=tuple(sorted(self.references + other.references, key=lambda r: (r.source, r.kind, r.name))),
                           errors=tuple(sorted(self.errors + other.errors, key=lambda e: (e.source, e.code, e.detail))),
                           files=tuple(sorted(set(self.files + other.files))), ignored_files=self.ignored_files + other.ignored_files)


def _sorted_manifests(items) -> Tuple[Manifest, ...]:
    return tuple(sorted(items, key=lambda m: (m.source, m.index)))


_EXPECTED_KEYS = frozenset({"expected", "expected_value", "expect", "predicate", "verdict"})


def _expected_key(v: Any) -> Optional[str]:
    """A reference document describes declared context; a key that looks like an expected value or verdict is refused."""
    if isinstance(v, Mapping):
        for k, item in v.items():
            if isinstance(k, str) and k.lower() in _EXPECTED_KEYS:
                return k
            found = _expected_key(item)
            if found is not None:
                return found
    elif isinstance(v, (list, tuple)):
        for item in v:
            found = _expected_key(item)
            if found is not None:
                return found
    return None


def _expand(doc: Mapping, source: str, index: int, out_m: List[Manifest], out_r: List[Reference], out_e: List[LoadError]) -> None:
    if doc.get("kind") == "List" and isinstance(doc.get("items"), list) and doc.get("apiVersion") != REFERENCE_API_VERSION:
        for item in doc["items"]:
            if isinstance(item, Mapping):
                _expand(item, source, index, out_m, out_r, out_e)
            else:
                out_e.append(LoadError(source, "NOT_A_MAPPING", "a List item is not an object"))
        return
    if doc.get("apiVersion") == REFERENCE_API_VERSION:
        md = doc.get("metadata") if isinstance(doc.get("metadata"), Mapping) else {}
        spec = doc.get("spec")
        if type(doc.get("kind")) is not str or not isinstance(spec, Mapping):
            out_e.append(LoadError(source, "REFERENCE_MALFORMED", "a reference document needs a string kind and a spec object"))
            return
        bad = _expected_key(spec)
        if bad is not None:
            out_e.append(LoadError(source, "REFERENCE_CARRIES_EXPECTED", f"key {bad!r} in a reference document"))
            return
        out_r.append(Reference(source=source, kind=doc["kind"], name=str(md.get("name", "")), spec=freeze(spec)))
        return
    out_m.append(Manifest(source=source, index=index, doc=freeze(doc)))


def load_text(text: str, source: str) -> ManifestSet:
    """Load one document stream (used for fixtures and for single files)."""
    return _from_bytes(text.encode("utf-8"), source)


def _from_bytes(data: bytes, source: str) -> ManifestSet:
    m: List[Manifest] = []
    r: List[Reference] = []
    e: List[LoadError] = []
    if len(data) > MAX_FILE_BYTES:
        return ManifestSet(errors=(LoadError(source, "TOO_LARGE", f"file is larger than {MAX_FILE_BYTES} bytes"),),
                           files=((source, sha256_ref(data)),))
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ManifestSet(errors=(LoadError(source, "NOT_UTF8", "file is not valid UTF-8"),), files=((source, sha256_ref(data)),))
    if text.startswith("﻿"):
        text = text[1:]
    try:
        docs = parse_documents(text, as_json=source.lower().endswith(".json"))
    except LoadProblem as exc:
        return ManifestSet(errors=(LoadError(source, exc.code, exc.detail),), files=((source, sha256_ref(data)),))
    for i, doc in enumerate(docs):
        if not isinstance(doc, Mapping):
            e.append(LoadError(source, "NOT_A_MAPPING", f"document {i} is not an object"))
            continue
        _expand(doc, source, i, m, r, e)
    return ManifestSet(manifests=_sorted_manifests(m), references=tuple(r), errors=tuple(e), files=((source, sha256_ref(data)),))


# -- the case tree ----------------------------------------------------------------------------------------------------------

def safe_relative(path: str) -> PurePosixPath:
    """A case-relative path: not empty, not absolute, no ``..``, no backslash, no NUL, no drive letter."""
    if type(path) is not str or not path or "\x00" in path or "\\" in path:
        raise PathRefused("a path must be a non-empty relative posix path", path=repr(path)[:80])
    p = PurePosixPath(path)
    if p.is_absolute() or any(part in ("..", ".", "") for part in path.split("/")) or (len(path) > 1 and path[1] == ":"):
        raise PathRefused("a path must be relative to the case root and must not contain '..'", path=path)
    return p


def _lstat_regular_or_dir(p: Path, rel: str) -> os.stat_result:
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise PathRefused(f"cannot stat {rel}: {type(exc).__name__}", path=rel) from None
    if stat.S_ISLNK(st.st_mode):
        raise PathRefused("symbolic links are refused", path=rel)
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        raise PathRefused("only regular files and directories are read", path=rel)
    return st


def resolve_in_root(root: Path, rel: str) -> Path:
    """The path ``root/rel``, with every component checked as not a symbolic link and inside ``root``."""
    p = safe_relative(rel)
    cur = Path(root)
    for part in p.parts:
        cur = cur / part
        _lstat_regular_or_dir(cur, rel)         # FileNotFoundError propagates: the caller decides UNRESOLVED
    return cur


def iter_tree_files(base: Path, rel_prefix: str = "") -> Iterator[Tuple[str, Path]]:
    """Every regular file under ``base`` (a directory), sorted by posix path; ``.git`` is not descended into; symlinks refused."""
    stack: List[Tuple[Path, str]] = [(base, rel_prefix)]
    found: List[Tuple[str, Path]] = []
    while stack:
        directory, prefix = stack.pop()
        try:
            names = sorted(os.listdir(directory))
        except OSError as exc:
            raise PathRefused(f"cannot list {prefix or '.'}: {type(exc).__name__}", path=prefix) from None
        for name in names:
            child = directory / name
            rel = f"{prefix}/{name}" if prefix else name
            st = _lstat_regular_or_dir(child, rel)
            if stat.S_ISDIR(st.st_mode):
                if name in _SKIP_DIRS:
                    continue
                stack.append((child, rel))
            else:
                found.append((rel, child))
                if len(found) > MAX_FILES:
                    raise LimitExceeded(f"more than {MAX_FILES} files under {rel_prefix or '.'}")
    found.sort(key=lambda t: t[0])
    yield from found


def tree_digest(root: Path, rel: str = ".") -> str:
    """sha256 over the sorted (path, file digest) pairs of a directory, or over one file's bytes. ``.git`` is excluded."""
    base = Path(root) if rel in (".", "") else resolve_in_root(root, rel)
    st = os.lstat(base)
    if stat.S_ISREG(st.st_mode):
        return sha256_ref(_read_capped(base, rel))
    h = hashlib.sha256()
    total = 0
    for r, p in iter_tree_files(base):
        data = _read_capped(p, r)
        total += len(data)
        if total > MAX_TREE_BYTES:
            raise LimitExceeded(f"tree is larger than {MAX_TREE_BYTES} bytes")
        h.update(canonical_bytes([r, sha256_ref(data)]))
        h.update(b"\n")
    return "sha256:" + h.hexdigest()


def _read_capped(p: Path, rel: str) -> bytes:
    try:
        with open(p, "rb") as fh:
            data = fh.read(MAX_TREE_BYTES + 1)
    except OSError as exc:
        raise PathRefused(f"cannot read {rel}: {type(exc).__name__}", path=rel) from None
    if len(data) > MAX_TREE_BYTES:
        raise LimitExceeded(f"{rel} is too large")
    return data


def load_tree(root: Path, rel: str = ".") -> ManifestSet:
    """Load rendered manifests: ``rel`` is a file or a directory below ``root``. Files that are not manifests by extension are
    counted in ``ignored_files`` and not read. A file that cannot be parsed is an entry in ``errors``, never skipped silently."""
    base = Path(root) if rel in (".", "") else resolve_in_root(root, rel)
    st = os.lstat(base)
    prefix = "" if rel in (".", "") else str(safe_relative(rel))
    if stat.S_ISREG(st.st_mode):
        data = _read_capped(base, prefix or base.name)
        return _from_bytes(data, prefix or base.name)
    ms: List[Manifest] = []
    rs: List[Reference] = []
    es: List[LoadError] = []
    fs: List[Tuple[str, str]] = []
    ignored = 0
    total = 0
    for r, p in iter_tree_files(base, prefix):
        if not r.lower().endswith(MANIFEST_SUFFIXES):
            ignored += 1
            continue
        data = _read_capped(p, r)
        total += len(data)
        if total > MAX_TREE_BYTES:
            raise LimitExceeded(f"manifests under {rel} are larger than {MAX_TREE_BYTES} bytes")
        one = _from_bytes(data, r)
        ms.extend(one.manifests)
        rs.extend(one.references)
        es.extend(one.errors)
        fs.extend(one.files)
    return ManifestSet(manifests=_sorted_manifests(ms), references=tuple(sorted(rs, key=lambda x: (x.source, x.kind, x.name))),
                       errors=tuple(sorted(es, key=lambda x: (x.source, x.code, x.detail))), files=tuple(sorted(fs)),
                       ignored_files=ignored)


def thaw(v: Any) -> Any:
    """Plain ``dict`` / ``list`` copy of a frozen document."""
    if isinstance(v, Mapping):
        return {k: thaw(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [thaw(x) for x in v]
    return v
