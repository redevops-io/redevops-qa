# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``pins.toml``: the single configuration of what the bridge and the conformance suite are pinned to.

Nothing about a dependency is hard-coded elsewhere. For each of ``contracts`` (``runtime-contracts``, qa/v1) and
``harness_qa`` (``agent_harness.qa``) the file lists a git tag or commit, the source tree to import from, the sha256 of
the installed distribution tree and the sha256 of every vector file. Paths may be overridden per machine with
``QA_PIN_CONTRACTS_PATH`` and ``QA_PIN_HARNESS_QA_PATH``; digests and commits never are.

A draft pin is marked ``temp_pin = true`` (no tag yet). ``check_forbid_temp_pin`` is what CI runs on ``main``.
"""
from __future__ import annotations

import hashlib
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from .errors import PinMismatch, PinsInvalid

PINS_SCHEMA = "redevops-qa/pins"
PINS_VERSION = 1
PINS_FILE_ENV = "REDEVOPS_QA_PINS"
PATH_ENV = {"contracts": "QA_PIN_CONTRACTS_PATH", "harness_qa": "QA_PIN_HARNESS_QA_PATH"}

_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache"}
_SKIP_SUFFIXES = {".pyc", ".pyo"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_digest(root: Path, relative_dirs: Tuple[str, ...]) -> str:
    """sha256 over ``<relative path>\\0<file sha256>\\n`` of every file below ``relative_dirs`` (sorted, bytecode and
    VCS metadata skipped). The same walk is used whether a tree is a checkout or an installed package directory."""
    lines = []
    for rel in relative_dirs:
        base = root / rel
        if not base.is_dir():
            raise PinMismatch(f"distribution path {rel!r} is not a directory under {root}", path=rel)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
            for name in sorted(filenames):
                p = Path(dirpath) / name
                if p.suffix in _SKIP_SUFFIXES:
                    continue
                lines.append(f"{p.relative_to(root).as_posix()}\0{sha256_file(p)}\n")
    return hashlib.sha256("".join(sorted(lines)).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DependencyPin:
    name: str                                   # "contracts" or "harness_qa"
    repo: str
    version: str
    tag: str                                    # "" while temp_pin
    commit: str                                 # full 40-hex sha
    temp_pin: bool
    package: str                                # import name of the top-level package
    source_path: str                            # as written in pins.toml
    resolved_path: Path                         # after the environment override
    distribution_paths: Tuple[str, ...]
    distribution_sha256: str
    vector_files: Mapping[str, str]             # path relative to the source tree -> sha256
    addendum_globs: Tuple[str, ...] = ()
    base_pin: str = ""                          # harness only: the commit the QA branch was built from
    extra: Mapping[str, Any] = field(default_factory=dict)

    def vector_path(self, relative: str) -> Path:
        return self.resolved_path / relative


@dataclass(frozen=True)
class Pins:
    path: Path
    contracts: DependencyPin
    harness_qa: DependencyPin
    conformance: Mapping[str, Any]
    raw: Mapping[str, Any]

    def dependency(self, name: str) -> DependencyPin:
        if name == "contracts":
            return self.contracts
        if name == "harness_qa":
            return self.harness_qa
        raise PinsInvalid(f"unknown dependency {name!r}")

    @property
    def root(self) -> Path:
        return self.path.parent


def find_pins_file(start: Optional[Path] = None) -> Path:
    env = os.environ.get(PINS_FILE_ENV)
    if env:
        return Path(env)
    here = (start or Path(__file__)).resolve()
    for parent in [here, *here.parents]:
        candidate = parent / "pins.toml"
        if candidate.is_file():
            return candidate
    raise PinsInvalid("pins.toml not found (set REDEVOPS_QA_PINS or run inside the repository)")


def _req(table: Mapping[str, Any], key: str, kind: type, where: str) -> Any:
    if key not in table:
        raise PinsInvalid(f"{where}: missing {key!r}")
    value = table[key]
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise PinsInvalid(f"{where}.{key}: expected {kind.__name__}")
    return value


def _dependency(name: str, table: Mapping[str, Any], root: Path) -> DependencyPin:
    where = f"[{name}]"
    temp_pin = _req(table, "temp_pin", bool, where)
    tag = _req(table, "tag", str, where)
    commit = _req(table, "commit", str, where)
    if not _HEX40.fullmatch(commit):
        raise PinsInvalid(f"{where}.commit must be a full 40-hex commit sha")
    if temp_pin and tag:
        raise PinsInvalid(f"{where}: a TEMP-PIN carries no tag")
    if not temp_pin and not tag:
        raise PinsInvalid(f"{where}: a release pin needs a git tag")
    digest = _req(table, "distribution_sha256", str, where)
    if not _HEX64.fullmatch(digest):
        raise PinsInvalid(f"{where}.distribution_sha256 must be 64 lowercase hex digits")
    vectors = _req(table, "vector_files", dict, where)
    if not vectors:
        raise PinsInvalid(f"{where}.vector_files must list at least one vector file")
    for rel, sha in vectors.items():
        if not isinstance(sha, str) or not _HEX64.fullmatch(sha):
            raise PinsInvalid(f"{where}.vector_files[{rel!r}] must be 64 lowercase hex digits")
        if rel.startswith("/") or ".." in Path(rel).parts:
            raise PinsInvalid(f"{where}.vector_files[{rel!r}] must be a relative path inside the tree")
    paths = _req(table, "distribution_paths", list, where)
    if not paths or not all(isinstance(p, str) and p and not p.startswith("/") and ".." not in Path(p).parts
                            for p in paths):
        raise PinsInvalid(f"{where}.distribution_paths must be relative directory names")
    source = _req(table, "source_path", str, where)
    override = os.environ.get(PATH_ENV[name])
    resolved = Path(override) if override else (root / source)
    base_pin = table.get("base_pin", "")
    if name == "harness_qa" and not (isinstance(base_pin, str) and re.fullmatch(r"[0-9a-f]{40}", base_pin)):
        raise PinsInvalid(f"{where}.base_pin must be the full 40-hex base commit")
    known = {"repo", "version", "tag", "commit", "temp_pin", "package", "source_path", "distribution_paths",
             "distribution_sha256", "vector_files", "addendum_globs", "base_pin"}
    return DependencyPin(
        name=name, repo=_req(table, "repo", str, where), version=_req(table, "version", str, where), tag=tag,
        commit=commit, temp_pin=temp_pin, package=_req(table, "package", str, where), source_path=source,
        resolved_path=resolved, distribution_paths=tuple(paths), distribution_sha256=digest,
        vector_files=dict(sorted(vectors.items())), addendum_globs=tuple(table.get("addendum_globs", ())),
        base_pin=base_pin, extra={k: v for k, v in table.items() if k not in known})


def load_pins(path: Optional[Path] = None) -> Pins:
    pins_path = Path(path) if path is not None else find_pins_file()
    try:
        with open(pins_path, "rb") as handle:
            raw = tomllib.load(handle)
    except FileNotFoundError:
        raise PinsInvalid(f"pins file {pins_path} does not exist") from None
    except tomllib.TOMLDecodeError as exc:
        raise PinsInvalid(f"pins file is not valid TOML: {exc}") from None
    if raw.get("schema") != PINS_SCHEMA or raw.get("version") != PINS_VERSION:
        raise PinsInvalid(f"pins file must declare schema = {PINS_SCHEMA!r} and version = {PINS_VERSION}")
    root = pins_path.resolve().parent
    return Pins(path=pins_path.resolve(), contracts=_dependency("contracts", _req(raw, "contracts", dict, "pins"), root),
                harness_qa=_dependency("harness_qa", _req(raw, "harness_qa", dict, "pins"), root),
                conformance=dict(raw.get("conformance", {})), raw=raw)


def check_forbid_temp_pin(pins: Pins) -> None:
    """CI on ``main``: a TEMP-PIN may not be merged."""
    for dep in (pins.contracts, pins.harness_qa):
        if dep.temp_pin:
            raise PinMismatch(f"{dep.name} is a TEMP-PIN (commit {dep.commit}); main requires release tags",
                              dependency=dep.name)


def main(argv: Optional[list] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="python -m redevops_qa_bridge.pins")
    parser.add_argument("--file", default=None)
    parser.add_argument("--forbid-temp-pin", action="store_true")
    args = parser.parse_args(argv)
    try:
        pins = load_pins(Path(args.file) if args.file else None)
        if args.forbid_temp_pin:
            check_forbid_temp_pin(pins)
    except (PinsInvalid, PinMismatch) as exc:
        print(f"FAIL {exc.code}: {exc.message}")
        return 1
    print("OK pins.toml is well formed" + ("" if not args.forbid_temp_pin else " and has no TEMP-PIN"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
