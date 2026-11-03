# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``pins.toml``: the single configuration of what the bridge and the conformance suite are pinned to.

Nothing about a dependency is hard-coded elsewhere. The file holds one or more named **pin sets** (``[sets.<name>]``);
``default_set`` names the one used unless ``REDEVOPS_QA_PIN_SET`` (or an explicit argument) selects another. A pin set
names, for each of ``contracts`` (``runtime-contracts``, qa/v1) and ``harness_qa`` (``agent_harness.qa``), a git tag or
commit, the source tree to import from, the sha256 of the installed distribution tree and the sha256 of every vector
file. Paths may be overridden per machine with ``QA_PIN_CONTRACTS_PATH`` and ``QA_PIN_HARNESS_QA_PATH`` (they apply to
the selected set); digests and commits never are. ``[conformance]`` holds settings shared by all sets.

A draft pin is marked ``temp_pin = true`` (no tag yet). ``check_forbid_temp_pin`` is what CI runs on ``main``.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
import sysconfig
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from .errors import PinMismatch, PinsInvalid

PINS_SCHEMA = "redevops-qa/pins"
PINS_VERSION = 2
PINS_FILE_ENV = "REDEVOPS_QA_PINS"
PIN_SET_ENV = "REDEVOPS_QA_PIN_SET"
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
class NotApplicable:
    """A conformance item that cannot apply at this pin set because the contracts commit pinned here predates the feature
    it checks. Declared, named and justified; the suite still runs a probe that proves the feature is absent (and fails if
    it is present), so an item can never be hidden this way."""

    check: str
    item: str
    introduced_in: str          # the contracts commit that introduces the feature (never the commit pinned in this set)
    probe: str                  # name of a probe in conformance.checks.NA_PROBES
    reason: str


@dataclass(frozen=True)
class Pins:
    path: Path
    pin_set: str
    available_sets: Tuple[str, ...]
    contracts: DependencyPin
    harness_qa: DependencyPin
    conformance: Mapping[str, Any]
    raw: Mapping[str, Any]
    not_applicable: Tuple[NotApplicable, ...] = ()
    expected_items: Mapping[str, int] = field(default_factory=dict)

    def dependency(self, name: str) -> DependencyPin:
        if name == "contracts":
            return self.contracts
        if name == "harness_qa":
            return self.harness_qa
        raise PinsInvalid(f"unknown dependency {name!r}")

    @property
    def root(self) -> Path:
        return self.path.parent


def _purelib() -> Path:
    """Where this interpreter installs pure-Python packages (a virtual environment's site-packages, for a bundle install)."""
    return Path(sysconfig.get_path("purelib")).resolve()


def installed_pins_file() -> Optional[Path]:
    """The pins file of a bundle install: ``<prefix>/share/redevops-qa/pins.toml`` (the pinned trees it names lie next to it, under ``.pinned``). ``None`` when this
    environment holds no such file."""
    candidate = Path(sys.prefix) / "share" / "redevops-qa" / "pins.toml"
    return candidate if candidate.is_file() else None


def find_pins_file(start: Optional[Path] = None) -> Path:
    env = os.environ.get(PINS_FILE_ENV)
    if env:
        return Path(env)
    here = (start or Path(__file__)).resolve()
    try:
        here.relative_to(_purelib())
        under_prefix = True
    except ValueError:
        under_prefix = False
    if under_prefix:
        # This module is installed into the interpreter's own package directory (not merely somewhere below its prefix: a checkout in /usr/src is not an installation): its pins are the ones
        # installed with it. A missing file is a failure, never a reason to look further up for another one (a stray pins.toml above the environment would name other trees).
        installed = installed_pins_file()
        if installed is None:
            raise PinsInvalid(f"this package is installed under {sys.prefix} but {Path(sys.prefix) / 'share' / 'redevops-qa' / 'pins.toml'} is missing; reinstall the bundle, or set {PINS_FILE_ENV}")
        return installed
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


_CHECK_ID = re.compile(r"CHK[1-7]")


def _expected_items(table: Any, where: str) -> Mapping[str, int]:
    """Exact number of conformance items each check has at this pin set (the completeness item compares)."""
    if not isinstance(table, dict):
        raise PinsInvalid(f"{where}.expected_items must be a table")
    for key, value in table.items():
        if not _CHECK_ID.fullmatch(key) or type(value) is not int or value < 1:
            raise PinsInvalid(f"{where}.expected_items[{key!r}] must be a positive integer for a check id CHK1..CHK7")
    return dict(sorted(table.items()))


def _not_applicable(entries: Any, contracts_commit: str, where: str) -> Tuple[NotApplicable, ...]:
    if not isinstance(entries, list):
        raise PinsInvalid(f"{where}.not_applicable must be an array of tables")
    out = []
    seen = set()
    for i, e in enumerate(entries):
        w = f"{where}.not_applicable[{i}]"
        if not isinstance(e, dict):
            raise PinsInvalid(f"{w}: expected a table")
        item = NotApplicable(check=_req(e, "check", str, w), item=_req(e, "item", str, w),
                             introduced_in=_req(e, "introduced_in", str, w), probe=_req(e, "probe", str, w),
                             reason=_req(e, "reason", str, w))
        if set(e) - {"check", "item", "introduced_in", "probe", "reason"}:
            raise PinsInvalid(f"{w}: unknown key(s) {sorted(set(e) - {'check', 'item', 'introduced_in', 'probe', 'reason'})}")
        if not _CHECK_ID.fullmatch(item.check) or not item.item or not item.reason.strip() or not item.probe:
            raise PinsInvalid(f"{w}: a check id (CHK1..CHK7), an item, a probe and a reason are required")
        if not _HEX40.fullmatch(item.introduced_in):
            raise PinsInvalid(f"{w}.introduced_in must be the full 40-hex contracts commit that introduces the feature")
        if item.introduced_in == contracts_commit:
            raise PinsInvalid(f"{w}: an item cannot be not-applicable at the contracts commit that introduces it")
        if (item.check, item.item) in seen:
            raise PinsInvalid(f"{w}: {item.check} {item.item} is declared twice")
        seen.add((item.check, item.item))
        out.append(item)
    return tuple(sorted(out, key=lambda n: (n.check, n.item)))


def load_pins(path: Optional[Path] = None, pin_set: Optional[str] = None) -> Pins:
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
    sets = _req(raw, "sets", dict, "pins")
    if not sets:
        raise PinsInvalid("pins: at least one [sets.<name>] is required")
    default = _req(raw, "default_set", str, "pins")
    chosen = pin_set or os.environ.get(PIN_SET_ENV) or default
    if chosen not in sets:
        raise PinsInvalid(f"pins: no pin set {chosen!r} (available: {', '.join(sorted(sets))})")
    table = sets[chosen]
    if not isinstance(table, dict):
        raise PinsInvalid(f"pins: [sets.{chosen}] must be a table")
    root = pins_path.resolve().parent
    contracts = _dependency("contracts", _req(table, "contracts", dict, f"sets.{chosen}"), root)
    return Pins(path=pins_path.resolve(), pin_set=chosen, available_sets=tuple(sorted(sets)), contracts=contracts,
                harness_qa=_dependency("harness_qa", _req(table, "harness_qa", dict, f"sets.{chosen}"), root),
                conformance=dict(raw.get("conformance", {})), raw=raw,
                not_applicable=_not_applicable(table.get("not_applicable", []), contracts.commit, f"sets.{chosen}"),
                expected_items=_expected_items(table.get("expected_items", {}), f"sets.{chosen}"))


def verify_trees(pins: Pins, *, require_git: bool = False) -> None:
    """Fail unless both pinned trees are exactly what ``pins.toml`` says. With ``require_git`` each tree must be a git
    checkout whose ``HEAD`` is the pinned commit and whose working tree is clean (what CI does after fetching by SHA)."""
    from . import deps
    problems = []
    for dep in (pins.contracts, pins.harness_qa):
        if require_git and not (dep.resolved_path / ".git").exists():
            problems.append(f"{dep.name}: {dep.resolved_path} is not a git checkout (PIN_NOT_A_CHECKOUT)")
        problems.extend(f"{code}: {message}" for code, message in deps.pin_problems(dep))
    if problems:
        raise PinMismatch("; ".join(problems), problems=problems)


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
    parser.add_argument("--pin-set", default=None)
    parser.add_argument("--forbid-temp-pin", action="store_true")
    parser.add_argument("--verify-trees", action="store_true",
                        help="check the pinned source trees against pins.toml (commit, tree digest, vector digests)")
    parser.add_argument("--require-git", action="store_true",
                        help="with --verify-trees: each tree must be a clean git checkout at the pinned commit")
    parser.add_argument("--github-output", action="store_true",
                        help="print repo/commit/path of both dependencies as key=value lines for a CI step output")
    args = parser.parse_args(argv)
    try:
        pins = load_pins(Path(args.file) if args.file else None, args.pin_set)
        if args.forbid_temp_pin:
            check_forbid_temp_pin(pins)
        if args.verify_trees:
            verify_trees(pins, require_git=args.require_git)
        if args.github_output:
            for dep in (pins.contracts, pins.harness_qa):
                print(f"{dep.name}_repo={dep.repo}")
                print(f"{dep.name}_commit={dep.commit}")
                print(f"{dep.name}_path={dep.source_path}")
            print(f"pin_set={pins.pin_set}")
            return 0
    except (PinsInvalid, PinMismatch) as exc:
        print(f"FAIL {exc.code}: {exc.message}")
        return 1
    print(f"OK pins.toml (set {pins.pin_set}) is well formed" + ("" if not args.forbid_temp_pin else " and has no TEMP-PIN"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
