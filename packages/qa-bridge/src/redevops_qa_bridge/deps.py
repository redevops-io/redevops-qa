# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Guarded access to the two pinned dependencies.

The bridge never imports ``runtime_contracts`` or ``agent_harness.qa`` at module import time, so importing the bridge
itself cannot succeed or fail on their presence. Every use goes through :func:`contracts_qa` / :func:`neutral_qa`,
which raise :class:`DependencyUnavailable` (a failure, never a skip) when an import fails.

:func:`prepare_paths` puts the pinned source trees from ``pins.toml`` first on ``sys.path``. :func:`verify_pins`
proves that what was imported is what the pins name: the module file lies inside the pinned tree, the distribution
digest and every vector file digest match, no vector file matching an addendum glob is unlisted, the declared version
matches the tree's ``pyproject.toml`` and, when the tree is a git checkout, ``HEAD`` is the pinned commit.
"""
from __future__ import annotations

import importlib
import subprocess
import sys
import tomllib
from pathlib import Path
from types import ModuleType
from typing import Dict, List, Tuple

from .errors import DependencyUnavailable, PinMismatch
from .pins import DependencyPin, Pins, sha256_file, tree_digest

_MODULES = {"contracts": "runtime_contracts.qa", "harness_qa": "agent_harness.qa"}


def prepare_paths(pins: Pins) -> None:
    """Prepend the pinned source roots to ``sys.path`` (idempotent). Already-imported modules are not reloaded;
    :func:`verify_pins` then fails if they came from somewhere else."""
    for dep in (pins.harness_qa, pins.contracts):
        root = str(dep.resolved_path)
        if dep.resolved_path.is_dir() and root not in sys.path:
            sys.path.insert(0, root)


def _import(name: str) -> ModuleType:
    module = _MODULES[name]
    try:
        return importlib.import_module(module)
    except Exception as exc:    # ImportError, SyntaxError, the Python-floor guard in agent_harness.qa ...
        raise DependencyUnavailable(f"{module} cannot be imported: {type(exc).__name__}: {exc}",
                                    dependency=name, module=module) from exc


def contracts_qa() -> ModuleType:
    """``runtime_contracts.qa`` (the qa/v1 contracts)."""
    return _import("contracts")


def neutral_qa() -> ModuleType:
    """``agent_harness.qa`` (the harness neutral module)."""
    return _import("harness_qa")


def contracts_module(name: str) -> ModuleType:
    """A submodule of ``runtime_contracts.qa`` (``base``, ``errors``, ``registry`` ...), imported on demand."""
    return _submodule("contracts", name)


def contracts_package_module(name: str) -> ModuleType:
    """A module of the top-level ``runtime_contracts`` package outside ``qa`` (for example ``canonical``)."""
    _import("contracts")
    full = f"{_MODULES['contracts'].rsplit('.', 1)[0]}.{name}"
    try:
        return importlib.import_module(full)
    except Exception as exc:
        raise DependencyUnavailable(f"{full} cannot be imported: {type(exc).__name__}: {exc}",
                                    dependency="contracts", module=full) from exc


def neutral_module(name: str) -> ModuleType:
    """A submodule of ``agent_harness.qa`` (``verifier``, ``policy``, ``specstore`` ...), imported on demand."""
    return _submodule("harness_qa", name)


def _submodule(dependency: str, name: str) -> ModuleType:
    _import(dependency)
    full = f"{_MODULES[dependency]}.{name}"
    try:
        return importlib.import_module(full)
    except Exception as exc:
        raise DependencyUnavailable(f"{full} cannot be imported: {type(exc).__name__}: {exc}",
                                    dependency=dependency, module=full) from exc


def availability() -> Dict[str, bool]:
    out = {}
    for name in _MODULES:
        try:
            _import(name)
            out[name] = True
        except DependencyUnavailable:
            out[name] = False
    return out


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _git_head(root: Path) -> str:
    if not (root / ".git").exists():
        return ""
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True,
                             timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def _git_dirty(root: Path) -> bool:
    """True when ``root`` is a git checkout with uncommitted or untracked changes (bytecode ignored by .gitignore)."""
    if not (root / ".git").exists():
        return False
    try:
        out = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], capture_output=True, text=True,
                             timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return True
    return out.returncode != 0 or bool(out.stdout.strip())


def tree_version(dep: DependencyPin) -> str:
    """``[project].version`` of the pinned tree's ``pyproject.toml`` ('' when absent)."""
    pyproject = dep.resolved_path / "pyproject.toml"
    if not pyproject.is_file():
        return ""
    with open(pyproject, "rb") as handle:
        return str(tomllib.load(handle).get("project", {}).get("version", ""))


def addendum_files(dep: DependencyPin) -> List[str]:
    found = set()
    for pattern in dep.addendum_globs:
        for p in dep.resolved_path.glob(pattern):
            if p.is_file():
                found.add(p.relative_to(dep.resolved_path).as_posix())
    return sorted(found)


def current_state(dep: DependencyPin) -> Dict[str, object]:
    """What is on disk now for one dependency (digests, vector file hashes, git head, version)."""
    state: Dict[str, object] = {"path_exists": dep.resolved_path.is_dir()}
    if not dep.resolved_path.is_dir():
        return state
    try:
        state["distribution_sha256"] = tree_digest(dep.resolved_path, dep.distribution_paths)
    except PinMismatch:
        state["distribution_sha256"] = ""
    files = {}
    for rel in sorted(set(dep.vector_files) | set(addendum_files(dep))):
        p = dep.resolved_path / rel
        files[rel] = sha256_file(p) if p.is_file() else ""
    state["vector_files"] = files
    state["unlisted_addendum_files"] = [f for f in addendum_files(dep) if f not in dep.vector_files]
    state["git_head"] = _git_head(dep.resolved_path)
    state["tree_version"] = tree_version(dep)
    state["git_dirty"] = _git_dirty(dep.resolved_path)
    return state


def pin_problems(dep: DependencyPin) -> List[Tuple[str, str]]:
    """``(code, message)`` for every way the tree on disk differs from the pin. Empty means exact."""
    problems: List[Tuple[str, str]] = []
    state = current_state(dep)
    if not state["path_exists"]:
        return [("PIN_SOURCE_MISSING", f"{dep.name}: source tree {dep.resolved_path} does not exist")]
    if state["distribution_sha256"] != dep.distribution_sha256:
        problems.append(("PIN_DIGEST_MISMATCH", f"{dep.name}: distribution digest {state['distribution_sha256']!r} "
                         f"is not the pinned {dep.distribution_sha256!r}"))
    for rel, expected in dep.vector_files.items():
        got = state["vector_files"].get(rel, "")
        if got != expected:
            problems.append(("PIN_VECTOR_MISMATCH", f"{dep.name}: {rel} has sha256 {got!r}, pinned {expected!r}"))
    for rel in state["unlisted_addendum_files"]:
        problems.append(("PIN_VECTOR_UNLISTED", f"{dep.name}: {rel} matches an addendum glob but is not listed in "
                         "pins.toml; add it with its sha256 (the pin is stale)"))
    head = state["git_head"]
    if head and head != dep.commit:
        problems.append(("PIN_COMMIT_MISMATCH", f"{dep.name}: checkout is at {head}, pinned {dep.commit}"))
    if state["git_dirty"]:
        problems.append(("PIN_TREE_DIRTY", f"{dep.name}: the checkout has uncommitted or untracked changes"))
    version = state["tree_version"]
    if version and version != dep.version:
        problems.append(("PIN_VERSION_MISMATCH", f"{dep.name}: tree declares version {version!r}, pinned {dep.version!r}"))
    return problems


def imported_from_pin(dep: DependencyPin) -> List[Tuple[str, str]]:
    """The imported package must live inside the pinned tree (a floating install elsewhere is a failure)."""
    module = importlib.import_module(dep.package)
    file = getattr(module, "__file__", None)
    if not file or not _inside(Path(file), dep.resolved_path):
        return [("PIN_PATH_MISMATCH", f"{dep.name}: {dep.package} was imported from {file!r}, not from the pinned "
                 f"tree {dep.resolved_path}")]
    return []


def verify_pins(pins: Pins) -> None:
    """Raise :class:`PinMismatch` (``details['problems']``) unless both dependencies are exactly the pinned ones."""
    prepare_paths(pins)
    problems: List[Tuple[str, str]] = []
    for dep in (pins.contracts, pins.harness_qa):
        problems.extend(pin_problems(dep))
        try:
            _import(dep.name)
        except DependencyUnavailable:
            raise
        problems.extend(imported_from_pin(dep))
    if problems:
        raise PinMismatch("; ".join(f"{c}: {m}" for c, m in problems),
                          problems=[{"code": c, "message": m} for c, m in problems])
