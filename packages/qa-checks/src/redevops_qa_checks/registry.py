# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The registry of individually hashed check programs.

A check program is a module under ``programs/`` that declares ``PROGRAM_ID``, ``PROGRAM_VERSION``, ``DESCRIPTION`` and
``SUPPORT`` (the helper files it uses, relative to the package; optional ``FRAMEWORK`` names further framework files to hash) and defines ``run(data) -> observed value``. Its
``program_hash`` is the sha256 of a *source bundle*: a header naming the program id, version and entry point, the program
module, each declared support file, and the framework files every program depends on (loader, canonical serialisation, input
type). A change to any of them changes the hash, so a hash frozen in an assertion pins the whole behaviour. Line endings are
normalised (CRLF to LF) before hashing. A module may also define ``run_counts`` (a compact projection of its result), which is
registered as its own program, ``<id>.counts``, with its own hash: assertions compare one observed value with one expected
value, so a small value is what a gating assertion can name.

The registry is immutable once built. ``resolve`` is the only way to obtain a program for execution and it verifies
``{id, version, program_hash}`` first: an unregistered program raises ``ProgramUnregistered`` and a hash that differs from the
registered one raises ``ProgramHashMismatch``, in both cases before any program code is called. ``registered_program_hash``
is the read-only lookup the harness verifier uses for the same decision.

Programs are first-party code, not a sandbox target. Registration still refuses a program module whose syntax tree imports
outside a small allow-list (no file system, network, clock, randomness, process or environment access), calls dynamic
execution or introspection builtins, or touches dunder attributes. The refusal is a lint-level guard against accidents, not a
security boundary.

``run`` accepts the program input and nothing else: there is no parameter through which an expected value or a verdict can
arrive, and the returned value is checked to be plain JSON without floats and without verdict-shaped keys.
"""
from __future__ import annotations

import ast
import importlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

from .canonical import sha256_ref, to_plain
from .errors import (ExpectedValueRefused, OutputRefused, ProgramHashMismatch, ProgramRefused, ProgramUnregistered)
from .program_input import ProgramInput

PACKAGE_ROOT = Path(__file__).resolve().parent
FRAMEWORK_FILES = ("canonical.py", "manifests.py", "program_input.py")
#: further framework files a program may declare in ``FRAMEWORK`` (hashed with it; not part of the purity lint, they read files)
HASHED_FRAMEWORK = ("image_store.py", "tierk/argv.py", "tierk/drivers.py", "tierk/collectors.py", "tierk/probes.py", "tierk/subnets.py",
                    "tierk/connectivity.py")
ID_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*")
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")

#: modules a program (and its support files) may import
SUPPORT_MODULES = frozenset({"_common", "_image", "_cluster", "_connectivity"})
ALLOWED_IMPORTS = frozenset({"__future__", "re", "fractions", "ipaddress", "typing", "collections", "itertools", "math"})
FORBIDDEN_CALLS = frozenset({"open", "exec", "eval", "compile", "__import__", "globals", "locals", "vars", "getattr", "setattr",
                             "delattr", "breakpoint", "input", "memoryview"})
#: key names an observed value may not carry (a check observes; the verifier judges)
FORBIDDEN_OUTPUT_KEYS = frozenset({"verdict", "pass", "passed", "fail", "failed", "ok", "success", "expected", "expect",
                                   "compliant", "compliance", "violation", "violations", "finding", "findings", "severity"})
#: argument names that mean an expected value or a verdict
FORBIDDEN_ARGUMENT_NAMES = frozenset({"expected", "expected_value", "expect", "predicate", "verdict", "threshold"})


def normalised_source(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def source_bundle(files: Iterable[Tuple[str, bytes]]) -> bytes:
    parts = []
    for rel, data in sorted(files):
        body = normalised_source(data)
        parts.append(f"{rel}\n{len(body)}\n".encode("utf-8") + body + b"\n")
    return b"".join(parts)


def bundle_hash(files: Iterable[Tuple[str, bytes]]) -> str:
    return sha256_ref(source_bundle(files))


def assert_pure_source(rel: str, source: bytes) -> None:
    """Refuse a program source file that imports outside the allow-list or reaches for dynamic or dunder features."""
    try:
        tree = ast.parse(source, filename=rel)
    except SyntaxError as exc:
        raise ProgramRefused(f"{rel}: syntax error at line {exc.lineno}") from None
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in ALLOWED_IMPORTS:
                    raise ProgramRefused(f"{rel}: import of {alias.name!r} is not allowed in a check program")
        elif isinstance(node, ast.ImportFrom):
            if node.level == 1 and node.module in SUPPORT_MODULES:
                continue
            if node.level == 1 and node.module is None and all(a.name in SUPPORT_MODULES for a in node.names):
                continue
            if node.level != 0 or (node.module or "").split(".")[0] not in ALLOWED_IMPORTS:
                raise ProgramRefused(f"{rel}: import from {'.' * node.level}{node.module or ''} is not allowed in a check program")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
            raise ProgramRefused(f"{rel}: call to {node.func.id}() is not allowed in a check program")
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            raise ProgramRefused(f"{rel}: access to attribute {node.attr!r} is not allowed in a check program")
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            raise ProgramRefused(f"{rel}: global and nonlocal state is not allowed in a check program")
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_CALLS and isinstance(node.ctx, ast.Load):
            # the builtin referenced without a call (aliasing) is refused as well
            raise ProgramRefused(f"{rel}: use of {node.id} is not allowed in a check program")


def assert_run_signature(rel: str, source: bytes, entry: str = "run") -> None:
    tree = ast.parse(source, filename=rel)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == entry:
            a = node.args
            names = [x.arg for x in a.posonlyargs + a.args]
            if names != ["data"] or a.vararg or a.kwarg or a.kwonlyargs or a.defaults or a.kw_defaults:
                raise ProgramRefused(f"{rel}: {entry}() must take exactly one parameter named 'data'")
            return
    raise ProgramRefused(f"{rel}: no {entry}(data) function")


def validate_output(value: Any) -> Any:
    """A program result as plain JSON; refuses floats, non-JSON types and verdict-shaped keys at any depth."""
    plain = to_plain(value)

    def walk(v: Any, path: str) -> None:
        if isinstance(v, dict):
            for k, item in v.items():
                if k.lower() in FORBIDDEN_OUTPUT_KEYS:
                    raise OutputRefused(f"an observed value may not carry the key {k!r} (at {path or '/'})")
                walk(item, f"{path}/{k}")
        elif isinstance(v, list):
            for i, item in enumerate(v):
                walk(item, f"{path}/{i}")

    walk(plain, "")
    return plain


@dataclass(frozen=True)
class ProgramSpec:
    id: str
    version: str
    description: str
    program_hash: str
    source_files: Tuple[str, ...]
    fn: Callable[[ProgramInput], Any]
    tier: str = "OFFLINE"
    collector: str = ""

    @property
    def ref(self) -> Dict[str, str]:
        return {"id": self.id, "version": self.version, "program_hash": self.program_hash}


def _framework_bytes(rel: str) -> bytes:
    return (PACKAGE_ROOT / rel).read_bytes()


def spec_from_module(module_name: str) -> Tuple[ProgramSpec, ...]:
    """The ProgramSpecs of a module under ``redevops_qa_checks.programs``: ``run`` (full detail) under ``PROGRAM_ID`` and, when
    the module defines ``run_counts``, a compact projection under ``PROGRAM_ID + '.counts'``. Each is hashed separately over the
    source bundle plus a header naming its id, version and entry point."""
    mod = importlib.import_module(module_name)
    for attr in ("PROGRAM_ID", "PROGRAM_VERSION", "DESCRIPTION", "SUPPORT", "run"):
        if not hasattr(mod, attr):
            raise ProgramRefused(f"{module_name}: missing {attr}")
    pid, ver = mod.PROGRAM_ID, mod.PROGRAM_VERSION
    if type(pid) is not str or not ID_PATTERN.fullmatch(pid) or type(ver) is not str or not VERSION_PATTERN.fullmatch(ver):
        raise ProgramRefused(f"{module_name}: PROGRAM_ID / PROGRAM_VERSION are malformed")
    own = Path(mod.__file__).resolve()
    rel_own = own.relative_to(PACKAGE_ROOT).as_posix()
    files = {rel_own: own.read_bytes()}
    for rel in mod.SUPPORT:
        if type(rel) is not str or not rel.startswith("programs/") or ".." in rel:
            raise ProgramRefused(f"{module_name}: SUPPORT entries must be files under programs/")
        files[rel] = _framework_bytes(rel)
    for rel, data in files.items():
        assert_pure_source(rel, data)
    for rel in getattr(mod, "FRAMEWORK", ()):
        if rel not in HASHED_FRAMEWORK:
            raise ProgramRefused(f"{module_name}: FRAMEWORK entry {rel!r} is not an allowed framework file")
        files[rel] = _framework_bytes(rel)
    tier = getattr(mod, "TIER", "OFFLINE")
    collector = getattr(mod, "COLLECTOR", "")
    if tier not in ("OFFLINE", "K") or (tier == "OFFLINE" and collector) or (tier == "K" and not collector):
        raise ProgramRefused(f"{module_name}: TIER and COLLECTOR are inconsistent")
    entries = [("run", pid, mod.run)]
    if hasattr(mod, "run_counts"):
        entries.append(("run_counts", pid + ".counts", mod.run_counts))
    for rel in FRAMEWORK_FILES:
        files[rel] = _framework_bytes(rel)
    out = []
    for entry, eid, fn in entries:
        assert_run_signature(rel_own, files[rel_own], entry)
        header = f"program {eid}@{ver} entry {entry}\n" + (f"tier {tier} collector {collector}\n" if tier != "OFFLINE" else "")
        out.append(ProgramSpec(id=eid, version=ver, description=str(mod.DESCRIPTION), source_files=tuple(sorted(files)),
                               program_hash=sha256_ref(header.encode("utf-8") + source_bundle(files.items())), fn=fn, tier=tier,
                               collector=collector))
    return tuple(out)


class ProgramRegistry:
    """Immutable ``{(id, version): ProgramSpec}``; satisfies the harness ``ProgramRegistry`` protocol."""

    __slots__ = ("_specs",)

    def __init__(self, specs: Iterable[ProgramSpec]) -> None:
        table: Dict[Tuple[str, str], ProgramSpec] = {}
        for s in specs:
            key = (s.id, s.version)
            if key in table:
                raise ProgramRefused(f"duplicate check program {s.id}@{s.version}")
            table[key] = s
        object.__setattr__(self, "_specs", table)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("ProgramRegistry is read-only")

    def __len__(self) -> int:
        return len(self._specs)

    def entries(self) -> Tuple[ProgramSpec, ...]:
        return tuple(self._specs[k] for k in sorted(self._specs))

    def registered_program_hash(self, program_id: str, version: str) -> Optional[str]:
        spec = self._specs.get((program_id, version))
        return spec.program_hash if spec is not None else None

    def resolve(self, ref: Mapping) -> ProgramSpec:
        """The program for ``ref`` (``{id, version, program_hash}``) after verifying the hash. Raises before any program runs."""
        pid, ver, ph = ref.get("id"), ref.get("version"), ref.get("program_hash")
        spec = self._specs.get((pid, ver))
        if spec is None:
            raise ProgramUnregistered(f"check program {pid}@{ver} is not registered", program=f"{pid}@{ver}")
        if spec.program_hash != ph:
            raise ProgramHashMismatch(f"check program {pid}@{ver} is registered under a different program_hash",
                                      program=f"{pid}@{ver}")
        return spec

    def run(self, ref: Mapping, data: ProgramInput) -> Any:
        """Verify, then execute one program over ``data``. The only inputs are the reference and the program input."""
        if not isinstance(data, ProgramInput):
            raise ExpectedValueRefused("a check receives a ProgramInput and nothing else")
        spec = self.resolve(ref)
        return validate_output(spec.fn(data))


def refuse_expected(payload: Any, where: str = "check input") -> None:
    """Fail closed when a payload headed for a check carries an expected-value or verdict-shaped key at any depth."""
    def walk(v: Any) -> None:
        if isinstance(v, Mapping):
            for k, item in v.items():
                if isinstance(k, str) and k.lower() in FORBIDDEN_ARGUMENT_NAMES | FORBIDDEN_OUTPUT_KEYS - {"ok"}:
                    raise ExpectedValueRefused(f"{where} carries the key {k!r}; checks never receive an expected value")
                walk(item)
        elif isinstance(v, (list, tuple)):
            for item in v:
                walk(item)
    walk(payload)


BUILTIN_MODULES = ("image_references", "image_name_map", "security_context", "resources", "env_and_secret_refs",
                   "gateway_routes", "network_policies", "kyverno_policies", "probes", "cross_references", "structure",
                   "image_user_runtime", "image_ports_health", "image_labels_base", "image_layers", "image_attestations",
                   "cluster_dry_run", "cluster_admission", "cluster_gateway_status", "cluster_policy_status",
                   "connectivity_traffic", "connectivity_policy_state")


#: programs that read evidence a test engine recorded rather than infrastructure manifests; not part of ``builtin_registry`` (its program list and hashes are unchanged)
EVIDENCE_MODULES = ("robot_observations",)


def evidence_registry() -> ProgramRegistry:
    """A registry of the evidence programs only (``evidence.robot-observations``): nothing else is registered, so nothing else can be named by an assertion."""
    return ProgramRegistry(s for m in EVIDENCE_MODULES for s in spec_from_module(f"{__package__}.programs.{m}"))


def builtin_registry(extra_modules: Iterable[str] = ()) -> ProgramRegistry:
    return ProgramRegistry(s for m in (*BUILTIN_MODULES, *extra_modules) for s in spec_from_module(f"{__package__}.programs.{m}"))
