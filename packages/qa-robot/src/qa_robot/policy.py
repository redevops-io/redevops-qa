# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The library allowlist for Robot Framework suites, and the checks that enforce it before and after a run.

Before the run, ``scan_suite`` reads the ``.robot`` and ``.resource`` files and refuses a suite that imports a library that is not on the
allowlist, imports a library, resource or variable file by a path the policy does not accept, or uses a construct that loads or evaluates
code at run time. After the run, ``check_run`` refuses a report whose keywords belong to a library that is not allowed, or that called
one of the dynamic keywords.

This is a guard, not a sandbox. A static scan cannot see every way a Python-capable keyword could load code, and the run itself is only
bounded by the supervisor. The worker's isolation is what contains a hostile suite; the allowlist keeps an honest suite from reaching for
libraries it was never reviewed with, and nothing is ever installed: the adapter has no code path that runs a package installer.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import FrozenSet, Iterable, List, Mapping, Set, Tuple

from qa_adapter_kit import PathPolicy, PathRefused, PolicyRefused
from qa_adapter_kit.boundedread import UnsafeRead, read_regular
from qa_adapter_kit.status import ErrorCode

STANDARD_LIBRARIES = frozenset({"BuiltIn", "Collections", "DateTime", "Dialogs", "OperatingSystem", "Process", "Remote", "Screenshot", "String",
                                "Telnet", "XML"})
# No keyword of these reaches the operating system, a display, a remote host or a terminal.
DEFAULT_ALLOWED_LIBRARIES = frozenset({"BuiltIn", "Collections", "DateTime", "String", "XML"})
RESOURCE_SUFFIXES = (".resource", ".robot", ".txt")
VARIABLE_FILE_SUFFIXES = (".yaml", ".yml", ".json")
MAX_FILES = 500
MAX_FILE_BYTES = 1_000_000
# normalised (lower case, no spaces or underscores) keyword and setting fragments that load or evaluate code at run time
DYNAMIC_KEYWORDS = frozenset({"evaluate", "importlibrary", "importresource", "importvariables", "getlibraryinstance", "setlibrarysearchorder"})
_DYNAMIC_TEXT = ("importlibrary", "importresource", "importvariables", "getlibraryinstance", "setlibrarysearchorder", "evaluate", "${{")
_SECTION = re.compile(r"^\*+\s*([A-Za-z ]+?)\s*\**\s*$")
_ALIAS = ("as", "with name")


@dataclass(frozen=True)
class RobotConfig:
    allowed_libraries: FrozenSet[str] = DEFAULT_ALLOWED_LIBRARIES
    allowed_library_files: Mapping[str, str] = field(default_factory=dict)     # path relative to the workspace -> sha256 of a reviewed library file
    allow_dynamic_python: bool = False                                          # Evaluate, Import Library ... and ${{ }} expressions
    keep_raw_output: bool = False                                               # copy output.xml to the run's output directory as evidence


@dataclass(frozen=True)
class ScanResult:
    allowed_owners: FrozenSet[str]       # library names, library aliases and resource names whose keywords may appear in the report
    files: Tuple[str, ...]


def _refuse(message: str) -> PolicyRefused:
    return PolicyRefused(message, ErrorCode.LIBRARY_REFUSED)


def _norm(text: str) -> str:
    return re.sub(r"[\s_]+", "", text.lower())


def _tokens(line: str) -> List[str]:
    if line.lstrip().startswith("|"):
        return [t.strip() for t in line.strip().strip("|").split(" | ")]
    return [t for t in re.split(r"\s{2,}|\t", line.strip()) if t]


def _suite_files(suite: Path, policy: PathPolicy) -> List[Path]:
    files: List[Path] = []
    candidates = [suite] if suite.is_file() else sorted(suite.rglob("*"))
    for path in candidates:
        if len(files) >= MAX_FILES:
            raise _refuse(f"the suite has more than {MAX_FILES} files")
        if path.is_symlink():
            raise _refuse("the suite contains a symbolic link")
        if path.is_file() and path.suffix.lower() in (".robot", ".resource", ".txt"):
            policy.resolve(path, must_exist=True)
            files.append(path)
    return files


def scan_suite(workspace: Path, suite: Path, config: RobotConfig) -> ScanResult:
    policy = PathPolicy([workspace])
    allowed = set(config.allowed_libraries)
    if not allowed <= STANDARD_LIBRARIES:
        raise _refuse("only Robot Framework standard libraries can be allowlisted by name; a library file needs a reviewed hash")
    files = _suite_files(suite, policy)
    owners: Set[str] = set(allowed)
    shown: List[str] = []
    for path in files:
        rel = str(path.relative_to(workspace))
        shown.append(rel)
        owners.add(path.stem)
        if path.stem in STANDARD_LIBRARIES and path.stem not in allowed:
            raise _refuse(f"{rel}: a file named like a library that is not allowed could be mistaken for it in a report")
        try:
            data = read_regular(str(path), max_bytes=MAX_FILE_BYTES, deadline_s=10.0, follow_symlinks=False, root=str(workspace))
        except UnsafeRead as exc:
            raise _refuse(f"{rel}: the file is larger than {MAX_FILE_BYTES} bytes" if exc.code == "TOO_LARGE" else f"{rel}: the file is not a regular file that can be read") from None
        text = data.decode("utf-8", errors="replace")
        if not config.allow_dynamic_python:
            flat = _norm(text)
            for fragment in _DYNAMIC_TEXT:
                if fragment in flat:
                    raise _refuse(f"{rel}: contains a construct that loads or evaluates code at run time ({fragment})")
        section = ""
        for line in text.splitlines():
            stripped = line.strip()
            m = _SECTION.match(stripped)
            if m:
                section = m.group(1).strip().lower()
                continue
            if section not in ("settings", "setting") or not stripped or stripped.startswith("#"):
                continue
            toks = _tokens(line)
            if not toks:
                continue
            kind = toks[0].strip().lower()
            if kind not in ("library", "resource", "variables"):
                continue
            if len(toks) < 2:
                raise _refuse(f"{rel}: an import has no name")
            target = toks[1]
            if kind == "library":
                alias = None
                lowered = [t.lower() for t in toks]
                for marker in _ALIAS:
                    if marker in lowered[2:]:
                        idx = lowered.index(marker, 2)
                        alias = toks[idx + 1] if idx + 1 < len(toks) else None
                if target in STANDARD_LIBRARIES or ("/" not in target and "\\" not in target and not target.endswith(".py") and "." not in target):
                    if target not in allowed:
                        raise _refuse(f"{rel}: library {target} is not on the allowlist")
                    if alias:
                        owners.add(alias)
                else:
                    _check_library_file(workspace, path, target, config, rel, policy)
                    owners.add(Path(target).stem)
                    if alias:
                        owners.add(alias)
            elif kind == "resource":
                if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", target) or target.startswith(("/", "~")) or ".." in Path(target).parts:
                    raise _refuse(f"{rel}: resource {target} is not a path inside the workspace")
                try:
                    res = policy.resolve(target, base=path.parent, must_exist=True)
                except PathRefused:
                    raise _refuse(f"{rel}: resource {target} is not a file inside the workspace") from None
                if res.suffix.lower() not in RESOURCE_SUFFIXES:
                    raise _refuse(f"{rel}: resource {target} is not a .resource, .robot or .txt file")
                owners.add(res.stem)
            else:       # variables
                try:
                    res = policy.resolve(target, base=path.parent, must_exist=True)
                except PathRefused:
                    raise _refuse(f"{rel}: variable file {target} is not a file inside the workspace") from None
                if res.suffix.lower() not in VARIABLE_FILE_SUFFIXES:
                    raise _refuse(f"{rel}: only YAML and JSON variable files are allowed (a Python variable file runs code)")
    return ScanResult(frozenset(owners), tuple(shown))


def _check_library_file(workspace: Path, source: Path, target: str, config: RobotConfig, rel: str, policy: PathPolicy) -> None:
    try:
        real = policy.resolve(target, base=source.parent, must_exist=True)
    except PathRefused:
        raise _refuse(f"{rel}: library {target} is not a file inside the workspace") from None
    key = str(real.relative_to(workspace))
    expected = config.allowed_library_files.get(key)
    if expected is None:
        raise _refuse(f"{rel}: library file {key} is not on the reviewed list")
    try:
        library = read_regular(str(real), max_bytes=MAX_FILE_BYTES, deadline_s=10.0, follow_symlinks=False, root=str(workspace))
    except UnsafeRead:
        raise _refuse(f"{rel}: library file {key} is not a regular file of a readable size") from None
    if hashlib.sha256(library).hexdigest() != expected:
        raise _refuse(f"{rel}: library file {key} does not match its reviewed hash")


def check_run(owners: Iterable[str], keyword_names: Iterable[str], scan: ScanResult, config: RobotConfig) -> None:
    """Refuse a report whose keywords come from a library outside the allowlist or that called a dynamic keyword."""
    bad = sorted(set(owners) - scan.allowed_owners)
    if bad:
        raise _refuse(f"the run used keywords of {bad}, which are not allowed libraries or resources of this suite")
    if not config.allow_dynamic_python:
        used = sorted(n for n in keyword_names if _norm(n.rsplit(".", 1)[-1]) in DYNAMIC_KEYWORDS)
        if used:
            raise _refuse(f"the run called keywords that load or evaluate code at run time: {used}")
