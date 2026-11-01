# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Deterministic bundle construction. The same inputs give the same bytes on every host: entries sorted by path, no clock, no user or
host information, canonical JSON, a generated tar header. The builder checks its own output with the verifier before returning it."""
from __future__ import annotations

import os
import platform
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Tuple, Union

from .canon import dumps_canonical, sha256_bytes
from .constants import (ANCHOR_BLOCK_STATEMENT, ANCHOR_NAME, ANCHOR_SCHEMA, ANCHOR_TYPES, DEFAULT_LIMITS, FORMAT_DOC, FORMAT_DOC_NAME,
                        INTEGRITY_STATEMENT, MANIFEST_NAME, MANIFEST_SCHEMA, REPORT_NAME, REPORT_SCHEMA, RESERVED_UNLISTED, ROLES,
                        SCHEMA_VERSION, Limits)
from .paths import path_problems
from .report import check_report
from .schemas import check_document
from .sources import open_source
from .tarfmt import write_tar
from .verify import verify_files


class BuildError(ValueError):
    """The inputs cannot make a valid bundle. ``problems`` lists (code, where, message)."""

    def __init__(self, problems: List[Tuple[str, str, str]]):
        super().__init__("; ".join(f"{c} {w}: {m}" for c, w, m in problems[:10]))
        self.problems = problems


class FileSpec(NamedTuple):
    data: bytes
    role: str


class BuiltBundle(NamedTuple):
    files: Dict[str, bytes]
    manifest: Dict[str, Any]
    manifest_digest: str

    def with_anchor(self, anchor_type: str, reference: str) -> "BuiltBundle":
        """The same bundle plus ``anchor.json`` (data only; see ``anchor_document``). The manifest and its digest do not change."""
        files = dict(self.files)
        files[ANCHOR_NAME] = dumps_canonical(anchor_document(anchor_type, reference, self.manifest_digest))
        return BuiltBundle(files, self.manifest, self.manifest_digest)

    def write_directory(self, destination: str) -> None:
        write_directory(self.files, destination)

    def write_archive(self, destination: str) -> None:
        write_archive(self.files, destination)

    def archive_bytes(self) -> bytes:
        return write_tar(self.files)


def describe_environment() -> Dict[str, str]:
    """OS, architecture and Python of THIS host, in the report's environment form. Callers choose to use it; the builder never does."""
    return {"os": platform.system().lower() or "unknown", "arch": platform.machine().lower() or "unknown", "python": platform.python_version()}


def anchor_document(anchor_type: str, reference: str, manifest_digest: str) -> Dict[str, Any]:
    """The anchor sidecar as data. It records which kind of external anchor is meant, where it was published, and the digest it covers.
    It is not an attestation and nothing here creates one."""
    doc = {"schema": ANCHOR_SCHEMA, "schema_version": SCHEMA_VERSION, "anchor_type": anchor_type, "anchor_reference": reference,
           "manifest_digest": manifest_digest}
    problems, _, _ = check_document(doc, ANCHOR_SCHEMA)
    if problems:
        raise BuildError([(c, f"anchor{p}", m) for c, p, m in problems])
    return doc


def build_bundle(*, report: Mapping[str, Any], files: Mapping[str, Union[FileSpec, Tuple[bytes, str]]], tools: Mapping[str, str],
                 producer: Optional[Mapping[str, str]] = None, extensions: Optional[Mapping[str, Any]] = None,
                 limits: Limits = DEFAULT_LIMITS) -> BuiltBundle:
    """Assemble a bundle from a report and the files it refers to (path to ``FileSpec(data, role)`` or ``(data, role)``)."""
    problems: List[Tuple[str, str, str]] = []
    doc_problems, _, _ = check_document(dict(report), REPORT_SCHEMA)
    problems += [(c, f"report{p}", m) for c, p, m in doc_problems]
    if not doc_problems:
        problems += [(c, f"report{p}", m) for c, p, m in check_report(report)]
    entries: Dict[str, FileSpec] = {}
    for path, spec in files.items():
        spec = FileSpec(*spec)
        for code, message in path_problems(path, limits):
            problems.append((code, path, message))
        if path in RESERVED_UNLISTED or path in (REPORT_NAME, FORMAT_DOC_NAME):
            problems.append(("RESERVED_PATH", path, "this name is written by the builder"))
        if spec.role not in ROLES or spec.role in ("report", "documentation"):
            problems.append(("BAD_ROLE", path, f"role {spec.role!r} is not allowed for a caller-supplied file"))
        if not isinstance(spec.data, (bytes, bytearray)):
            problems.append(("BAD_DATA", path, "file data must be bytes"))
        entries[path] = spec
    if problems:
        raise BuildError(problems)
    report_bytes = dumps_canonical(report)
    entries[REPORT_NAME] = FileSpec(report_bytes, "report")
    entries[FORMAT_DOC_NAME] = FileSpec(FORMAT_DOC.encode("utf-8"), "documentation")
    manifest: Dict[str, Any] = {
        "schema": MANIFEST_SCHEMA, "schema_version": SCHEMA_VERSION,
        "integrity": {"mechanism": "sha256-file-digests", "keyed": False, "statement": INTEGRITY_STATEMENT},
        "anchor": {"slot": ANCHOR_NAME, "binds": "manifest-digest", "digest_algorithm": "sha256 of the exact bytes of bundle-manifest.json",
                   "accepted_types": list(ANCHOR_TYPES), "statement": ANCHOR_BLOCK_STATEMENT},
        "run_id": report["run_id"],
        "lanes": sorted(({"lane_id": x["lane_id"], "run_id": x["run_id"], "engine": dict(x["engine"])} for x in report["lanes"]),
                        key=lambda x: (x["lane_id"], x["run_id"])),
        "assertion_set_digests": [report["assertion_set"]["digest"]],
        "environment": dict(report["environment"]),
        "tools": dict(tools),
        "report_path": REPORT_NAME,
        "files": [{"path": p, "digest": sha256_bytes(bytes(entries[p].data)), "size": len(entries[p].data), "role": entries[p].role}
                  for p in sorted(entries)],
    }
    if producer is not None:
        manifest["producer"] = dict(producer)
    if extensions:
        manifest["extensions"] = dict(extensions)
    manifest_bytes = dumps_canonical(manifest)
    contents: Dict[str, bytes] = {p: bytes(s.data) for p, s in entries.items()}
    contents[MANIFEST_NAME] = manifest_bytes
    check = verify_files(contents, limits=limits)
    if check.findings:
        raise BuildError([(f.code, f.path, f.message) for f in check.findings])
    return BuiltBundle(contents, manifest, sha256_bytes(manifest_bytes))


def write_directory(files: Mapping[str, bytes], destination: str) -> None:
    """Write the files under ``destination`` (which must not exist or must be an empty directory). Permission bits are not part of the
    format; a bundle is identified by its manifest and file digests."""
    if os.path.lexists(destination):
        if os.path.islink(destination) or not os.path.isdir(destination) or os.listdir(destination):
            raise FileExistsError(f"{destination} exists and is not an empty directory")
    os.makedirs(destination, exist_ok=True)
    for path in sorted(files):
        problems = path_problems(path)
        if problems:
            raise BuildError([(c, path, m) for c, m in problems])
        target = os.path.join(destination, *path.split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "xb") as fh:
            fh.write(files[path])


def write_archive(files: Mapping[str, bytes], destination: str) -> None:
    """Write the canonical single-file archive. ``destination`` must not exist."""
    data = write_tar(files)
    with open(destination, "xb") as fh:
        fh.write(data)


def read_files(location: str, limits: Limits = DEFAULT_LIMITS) -> Dict[str, bytes]:
    """All files of a bundle directory or archive, for re-writing in the other form. Refuses a bundle that fails the structural rules."""
    source = open_source(location, limits)
    try:
        if source.problems:
            raise BuildError([(c, p, m) for c, p, m in source.problems])
        out: Dict[str, bytes] = {}
        for entry in source.entries:
            problems = path_problems(entry.path, limits)
            if problems or entry.size > limits.max_file_bytes:
                raise BuildError([(c, entry.path, m) for c, m in problems] or [("OVERSIZE_ENTRY", entry.path, "too large")])
            out[entry.path] = source.read_all(entry.path, limits.max_file_bytes)
        return out
    finally:
        source.close()
