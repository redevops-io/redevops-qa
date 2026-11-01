# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Offline verification of an evidence bundle (a directory or a canonical archive). No network, no clock, no environment.

What a clean result means: every listed file exists with the listed size and sha256, nothing else is present, the manifest and the report
are canonical, valid and consistent with each other, and the accounting adds up. That is INTERNAL CONSISTENCY. Because the hashes are
unkeyed, it does not show that nobody rewrote the whole bundle; only the external anchor check can, and this module reports that check's
state (``AnchorResult``) separately and never folds it into ``ok``.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Mapping, Optional

from . import report as rpt
from .canon import CanonError, dumps_canonical, loads_strict, sha256_bytes
from .constants import (ANCHOR_BLOCK_STATEMENT, ANCHOR_NAME, ANCHOR_SCHEMA, ASSERTION_LOCK_NAME, DEFAULT_LIMITS, DIGEST_RE, FORMAT_DOC,
                        FORMAT_DOC_NAME, INTEGRITY_STATEMENT, MANIFEST_NAME, MANIFEST_SCHEMA, NATIVE_DIR_RE, REPORT_SCHEMA, RESERVED_UNLISTED, Limits)
from .model import AnchorResult, Finding, PlanResult, VerifyResult
from .paths import fold_key, path_problems
from .schemas import check_document
from .sources import MemorySource, Source, SourceError, open_source


class Documents:
    """The parsed manifest and report (None when unreadable), for the inspector. Nothing in here is trustworthy unless the result is ok."""

    def __init__(self):
        self.manifest: Optional[Dict[str, Any]] = None
        self.report: Optional[Dict[str, Any]] = None
        self.anchor_doc: Optional[Dict[str, Any]] = None
        self.sizes: Dict[str, int] = {}


def _add(findings: List[Finding], code: str, path: str, message: str) -> None:
    findings.append(Finding(code, path, message))


def _read_json(source: Source, path: str, limits: Limits, findings: List[Finding], tag: str):
    """Read, parse strictly and require canonical bytes. Returns ``(bytes or None, document, good)``.

    ``good`` is the explicit status: True only when the bytes parsed to a JSON OBJECT in canonical form. A document that parses to
    ``null`` or any other non-object is unreadable (a finding is added); it is never confused with 'nothing to check'."""
    try:
        data = source.read_all(path, limits.max_json_bytes)
    except OSError as exc:
        _add(findings, f"{tag}_UNREADABLE", path, f"cannot read: {exc.strerror or exc}")
        return None, None, False
    try:
        doc = loads_strict(data, limits)
    except CanonError as exc:
        _add(findings, f"{tag}_UNREADABLE", path, f"{exc.code}: {exc}")
        return data, None, False
    if not isinstance(doc, dict):
        _add(findings, f"{tag}_UNREADABLE", path, "the document must be a JSON object")
        return data, None, False
    try:
        canonical = dumps_canonical(doc)
    except (TypeError, ValueError):
        _add(findings, f"{tag}_UNREADABLE", path, "the document cannot be put in canonical form")
        return data, None, False
    if canonical != data:
        _add(findings, f"{tag}_NOT_CANONICAL", path, "the bytes are not the canonical form of the document (sorted keys, two-space indent, ASCII escapes, one trailing newline)")
    return data, doc, True


def _schema_findings(findings, infos, notes, label, schema_id, doc, file_path):
    problems, info, note = check_document(doc, schema_id)
    for code, pointer, message in problems:
        _add(findings, code, f"{file_path}#{pointer}", message)
    for pointer in info:
        infos.append({"document": label, "pointer": pointer})
    for code, message in note:
        notes.append({"code": code, "document": label, "message": message})
    return not problems


def _entry_checks(source: Source, limits: Limits, findings: List[Finding]) -> Dict[str, int]:
    """Path, size, duplicate and collision rules over the entries as found. Returns the safe path -> size map (only these are read)."""
    for code, path, message in source.problems:
        _add(findings, code, path, message)
    safe: Dict[str, int] = {}
    counts: Dict[str, int] = {}
    total = 0
    spellings: Dict[str, set] = {}
    for entry in source.entries:
        counts[entry.path] = counts.get(entry.path, 0) + 1
        if counts[entry.path] == 2:
            _add(findings, "DUPLICATE_PATH", entry.path, "two entries have this path")
        total += entry.size
        bad = path_problems(entry.path, limits)
        for code, message in bad:
            _add(findings, code, entry.path, message)
        parts = entry.path.split("/")
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            spellings.setdefault(fold_key(prefix), set()).add(prefix)
        if entry.size > limits.max_file_bytes:
            _add(findings, "OVERSIZE_ENTRY", entry.path, f"{entry.size} bytes exceeds the cap of {limits.max_file_bytes}")
        elif not bad and counts[entry.path] == 1:
            safe[entry.path] = entry.size
    for names in spellings.values():
        if len(names) > 1:
            _add(findings, "CASE_COLLISION", sorted(names)[0], "names that differ only in case or normalisation: " + ", ".join(sorted(names)))
    paths = set(counts)
    for p in sorted(paths):
        if any(q.startswith(p + "/") for q in paths):
            _add(findings, "FILE_DIR_CONFLICT", p, "this path is both a file and a directory")
    if total > limits.max_total_bytes:
        _add(findings, "OVERSIZE_BUNDLE", "", f"{total} bytes in all exceeds the cap of {limits.max_total_bytes}")
    return safe


def _manifest_checks(man: Mapping[str, Any], limits: Limits, findings: List[Finding]) -> Dict[str, Mapping[str, Any]]:
    file_name = MANIFEST_NAME
    if man["integrity"]["statement"] != INTEGRITY_STATEMENT:
        _add(findings, "INTEGRITY_STATEMENT_ALTERED", f"{file_name}#/integrity/statement", "the statement about what the digests do not show is missing or was changed")
    if man["anchor"]["statement"] != ANCHOR_BLOCK_STATEMENT:
        _add(findings, "ANCHOR_BLOCK_ALTERED", f"{file_name}#/anchor/statement", "the anchor block statement was changed")
    listed: Dict[str, Mapping[str, Any]] = {}
    previous = None
    total = 0
    folds: Dict[str, str] = {}
    for i, f in enumerate(man["files"]):
        path = f["path"]
        where = f"{file_name}#/files/{i}"
        for code, message in path_problems(path, limits):
            _add(findings, code, where, f"{path!r}: {message}")
        if path in listed:
            _add(findings, "DUPLICATE_PATH", where, f"{path!r} is listed twice")
        listed.setdefault(path, f)
        if previous is not None and path < previous:
            _add(findings, "MANIFEST_ORDER", where, "files must be sorted by path")
        previous = path
        key = fold_key(path)
        if key in folds and folds[key] != path:
            _add(findings, "CASE_COLLISION", where, f"{path!r} and {folds[key]!r} differ only in case or normalisation")
        folds.setdefault(key, path)
        if path in RESERVED_UNLISTED:
            _add(findings, "RESERVED_LISTED", where, f"{path!r} cannot be listed in the manifest")
        if f["size"] > limits.max_file_bytes:
            _add(findings, "OVERSIZE_ENTRY", where, f"declared size {f['size']} exceeds the cap of {limits.max_file_bytes}")
        total += f["size"]
    if total > limits.max_total_bytes:
        _add(findings, "OVERSIZE_BUNDLE", file_name, f"declared sizes add up to {total}, above the cap of {limits.max_total_bytes}")
    if len(man["files"]) > limits.max_files:
        _add(findings, "TOO_MANY_FILES", file_name, f"more than {limits.max_files} files are listed")
    for i, f in enumerate(man["files"]):
        if NATIVE_DIR_RE.fullmatch(f["path"]) and f["role"] != "native-artifact":
            _add(findings, "NATIVE_ARTIFACT_LOCATION", f"{file_name}#/files/{i}", f"{f['path']!r} is in a lane's native directory but has the role {f['role']!r}")
        if f["role"] == "native-artifact" and not NATIVE_DIR_RE.fullmatch(f["path"]):
            _add(findings, "NATIVE_ARTIFACT_LOCATION", f"{file_name}#/files/{i}", f"{f['path']!r} has the role native-artifact but is not under lanes/<lane>/native/")
    reports = [f for f in man["files"] if f["role"] == "report"]
    if len(reports) != 1 or reports[0]["path"] != man["report_path"]:
        _add(findings, "REPORT_ENTRY", f"{file_name}#/files", "exactly one file must have the role report, and it must be the report_path")
    locks = [f for f in man["files"] if f["role"] == "assertion-lock"]
    if len(locks) != 1 or locks[0]["path"] != ASSERTION_LOCK_NAME:
        _add(findings, "ASSERTION_LOCK_MISSING", f"{file_name}#/files", f"exactly one file must have the role assertion-lock, and it must be {ASSERTION_LOCK_NAME}")
    doc = listed.get(FORMAT_DOC_NAME)
    if doc is None or doc["role"] != "documentation":
        _add(findings, "FORMAT_DOC_MISSING", f"{file_name}#/files", f"{FORMAT_DOC_NAME} must be listed with the role documentation")
    lane_ids = [x["lane_id"] for x in man["lanes"]]
    run_ids = [x["run_id"] for x in man["lanes"]]
    for i, x in enumerate(man["lanes"]):
        if x["run_id"] != f"{man['run_id']}.{x['lane_id']}":
            _add(findings, "LANE_RUN_ID_MISMATCH", f"{file_name}#/lanes/{i}/run_id", f"a lane run id must be <run id>.<lane id>, here {man['run_id']}.{x['lane_id']}")
        if lane_ids.count(x["lane_id"]) > 1:
            _add(findings, "DUPLICATE_LANE_ID", f"{file_name}#/lanes/{i}/lane_id", f"lane id {x['lane_id']!r} is used more than once")
        if run_ids.count(x["run_id"]) > 1:
            _add(findings, "DUPLICATE_RUN_ID", f"{file_name}#/lanes/{i}/run_id", f"lane run id {x['run_id']!r} is used more than once")
    return listed


def _cross_checks(man, rep, listed, findings: List[Finding]) -> None:
    here = "MANIFEST_REPORT_MISMATCH"
    if man["run_id"] != rep["run_id"]:
        _add(findings, here, "run_id", "the manifest and the report name different runs")
    mlanes = sorted((x["lane_id"], x["run_id"], x["engine"]["name"], x["engine"]["version"]) for x in man["lanes"])
    rlanes = sorted((x["lane_id"], x["run_id"], x["engine"]["name"], x["engine"]["version"]) for x in rep["lanes"])
    if mlanes != rlanes:
        _add(findings, here, "lanes", "the manifest and the report disagree about the lanes, their run ids or their engine versions")
    for key in ("os", "arch", "python"):
        if man["environment"].get(key) != rep["environment"].get(key):
            _add(findings, here, f"environment/{key}", f"the manifest and the report disagree about {key}")
    if sorted(man["assertion_set_digests"]) != [rep["assertion_set"]["digest"]]:
        _add(findings, here, "assertion_set_digests", "the manifest's assertion digests are not the report's assertion set digest")
    if man["plan_digest"] != rep["plan_digest"]:
        _add(findings, here, "plan_digest", "the manifest and the report disagree about the plan digest")
    lock = listed.get(ASSERTION_LOCK_NAME)
    if lock is not None and lock["role"] == "assertion-lock" and lock["digest"] != rep["assertion_set"]["digest"]:
        _add(findings, "ASSERTION_LOCK_MISMATCH", ASSERTION_LOCK_NAME, "the assertion lock is not the file whose digest is the report's assertion-set digest")
    verifier = rep["verdict"]["provenance"]["verifier"]
    if man["tools"].get(verifier["id"]) != verifier["version"]:
        _add(findings, "TOOLS_VERIFIER_MISMATCH", f"{MANIFEST_NAME}#/tools", f"the manifest must list the verifier {verifier['id']!r} with the version {verifier['version']!r} the report names")
    for li, lane in enumerate(rep["lanes"]):
        for ai, art in enumerate(lane["native"]["artifacts"]):
            entry = listed.get(art["path"])
            where = f"report.json#/lanes/{li}/native/artifacts/{ai}"
            if entry is None or entry["digest"] != art["digest"] or entry["size"] != art["size"]:
                _add(findings, "NATIVE_ARTIFACT_MISMATCH", where, f"{art['path']!r} is not listed in the manifest with this digest and size")
            elif entry["role"] != "native-artifact":
                _add(findings, "NATIVE_ARTIFACT_MISMATCH", where, f"{art['path']!r} is listed with the role {entry['role']!r}, not native-artifact")
    # what the engines wrote, whatever the producer called it: every digest of a native artifact, of any file under a lane's native directory
    native_digests = {e["digest"] for e in listed.values() if NATIVE_DIR_RE.fullmatch(e["path"]) or e["role"] == "native-artifact"}
    native_digests |= {a["digest"] for lane in rep["lanes"] for a in lane["native"]["artifacts"]}
    for ri, res in enumerate(rep["accounting"]["results"]):
        prov = res["verdict"]["provenance"]
        ev = None if prov is None else prov["evidence"]
        if ev is None:
            continue
        entry = listed.get(ev["path"])
        where = f"report.json#/accounting/results/{ri}/verdict/provenance/evidence"
        if ev["digest"] in native_digests:
            _add(findings, "EVIDENCE_IS_NATIVE_BYTES", where, "the evidence has the same bytes as a native artifact: a verdict is computed from a recorded observation, never from what the engine wrote")
        if NATIVE_DIR_RE.fullmatch(ev["path"]):
            _add(findings, "EVIDENCE_IN_NATIVE_DIRECTORY", where, f"{ev['path']!r} is inside a lane's native output directory")
        if entry is None or entry["digest"] != ev["digest"]:
            _add(findings, "EVIDENCE_NOT_IN_MANIFEST", where, f"{ev['path']!r} is not listed in the manifest with this digest")
        elif entry["role"] not in ("observation", "record"):
            _add(findings, "EVIDENCE_ROLE", where, f"{ev['path']!r} has the role {entry['role']!r}; a verdict is computed from a recorded observation or record, never from a native artifact")


def _anchor(source, safe, limits, findings, infos, notes, manifest_digest, supplied, docs) -> AnchorResult:
    declared = anchor_type = reference = None
    state = "absent"
    sidecar_ok = False
    if ANCHOR_NAME in {e.path for e in source.entries}:
        state = "declared"
        if ANCHOR_NAME not in safe:
            state = "invalid"
        else:
            data, doc, good = _read_json(source, ANCHOR_NAME, limits, findings, "ANCHOR")
            if not good or not _schema_findings(findings, infos, notes, "anchor", ANCHOR_SCHEMA, doc, ANCHOR_NAME):
                state = "invalid"
            else:
                docs.anchor_doc = doc
                declared, anchor_type, reference = doc["manifest_digest"], doc["anchor_type"], doc["anchor_reference"]
                sidecar_ok = True
    if supplied is not None:
        if not isinstance(supplied, str) or not DIGEST_RE.fullmatch(supplied):
            _add(findings, "ANCHOR_VALUE_MALFORMED", "anchor", "the supplied anchor value must look like sha256:<64 lower-case hex digits>")
            return AnchorResult("invalid", anchor_type, reference, None, declared, manifest_digest)
        if manifest_digest is None:
            return AnchorResult("mismatch", anchor_type, reference, supplied, declared, None)
        if supplied != manifest_digest:
            _add(findings, "ANCHOR_MISMATCH", "anchor", f"the supplied anchor value {supplied} is not the recomputed manifest digest {manifest_digest}")
            return AnchorResult("mismatch", anchor_type, reference, supplied, declared, manifest_digest)
        if sidecar_ok and declared != manifest_digest:
            _add(findings, "ANCHOR_SIDECAR_MISMATCH", ANCHOR_NAME, "anchor.json names a different manifest digest than the one supplied and recomputed")
        return AnchorResult("verified", anchor_type, reference, supplied, declared, manifest_digest)
    if sidecar_ok:
        if manifest_digest is None or declared != manifest_digest:
            _add(findings, "ANCHOR_MISMATCH", ANCHOR_NAME, "anchor.json names a manifest digest that is not the recomputed one")
            return AnchorResult("mismatch", anchor_type, reference, None, declared, manifest_digest)
        return AnchorResult("declared", anchor_type, reference, None, declared, manifest_digest)
    return AnchorResult(state, anchor_type, reference, None, declared, manifest_digest)


def verify_source(source: Source, *, anchor: Optional[str] = None, plan_digest: Optional[str] = None, limits: Limits = DEFAULT_LIMITS):
    """Verify an opened source. Returns ``(VerifyResult, Documents)``."""
    findings: List[Finding] = []
    infos: List[Dict[str, str]] = []
    notes: List[Dict[str, str]] = []
    docs = Documents()
    safe = _entry_checks(source, limits, findings)
    docs.sizes = dict(safe)
    manifest_digest: Optional[str] = None
    man = None
    listed: Dict[str, Mapping[str, Any]] = {}
    if MANIFEST_NAME not in safe:
        _add(findings, "MANIFEST_MISSING", MANIFEST_NAME, "the bundle has no readable manifest")
    else:
        data, doc, good = _read_json(source, MANIFEST_NAME, limits, findings, "MANIFEST")
        if data is not None:
            manifest_digest = sha256_bytes(data)
        if good and _schema_findings(findings, infos, notes, "manifest", MANIFEST_SCHEMA, doc, MANIFEST_NAME):
            man = doc
            docs.manifest = doc
            listed = _manifest_checks(man, limits, findings)
    if man is not None:
        present = set(safe)
        everything = {e.path for e in source.entries}
        for path in listed:
            if path not in everything:
                _add(findings, "MISSING_FILE", path, "listed in the manifest but not in the bundle")
        for path in sorted(present):
            if path not in listed and path not in RESERVED_UNLISTED:
                _add(findings, "EXTRA_FILE", path, "present in the bundle but not listed in the manifest")
        for path, entry in listed.items():
            if path not in safe:
                continue
            if safe[path] != entry["size"]:
                _add(findings, "SIZE_MISMATCH", path, f"the manifest says {entry['size']} bytes, the bundle has {safe[path]}")
                continue
            h = hashlib.sha256()
            read = 0
            try:
                for chunk in source.read_chunks(path, entry["size"]):
                    read += len(chunk)
                    h.update(chunk)
            except OSError as exc:
                _add(findings, "UNREADABLE", path, f"cannot read: {exc.strerror or exc}")
                continue
            if read != entry["size"]:
                _add(findings, "SIZE_MISMATCH", path, f"the manifest says {entry['size']} bytes, {read} could be read")
            elif "sha256:" + h.hexdigest() != entry["digest"]:
                _add(findings, "DIGEST_MISMATCH", path, "the sha256 of the file is not the one in the manifest")
        fdoc = listed.get(FORMAT_DOC_NAME)
        if fdoc is not None and FORMAT_DOC_NAME in safe and safe[FORMAT_DOC_NAME] <= limits.max_json_bytes:
            if source.read_all(FORMAT_DOC_NAME, limits.max_json_bytes) != FORMAT_DOC.encode("utf-8"):
                _add(findings, "FORMAT_DOC_ALTERED", FORMAT_DOC_NAME, "the format document is not the text of this format version")
        rpath = man["report_path"]
        if rpath not in safe:
            _add(findings, "REPORT_MISSING", rpath, "the report named by the manifest is not in the bundle")
        else:
            _, rdoc, rgood = _read_json(source, rpath, limits, findings, "REPORT")
            if rgood and _schema_findings(findings, infos, notes, "report", REPORT_SCHEMA, rdoc, rpath):
                docs.report = rdoc
                for code, pointer, message in rpt.check_report(rdoc):
                    _add(findings, code, f"{rpath}#{pointer}", message)
                _cross_checks(man, rdoc, listed, findings)
    result_anchor = _anchor(source, safe, limits, findings, infos, notes, manifest_digest, anchor, docs)
    result_plan = _plan(plan_digest, docs, findings)
    # The invariant that no path through the code above can skip: a bundle is only ok if BOTH documents were read, were objects and validated.
    complete = docs.manifest is not None and docs.report is not None
    if not complete:
        missing = [name for name, doc in (("manifest", docs.manifest), ("report", docs.report)) if doc is None]
        _add(findings, "INCOMPLETE_VERIFICATION", "", "the " + " and the ".join(missing) + " could not be read as a valid document, so nothing in the bundle was checked against it")
    result = VerifyResult(findings=findings, anchor=result_anchor, manifest_digest=manifest_digest, informational=infos, notes=notes,
                          file_count=len(source.entries), form=source.kind, complete=complete, plan=result_plan,
                          run_outcome=({"outcome": docs.report["verdict"]["outcome"], "reason_code": docs.report["verdict"]["reason_code"]}
                                       if docs.report is not None else None),
                          disagreements=rpt.engine_verifier_disagreements(docs.report) if docs.report is not None else None)
    return result, docs


def _plan(supplied, docs: Documents, findings: List[Finding]) -> PlanResult:
    """Compare the report's plan digest with a value supplied from outside the bundle. Without one the state is ``absent``."""
    declared = docs.report["plan_digest"] if docs.report is not None else None
    if supplied is None:
        return PlanResult("absent", None, declared)
    if not isinstance(supplied, str) or not DIGEST_RE.fullmatch(supplied):
        _add(findings, "PLAN_VALUE_MALFORMED", "plan", "the supplied plan digest must look like sha256:<64 lower-case hex digits>")
        return PlanResult("invalid", None, declared)
    if declared != supplied:
        _add(findings, "PLAN_DIGEST_MISMATCH", "plan", f"the supplied plan digest {supplied} is not the plan digest in the report ({declared})")
        return PlanResult("mismatch", supplied, declared)
    return PlanResult("verified", supplied, declared)


def verify_bundle(location: str, *, anchor: Optional[str] = None, plan_digest: Optional[str] = None, limits: Limits = DEFAULT_LIMITS) -> VerifyResult:
    """Verify a bundle directory or archive at ``location``. Raises ``SourceError`` only when the location cannot be opened."""
    source = open_source(location, limits)
    try:
        return verify_source(source, anchor=anchor, plan_digest=plan_digest, limits=limits)[0]
    finally:
        source.close()


def verify_files(files: Mapping[str, bytes], *, anchor: Optional[str] = None, plan_digest: Optional[str] = None, limits: Limits = DEFAULT_LIMITS) -> VerifyResult:
    """Verify bundle files held in memory (path to bytes)."""
    return verify_source(MemorySource(files), anchor=anchor, plan_digest=plan_digest, limits=limits)[0]
