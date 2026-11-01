# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Tamper matrix: a small valid bundle is built here, then altered one way at a time. Each row names the finding that must appear; the
clean bundle must have none. The last group shows what an unkeyed hash chain can and cannot do."""
import os

import pytest

from qa_evidence.build import BuiltBundle, read_files, write_archive, write_directory
from qa_evidence.canon import dumps_canonical, sha256_bytes
from qa_evidence.constants import ANCHOR_ABSENT_NOTICE, ANCHOR_NAME, FORMAT_DOC_NAME, MANIFEST_NAME, REPORT_NAME, Limits
from qa_evidence.tarfmt import write_tar
from qa_evidence.verify import verify_bundle, verify_files

from qe_helpers import build_base, build_forged, codes, edit, load, put, rechain


@pytest.fixture(scope="module")
def base():
    return build_base()


def test_the_clean_bundle_has_no_finding_and_says_it_is_not_anchored(base):
    r = verify_files(base.files)
    assert r.findings == [] and r.ok and r.internally_consistent
    assert r.anchor.state == "absent" and not r.anchor.established
    assert r.assurance == "internal-consistency-only" and r.assurance_notice == ANCHOR_ABSENT_NOTICE


def test_every_result_says_what_the_anchor_state_is(base):
    j = verify_files(base.files).to_json()
    assert j["anchor"]["state"] == "absent" and j["anchor"]["established"] is False and j["assurance"] == "internal-consistency-only"


# ---- one change at a time -------------------------------------------------------------------------------------------------------------
def _altered_artifact(f):
    f = dict(f)
    f["lanes/robot/output.xml"] = f["lanes/robot/output.xml"][:-2] + b"X\n"
    return f


def _deleted_artifact(f):
    f = dict(f)
    del f["lanes/browser/native.txt"]
    return f


def _extra_file(f):
    return {**f, "lanes/robot/extra.txt": b"smuggled\n"}


def _edited_manifest(f):
    return edit(f, MANIFEST_NAME, lambda m: m["tools"].update({"verifier": "9.9.9"}))


def _edited_manifest_digest(f):
    return edit(f, MANIFEST_NAME, lambda m: m["files"][0].update({"digest": "sha256:" + "0" * 64}))


def _edited_report(f):
    return edit(f, REPORT_NAME, lambda r: r.update({"started_at": "2025-12-31T00:00:00Z"}))


def _manifest_not_canonical(f):
    f = dict(f)
    f[MANIFEST_NAME] = f[MANIFEST_NAME].replace(b'  "', b'    "', 3)
    return f


def _changed_assertion_digest_in_report(f):
    def go(r):
        r["assertion_set"]["assertions"][0]["digest"] = "sha256:" + "9" * 64
    return rechain(edit(f, REPORT_NAME, go))


def _changed_assertion_digest_in_manifest(f):
    return edit(f, MANIFEST_NAME, lambda m: m.update({"assertion_set_digests": ["sha256:" + "9" * 64]}))


def _duplicated_lane_id(f):
    def go(r):
        r["lanes"][1]["lane_id"] = "browser"
    return rechain(edit(f, REPORT_NAME, go))


def _duplicated_lane_id_in_manifest(f):
    return edit(f, MANIFEST_NAME, lambda m: m["lanes"][1].update({"lane_id": "browser"}))


def _duplicated_assertion_id(f):
    def go(r):
        r["assertion_set"]["assertions"][1]["assertion_id"] = "A-STATUS"
    return rechain(edit(f, REPORT_NAME, go))


def _verdict_without_provenance(f):
    def go(r):
        r["accounting"]["results"][0]["verdict"]["provenance"] = None
    return rechain(edit(f, REPORT_NAME, go))


def _accounting_does_not_add_up(f):
    return rechain(edit(f, REPORT_NAME, lambda r: r["accounting"].update({"verified": 3})))


def _frozen_assertion_not_accounted(f):
    return rechain(edit(f, REPORT_NAME, lambda r: r["accounting"]["results"].pop()))


def _outcome_flipped(f):
    return rechain(edit(f, REPORT_NAME, lambda r: r["verdict"].update({"outcome": "VERIFIED"})))


def _native_pass_turned_into_verdict(f):
    def go(r):
        r["lanes"][1]["native"]["status"] = "VERIFIED"
    return rechain(edit(f, REPORT_NAME, go))


def _verdict_computed_from_a_native_artifact(f):
    def go(m):
        for e in m["files"]:
            if e["path"] == "lanes/robot/observations.json":
                e["role"] = "native-artifact"
    return edit(f, MANIFEST_NAME, go)


def _unknown_major(f):
    return edit(f, MANIFEST_NAME, lambda m: m.update({"schema_version": "2.0"}))


def _unknown_major_report(f):
    return rechain(edit(f, REPORT_NAME, lambda r: r.update({"schema_version": "2.0"})))


def _unknown_sensitive_field_manifest(f):
    return edit(f, MANIFEST_NAME, lambda m: m.update({"trusted": True}))


def _unknown_sensitive_field_file_entry(f):
    return edit(f, MANIFEST_NAME, lambda m: m["files"][0].update({"verified": True}))


def _adapter_originated_verified_field(f):
    def go(r):
        r["lanes"][0]["native"]["verified"] = True
    return rechain(edit(f, REPORT_NAME, go))


def _unknown_sensitive_field_in_verdict(f):
    def go(r):
        r["verdict"]["provenance"]["note"] = "x"
    return rechain(edit(f, REPORT_NAME, go))


def _limitation_removed(f):
    return rechain(edit(f, REPORT_NAME, lambda r: r.update({"limitations": r["limitations"][:1]})))


def _integrity_statement_removed(f):
    return edit(f, MANIFEST_NAME, lambda m: m["integrity"].update({"statement": "trust me"}))


def _format_doc_edited(f):
    return rechain({**f, FORMAT_DOC_NAME: f[FORMAT_DOC_NAME] + b"extra\n"})


def _report_swapped_from_another_run(f):
    other = build_forged().files[REPORT_NAME]
    return {**f, REPORT_NAME: other}


def _manifest_lists_report_twice(f):
    def go(m):
        m["files"].append(dict(m["files"][-1]))
    return edit(f, MANIFEST_NAME, go)


def _run_id_differs(f):
    return edit(f, MANIFEST_NAME, lambda m: m.update({"run_id": "r0-other"}))


def _lane_engine_version_differs(f):
    return edit(f, MANIFEST_NAME, lambda m: m["lanes"][0]["engine"].update({"version": "1.0.0"}))


def _report_role_changed(f):
    def go(m):
        for e in m["files"]:
            if e["path"] == "report.json":
                e["role"] = "other"
    return edit(f, MANIFEST_NAME, go)


def _format_doc_unlisted(f):
    def go(m):
        m["files"] = [e for e in m["files"] if e["path"] != FORMAT_DOC_NAME]
    return edit({k: v for k, v in f.items() if k != FORMAT_DOC_NAME}, MANIFEST_NAME, go)


def _environment_differs(f):
    return edit(f, MANIFEST_NAME, lambda m: m["environment"].update({"os": "windows"}))


def _native_artifact_digest_differs_in_report(f):
    return rechain(edit(f, REPORT_NAME, lambda r: r["lanes"][0]["native"]["artifacts"][0].update({"digest": "sha256:" + "7" * 64})))


def _native_artifact_role_changed(f):
    def go(m):
        for e in m["files"]:
            if e["path"] == "lanes/browser/native.txt":
                e["role"] = "other"
    return edit(f, MANIFEST_NAME, go)


def _evidence_file_removed(f):
    def go(m):
        m["files"] = [e for e in m["files"] if e["path"] != "lanes/robot/observations.json"]
    return edit({k: v for k, v in f.items() if k != "lanes/robot/observations.json"}, MANIFEST_NAME, go)


def _evidence_digest_differs_in_manifest(f):
    def go(m):
        for e in m["files"]:
            if e["path"] == "lanes/robot/observations.json":
                e["digest"] = "sha256:" + "8" * 64
    return edit(f, MANIFEST_NAME, go)


def _reserved_name_unlisted_variant_present(f):
    return {**f, "Bundle-Manifest.json": b"{}"}


def _report_wrong_schema(f):
    return rechain(edit(f, REPORT_NAME, lambda r: r.update({"schema": "qa-evidence/other"})))


ROWS = [
    ("report names another schema", _report_wrong_schema, "WRONG_SCHEMA"),
    ("report entry has another role", _report_role_changed, "REPORT_ENTRY"),
    ("format document not listed", _format_doc_unlisted, "FORMAT_DOC_MISSING"),
    ("environment differs between manifest and report", _environment_differs, "MANIFEST_REPORT_MISMATCH"),
    ("native artifact digest differs in the report", _native_artifact_digest_differs_in_report, "NATIVE_ARTIFACT_MISMATCH"),
    ("native artifact has another role in the manifest", _native_artifact_role_changed, "NATIVE_ARTIFACT_MISMATCH"),
    ("evidence file removed from the bundle and the manifest", _evidence_file_removed, "EVIDENCE_NOT_IN_MANIFEST"),
    ("evidence digest differs in the manifest", _evidence_digest_differs_in_manifest, "EVIDENCE_NOT_IN_MANIFEST"),
    ("a case variant of the manifest name", _reserved_name_unlisted_variant_present, "CASE_COLLISION"),
    ("altered artifact", _altered_artifact, "DIGEST_MISMATCH"),
    ("deleted artifact", _deleted_artifact, "MISSING_FILE"),
    ("extra file", _extra_file, "EXTRA_FILE"),
    ("edited manifest (a digest)", _edited_manifest_digest, "DIGEST_MISMATCH"),
    ("edited manifest (metadata only, so the manifest digest moves)", _edited_manifest, None),
    ("manifest bytes not canonical", _manifest_not_canonical, "MANIFEST_NOT_CANONICAL"),
    ("edited report", _edited_report, "DIGEST_MISMATCH"),
    ("changed assertion digest in the report", _changed_assertion_digest_in_report, "ASSERTION_SET_DIGEST_MISMATCH"),
    ("changed assertion digest in the manifest", _changed_assertion_digest_in_manifest, "MANIFEST_REPORT_MISMATCH"),
    ("duplicated lane id (report)", _duplicated_lane_id, "DUPLICATE_LANE_ID"),
    ("duplicated lane id (manifest)", _duplicated_lane_id_in_manifest, "DUPLICATE_LANE_ID"),
    ("duplicated assertion id", _duplicated_assertion_id, "DUPLICATE_ASSERTION_ID"),
    ("verdict without provenance", _verdict_without_provenance, "PROVENANCE_RULE"),
    ("accounting that does not add up", _accounting_does_not_add_up, "ACCOUNTING_COUNT_MISMATCH"),
    ("frozen assertion not accounted", _frozen_assertion_not_accounted, "ACCOUNTING_MISSING"),
    ("run outcome flipped to VERIFIED", _outcome_flipped, "VERDICT_OUTCOME_MISMATCH"),
    ("native status replaced by a verdict word", _native_pass_turned_into_verdict, "SCHEMA_INVALID"),
    ("verdict evidence is a native artifact", _verdict_computed_from_a_native_artifact, "EVIDENCE_ROLE"),
    ("unknown major version (manifest)", _unknown_major, "UNSUPPORTED_MAJOR_VERSION"),
    ("unknown major version (report)", _unknown_major_report, "UNSUPPORTED_MAJOR_VERSION"),
    ("unknown security-sensitive field (manifest)", _unknown_sensitive_field_manifest, "UNKNOWN_FIELD"),
    ("unknown security-sensitive field (file entry)", _unknown_sensitive_field_file_entry, "UNKNOWN_FIELD"),
    ("adapter-originated verified field", _adapter_originated_verified_field, "UNKNOWN_FIELD"),
    ("unknown security-sensitive field (verdict provenance)", _unknown_sensitive_field_in_verdict, "UNKNOWN_FIELD"),
    ("required limitation removed", _limitation_removed, "LIMITATION_MISSING"),
    ("integrity statement replaced", _integrity_statement_removed, "INTEGRITY_STATEMENT_ALTERED"),
    ("format document edited", _format_doc_edited, "FORMAT_DOC_ALTERED"),
    ("report swapped from another run", _report_swapped_from_another_run, "SIZE_MISMATCH"),
    ("file listed twice", _manifest_lists_report_twice, "DUPLICATE_PATH"),
    ("manifest names another run", _run_id_differs, "MANIFEST_REPORT_MISMATCH"),
    ("manifest and report disagree about an engine version", _lane_engine_version_differs, "MANIFEST_REPORT_MISMATCH"),
]


@pytest.mark.parametrize("name,mutate,code", ROWS, ids=[r[0] for r in ROWS])
def test_the_tamper_row_is_detected(base, name, mutate, code):
    r = verify_files(mutate(base.files))
    if code is None:
        # metadata edits that keep every file consistent are internally consistent; the anchor is what notices them
        assert r.ok and r.manifest_digest != base.manifest_digest
        assert verify_files(mutate(base.files), anchor=base.manifest_digest).anchor.state == "mismatch"
        return
    assert not r.ok and code in codes(r), (name, codes(r))


def test_a_changed_major_version_stops_before_any_field_is_judged(base):
    r = verify_files(_unknown_major(base.files))
    assert [f.code for f in r.findings if f.path.startswith(MANIFEST_NAME)] == ["UNSUPPORTED_MAJOR_VERSION"]


def test_a_native_pass_is_not_a_verdict_and_the_bundle_keeps_both(base):
    report = load(base.files, REPORT_NAME)
    lane = next(x for x in report["lanes"] if x["lane_id"] == "robot")
    result = next(x for x in report["accounting"]["results"] if x["assertion_id"] == "A-TOTAL")
    assert lane["native"]["status"] == "NATIVE_PASS" and result["native_status"] == "NATIVE_PASS"
    assert result["verdict"]["state"] == "FAILED" and report["verdict"]["outcome"] == "FAILED"
    assert verify_files(base.files).ok


# ---- paths, collisions, sizes, links (directory and archive forms) ---------------------------------------------------------------------
@pytest.mark.parametrize("evil,code", [("../escape.txt", "PATH_TRAVERSAL"), ("a/../../x", "PATH_TRAVERSAL"), ("/abs/x", "PATH_ABSOLUTE"),
                                       ("C:/x", "PATH_UNSAFE"), ("C:x", "PATH_UNSAFE"), ("a\\b", "PATH_UNSAFE"), ("a//b", "PATH_UNSAFE"),
                                       ("a/./b", "PATH_UNSAFE"), ("nul", "PATH_UNSAFE"), ("e\u0301.txt", "PATH_NOT_NFC"), ("a b", "PATH_UNSAFE"),
                                       (".hidden", "PATH_UNSAFE"), ("trail.", "PATH_UNSAFE"), ("bad\u202ename", "PATH_UNSAFE")])
def test_an_unsafe_path_in_the_archive_is_refused(tmp_path, base, evil, code):
    files = dict(base.files)
    files[evil] = b"x"
    archive = tmp_path / "evil.tar"
    archive.write_bytes(write_tar(files))
    assert code in codes(verify_bundle(str(archive)))


def test_a_path_longer_than_the_cap_is_refused_in_both_forms(tmp_path, base):
    files = {**base.files, "lanes/" + "x" * 30: b"x"}
    limits = Limits(max_path_bytes=30)
    archive = tmp_path / "long.tar"
    archive.write_bytes(write_tar(files))
    assert "PATH_TOO_LONG" in codes(verify_bundle(str(archive), limits=limits))
    write_directory(files, str(tmp_path / "d"))
    assert "PATH_TOO_LONG" in codes(verify_bundle(str(tmp_path / "d"), limits=limits))
    assert "PATH_TOO_LONG" in codes(verify_files(files, limits=limits))


def test_a_path_traversal_entry_in_the_manifest_is_refused(base):
    def go(m):
        m["files"].insert(0, {"path": "../outside.txt", "digest": "sha256:" + "0" * 64, "size": 1, "role": "other"})
    assert {"PATH_TRAVERSAL", "MISSING_FILE"} <= set(codes(verify_files(edit(base.files, MANIFEST_NAME, go))))


def test_a_manifest_that_lists_the_manifest_or_the_anchor_is_refused(base):
    def go(m):
        m["files"].append({"path": ANCHOR_NAME, "digest": "sha256:" + "0" * 64, "size": 1, "role": "other"})
    assert "RESERVED_LISTED" in codes(verify_files(edit(base.files, MANIFEST_NAME, go)))


def test_case_colliding_names_are_refused_in_an_archive(tmp_path, base):
    files = dict(base.files)
    files["lanes/robot/Output.xml"] = b"other bytes"
    archive = tmp_path / "case.tar"
    archive.write_bytes(write_tar(files))
    assert "CASE_COLLISION" in codes(verify_bundle(str(archive)))


def test_case_colliding_directories_are_refused(base):
    files = dict(base.files)
    files["Lanes/robot/other.txt"] = b"x"
    assert "CASE_COLLISION" in codes(verify_files(files))


def test_case_colliding_names_in_the_manifest_are_refused(base):
    def go(m):
        m["files"].append({"path": "LOGS/orchestrator.log", "digest": "sha256:" + "0" * 64, "size": 1, "role": "log"})
        m["files"].sort(key=lambda e: e["path"])
    assert "CASE_COLLISION" in codes(verify_files(edit(base.files, MANIFEST_NAME, go)))


def test_a_file_that_is_also_a_directory_is_refused(base):
    files = dict(base.files)
    files["logs/orchestrator.log/inner.txt"] = b"x"
    assert "FILE_DIR_CONFLICT" in codes(verify_files(files))


def test_an_oversize_entry_is_refused_by_its_actual_size(base):
    small = Limits(max_file_bytes=len(base.files["logs/orchestrator.log"]) - 1)
    r = verify_files(base.files, limits=small)
    assert "logs/orchestrator.log" in {f.path for f in r.findings if f.code == "OVERSIZE_ENTRY"}


def test_an_oversize_entry_is_refused_by_the_size_the_manifest_declares(base):
    declared = edit(base.files, MANIFEST_NAME, lambda m: m["files"][0].update({"size": 5000}))
    r = verify_files(declared, limits=Limits(max_file_bytes=4000))
    assert f"{MANIFEST_NAME}#/files/0" in {f.path for f in r.findings if f.code == "OVERSIZE_ENTRY"}
    assert not verify_files(edit(base.files, MANIFEST_NAME, lambda m: m["files"][0].update({"size": 67108865}))).ok      # the schema's own cap


def test_an_oversize_bundle_and_too_many_files_are_refused(base):
    declared = sum(len(v) for k, v in base.files.items() if k != MANIFEST_NAME)
    total = declared + len(base.files[MANIFEST_NAME])
    r = verify_files(base.files, limits=Limits(max_total_bytes=declared - 1))
    assert {f.path for f in r.findings if f.code == "OVERSIZE_BUNDLE"} == {"", MANIFEST_NAME}      # by what is there and by what is declared
    assert "TOO_MANY_FILES" in codes(verify_files(base.files, limits=Limits(max_files=3)))


def test_an_oversize_manifest_is_refused_without_being_parsed(base):
    r = verify_files(base.files, limits=Limits(max_json_bytes=100))
    assert "MANIFEST_UNREADABLE" in codes(r) and "JSON_TOO_LARGE" in " ".join(f.message for f in r.findings)


def test_a_symbolic_link_in_a_directory_bundle_is_refused(tmp_path, base):
    write_directory(base.files, str(tmp_path / "b"))
    os.symlink("/etc/hostname", tmp_path / "b" / "link.txt")
    assert "SYMLINK_REFUSED" in codes(verify_bundle(str(tmp_path / "b")))


def test_a_symbolic_link_replacing_a_file_is_refused_and_not_followed(tmp_path, base):
    write_directory(base.files, str(tmp_path / "b"))
    target = tmp_path / "secret.txt"
    target.write_bytes(base.files["logs/orchestrator.log"])
    os.remove(tmp_path / "b" / "logs" / "orchestrator.log")
    os.symlink(target, tmp_path / "b" / "logs" / "orchestrator.log")
    r = verify_bundle(str(tmp_path / "b"))
    assert "SYMLINK_REFUSED" in codes(r) and "MISSING_FILE" in codes(r)


def test_a_symbolic_link_directory_is_not_followed(tmp_path, base):
    write_directory(base.files, str(tmp_path / "b"))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "stolen.txt").write_bytes(b"x")
    os.symlink(outside, tmp_path / "b" / "linked")
    r = verify_bundle(str(tmp_path / "b"))
    assert "SYMLINK_REFUSED" in codes(r) and not any(f.path.endswith("stolen.txt") for f in r.findings)


def test_a_fifo_is_refused_as_a_special_file(tmp_path, base):
    write_directory(base.files, str(tmp_path / "b"))
    os.mkfifo(tmp_path / "b" / "pipe")
    assert "SPECIAL_FILE" in codes(verify_bundle(str(tmp_path / "b")))


def test_a_junction_is_refused(tmp_path, base, monkeypatch):
    """Windows reparse points show as a directory or file with the 0x400 attribute; the scanner refuses them without following."""
    import stat as st
    from qa_evidence import sources

    class FakeStat:
        st_mode = st.S_IFDIR | 0o755
        st_file_attributes = 0x400
        st_size = 0

    class FakeEntry:
        name, path = "junction", "/nonexistent/junction"

        def stat(self, follow_symlinks=True):
            return FakeStat()

    class FakeScan:
        def __enter__(self):
            return iter([FakeEntry()])

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(sources.os, "scandir", lambda p: FakeScan())
    src = sources.DirSource(str(tmp_path))
    assert [p[0] for p in src.problems] == ["JUNCTION_REFUSED"]


def test_a_bundle_location_that_is_itself_a_symbolic_link_is_not_opened(tmp_path, base):
    from qa_evidence.sources import SourceError
    write_directory(base.files, str(tmp_path / "b"))
    os.symlink(tmp_path / "b", tmp_path / "alias")
    with pytest.raises(SourceError, match="location itself is a symbolic link"):
        verify_bundle(str(tmp_path / "alias"))


# ---- anchor ------------------------------------------------------------------------------------------------------------------------------
def test_a_correct_external_anchor_is_verified_and_the_result_says_the_value_was_not_authenticated(base):
    r = verify_files(base.files, anchor=base.manifest_digest)
    assert r.ok and r.anchor.state == "verified" and r.anchor.established and r.assurance == "anchored-to-supplied-digest"
    assert "did not authenticate" in r.anchor.notice


def test_a_wrong_anchor_fails(base):
    r = verify_files(base.files, anchor="sha256:" + "0" * 64)
    assert not r.ok and r.anchor.state == "mismatch" and "ANCHOR_MISMATCH" in codes(r) and r.assurance == "failed"


@pytest.mark.parametrize("value", ["", "sha256:abc", "SHA256:" + "0" * 64, "0" * 64, "sha256:" + "G" * 64, "sha256:" + "A" * 64])
def test_a_malformed_anchor_value_is_refused(base, value):
    r = verify_files(base.files, anchor=value)
    assert not r.ok and r.anchor.state == "invalid" and "ANCHOR_VALUE_MALFORMED" in codes(r)


def test_an_anchor_sidecar_alone_is_declared_not_established(base):
    r = verify_files(base.with_anchor("ci-artifact-attestation", "https://example.invalid/run/1").files)
    assert r.ok and r.anchor.state == "declared" and not r.anchor.established
    assert r.anchor.anchor_type == "ci-artifact-attestation" and r.anchor.reference.endswith("/run/1")
    assert "NOT established" in r.anchor.notice and r.assurance == "internal-consistency-only"


def test_a_sidecar_plus_the_matching_supplied_value_is_verified(base):
    b = base.with_anchor("ci-artifact-attestation", "ref")
    assert verify_files(b.files, anchor=base.manifest_digest).anchor.state == "verified"


def test_a_sidecar_that_names_another_manifest_fails_even_without_a_supplied_value(base):
    files = dict(base.with_anchor("ci-artifact-attestation", "ref").files)
    side = load(files, ANCHOR_NAME)
    side["manifest_digest"] = "sha256:" + "5" * 64
    put(files, ANCHOR_NAME, side)
    r = verify_files(files)
    assert not r.ok and r.anchor.state == "mismatch" and "ANCHOR_MISMATCH" in codes(r)


def test_a_sidecar_that_disagrees_with_a_matching_supplied_value_is_flagged(base):
    files = dict(base.with_anchor("ci-artifact-attestation", "ref").files)
    side = load(files, ANCHOR_NAME)
    side["manifest_digest"] = "sha256:" + "5" * 64
    put(files, ANCHOR_NAME, side)
    r = verify_files(files, anchor=base.manifest_digest)
    assert not r.ok and "ANCHOR_SIDECAR_MISMATCH" in codes(r)


def test_a_malformed_sidecar_is_invalid(base):
    files = dict(base.files)
    files[ANCHOR_NAME] = b'{"schema": "qa-evidence/anchor"}\n'
    r = verify_files(files)
    assert not r.ok and r.anchor.state == "invalid"
    files[ANCHOR_NAME] = dumps_canonical({"schema": "qa-evidence/anchor", "schema_version": "1.0", "anchor_type": "ci-artifact-attestation",
                                          "anchor_reference": "r", "manifest_digest": base.manifest_digest, "attested": True})
    assert "UNKNOWN_FIELD" in codes(verify_files(files))


def test_an_unknown_anchor_type_is_refused(base):
    files = dict(base.files)
    files[ANCHOR_NAME] = dumps_canonical({"schema": "qa-evidence/anchor", "schema_version": "1.0", "anchor_type": "trust-me",
                                          "anchor_reference": "r", "manifest_digest": base.manifest_digest})
    assert not verify_files(files).ok


def test_an_anchor_file_that_differs_only_in_case_is_a_collision(base):
    files = dict(base.with_anchor("ci-artifact-attestation", "ref").files)
    files["ANCHOR.JSON"] = files[ANCHOR_NAME]
    assert "CASE_COLLISION" in codes(verify_files(files))


# ---- the limit of an unkeyed chain --------------------------------------------------------------------------------------------------------
def test_a_rechained_forged_manifest_without_an_anchor_verifies_as_internally_consistent_and_says_it_is_not_anchored(base):
    """A log is altered and the manifest digest and size rewritten: nothing inside the bundle can tell."""
    files = dict(base.files)
    files["logs/orchestrator.log"] = b"a different log\n"
    forged = rechain(files)
    r = verify_files(forged)
    assert r.findings == [] and r.internally_consistent and r.ok
    assert r.anchor.state == "absent" and r.anchor.established is False
    assert r.assurance == "internal-consistency-only" and r.assurance_notice == ANCHOR_ABSENT_NOTICE
    assert r.manifest_digest != base.manifest_digest


def test_a_fully_reforged_bundle_with_a_flipped_verdict_also_verifies_without_an_anchor(base):
    """The same library that builds a bundle can build a lying one: the failing assertion becomes VERIFIED over an observation that fits."""
    forged = build_forged()
    r = verify_files(forged.files)
    assert r.ok and r.anchor.state == "absent" and "NOT established" in r.assurance_notice
    assert load(forged.files, REPORT_NAME)["verdict"]["outcome"] == "VERIFIED"


def test_the_original_anchor_catches_both_forgeries_and_a_wrong_anchor_fails(base):
    files = dict(base.files)
    files["logs/orchestrator.log"] = b"a different log\n"
    for forged in (rechain(files), build_forged().files):
        assert verify_files(forged, anchor=base.manifest_digest).anchor.state == "mismatch"
        assert not verify_files(forged, anchor=base.manifest_digest).ok
        assert not verify_files(forged, anchor="sha256:" + "1" * 64).ok
        assert verify_files(forged, anchor=sha256_bytes(forged[MANIFEST_NAME])).anchor.state == "verified"   # the forger's own anchor is also "verified"


# ---- informational fields ------------------------------------------------------------------------------------------------------------------
def test_an_informational_field_in_the_manifest_and_the_report_alike(base):
    def man(m):
        m["environment"]["kernel"] = "6.8"
        m["extensions"] = {"note": "ci run"}

    def rep(r):
        r["environment"]["kernel"] = "6.8"
        r["extensions"] = {"note": "ci run"}
    files = edit(rechain(edit(base.files, REPORT_NAME, rep)), MANIFEST_NAME, man)
    r = verify_files(files)
    assert r.ok, r.findings
    assert {(i["document"], i["pointer"]) for i in r.informational} == {("manifest", "/environment/kernel"), ("manifest", "/extensions/note"),
                                                                       ("report", "/environment/kernel"), ("report", "/extensions/note")}
    assert r.anchor.state == "absent"


def test_a_newer_minor_version_is_read_with_the_same_rules(base):
    def man(m):
        m["schema_version"] = "1.7"
        m["extensions"] = {"added-in-1-7": "fine"}
    r = verify_files(edit(base.files, MANIFEST_NAME, man))
    assert r.ok and [n["code"] for n in r.notes] == ["NEWER_MINOR_VERSION"]
    assert [i["pointer"] for i in r.informational] == ["/extensions/added-in-1-7"]


def test_a_newer_minor_version_with_a_new_sensitive_field_is_refused(base):
    def man(m):
        m["schema_version"] = "1.7"
        m["signature"] = "abc"
    r = verify_files(edit(base.files, MANIFEST_NAME, man))
    assert not r.ok and "UNKNOWN_FIELD" in codes(r) and [n["code"] for n in r.notes] == ["NEWER_MINOR_VERSION"]


@pytest.mark.parametrize("extra", [{"Bad Key": "x"}, {"k": {"nested": 1}}, {"k": [1]}, {"k": "x" * 2000}, {"1k": "x"}])
def test_informational_values_must_be_short_scalars_with_plain_names(base, extra):
    r = verify_files(edit(base.files, MANIFEST_NAME, lambda m: m.update({"extensions": extra})))
    assert not r.ok and "SCHEMA_INVALID" in codes(r)


def test_a_document_with_duplicate_keys_floats_or_a_bom_is_refused(base):
    files = dict(base.files)
    files[MANIFEST_NAME] = files[MANIFEST_NAME].replace(b'"run_id": "r0-test",', b'"run_id": "r0-test",\n  "run_id": "r0-test",')
    assert "MANIFEST_UNREADABLE" in codes(verify_files(files))
    files[MANIFEST_NAME] = b"\xef\xbb\xbf" + base.files[MANIFEST_NAME]
    assert "MANIFEST_UNREADABLE" in codes(verify_files(files))
    first = load(base.files, MANIFEST_NAME)["files"][0]["size"]
    files[MANIFEST_NAME] = base.files[MANIFEST_NAME].replace(b'"size": %d' % first, b'"size": %d.0' % first, 1)
    assert "MANIFEST_UNREADABLE" in codes(verify_files(files))
    files = dict(base.files)
    files[REPORT_NAME] = base.files[REPORT_NAME].replace(b'"exit_code": 0', b'"exit_code": 0.0', 1)
    assert "REPORT_UNREADABLE" in codes(verify_files(files))


def test_a_missing_manifest_and_a_missing_report_are_reported(base):
    files = dict(base.files)
    del files[MANIFEST_NAME]
    assert "MANIFEST_MISSING" in codes(verify_files(files))
    files = dict(base.files)
    del files[REPORT_NAME]
    assert "MISSING_FILE" in codes(verify_files(files)) and "REPORT_MISSING" in codes(verify_files(files))


def test_a_manifest_with_files_out_of_order_is_refused(base):
    def go(m):
        m["files"].reverse()
    assert "MANIFEST_ORDER" in codes(verify_files(edit(base.files, MANIFEST_NAME, go)))


def test_the_anchor_block_statement_cannot_be_changed(base):
    r = verify_files(edit(base.files, MANIFEST_NAME, lambda m: m["anchor"].update({"statement": "this manifest is anchored"})))
    assert "ANCHOR_BLOCK_ALTERED" in codes(r)


def test_two_entries_with_one_path_are_reported_by_the_verifier_itself(base):
    """A source that lists one path twice (the archive reader already reports this; the verifier must not rely on it)."""
    from qa_evidence.sources import MemorySource, SourceEntry
    from qa_evidence.verify import verify_source

    class Doubled(MemorySource):
        def __init__(self, files):
            super().__init__(files)
            self.entries = self.entries + [SourceEntry("logs/orchestrator.log", 3)]

    r, _ = verify_source(Doubled(base.files))
    assert [f.code for f in r.findings if f.code == "DUPLICATE_PATH"] == ["DUPLICATE_PATH"]
