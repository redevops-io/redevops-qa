# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A run that hit the evidence cap, and what ``verify`` accepts of it (retest round 2, R2-1).

The decided result of a run over the cap is an explicit incomplete result (exit 3). Its own re-verification rejected it (exit 5) because the downgraded lane differs from what its files say and
because the blobs the budget did not keep are missing. ``verify`` now accepts exactly that: a lane the report itself declares an engine error ``evidence-over-cap`` (and only when the report also says
``evidence_incomplete``), and the files the run lists as not kept. It can only LOWER a result. The negative tests: a forged ``evidence_incomplete`` cannot raise a status, cannot make a VERIFIED run
acceptable, and cannot hide a changed or an unlisted missing file.

The base is ``golden/bundle-overcap.tar``: what ``redevops-qa demo`` wrote with a 150000 byte cap (both real engines)."""
import json
from dataclasses import replace

import pytest

from qa_evidence.canon import dumps_canonical, loads_strict, sha256_bytes
from qa_evidence.constants import MANIFEST_NAME
from qa_runner import constants as K
from qa_runner.verify import render_text
from qr_tamper import codes, edit_json, forge_consistently, golden, load, put, rechain, verify_files_in

INCOMPLETE = {"evidence_incomplete": "forged: 1 file(s) not kept"}
BLOB_DIR = "lanes/browser/native/blobs/"


def over_cap(lid, o):
    return replace(o, native_status="NATIVE_ERROR", raw_status="evidence-over-cap", counts=None)


def test_an_honest_over_cap_run_is_accepted_as_an_incomplete_result_with_the_environment_exit(up, tmp_path):
    v = verify_files_in(tmp_path, golden("overcap"))
    assert v.accepted and v.findings == [] and v.exit_code == K.EXIT_ENVIRONMENT
    assert v.outcome["outcome"] != "VERIFIED" and any("INCOMPLETE" in n for n in v.notes) and any("evidence-over-cap" in n for n in v.notes)
    text = render_text("b", v)
    assert "ACCEPTED" in text and "INCOMPLETE" in text and v.to_json()["exit_code"] == K.EXIT_ENVIRONMENT


def test_the_over_cap_bundle_names_what_it_did_not_keep_and_the_report_says_it_is_incomplete():
    files = golden("overcap")
    report = load(files, "report.json")
    listed = loads_strict(files[K.NOT_KEPT_PATH])
    assert "evidence_incomplete" in report["extensions"] and listed["schema"] == K.NOT_KEPT_SCHEMA and listed["names"]
    assert all(name not in files or files[name] == b"" for name in listed["names"])               # what is listed is absent (the target's own log stays as an empty file)


def test_a_forged_evidence_incomplete_cannot_make_a_verified_run_acceptable(up, tmp_path):
    forged = rechain(edit_json(golden("none"), "report.json", lambda r: r["extensions"].update(INCOMPLETE)))
    v = verify_files_in(tmp_path, forged)
    assert not v.accepted and "EVIDENCE_INCOMPLETE_BUT_VERIFIED" in codes(v)


def test_a_lane_relabelled_as_over_cap_without_the_report_saying_the_evidence_is_incomplete_is_still_a_relabel(up, tmp_path):
    v = verify_files_in(tmp_path, forge_consistently(up, golden("none"), edit_lane=over_cap))
    assert not v.accepted and "NATIVE_STATUS_RELABELLED" in codes(v)


def test_a_downgrade_the_report_declares_is_accepted_and_is_never_a_verified_run(up, tmp_path):
    """With the declaration the lower result is accepted: the builder recomputes every verdict, so nothing is VERIFIED, and the exit is 3."""
    v = verify_files_in(tmp_path, forge_consistently(up, golden("none"), edit_lane=over_cap, extensions=INCOMPLETE))
    assert v.accepted and v.outcome["outcome"] != "VERIFIED" and v.exit_code == K.EXIT_ENVIRONMENT


def test_a_forged_evidence_incomplete_cannot_raise_a_status_the_files_contradict(up, tmp_path):
    """The Robot lane's own report says FAIL (the discount defect); the forger reports it as a pass in the report and adds the declaration (the builder of this package refuses to write that)."""
    def raised(r):
        r["extensions"].update(INCOMPLETE)
        lane = next(l for l in r["lanes"] if l["lane_id"] == "robot")
        lane["native"].update(status="NATIVE_PASS", raw_status="PASS")
    v = verify_files_in(tmp_path, rechain(edit_json(golden("discount"), "report.json", raised)))
    assert not v.accepted and "NATIVE_STATUS_RELABELLED" in codes(v)


def test_the_declaration_does_not_hide_a_changed_file_that_was_kept(up, tmp_path):
    files = golden("overcap")
    kept = sorted(p for p in files if p.startswith(BLOB_DIR))
    assert kept
    files[kept[0]] = b"CHANGED AFTER THE RUN"
    v = verify_files_in(tmp_path, rechain(files))
    assert not v.accepted and any(c.startswith("RUN_RECORD_") or c.startswith("BLOB") for c in codes(v)), codes(v)


def test_the_declaration_does_not_excuse_a_file_the_run_did_not_list(up, tmp_path):
    """Every kept blob removed (and its manifest entry): the run listed only the ones it really dropped, so the others are missing without an excuse."""
    files = golden("overcap")
    kept = {p for p in files if p.startswith(BLOB_DIR)}
    out = {p: d for p, d in files.items() if p not in kept}
    man = load(out, MANIFEST_NAME)
    man["files"] = [e for e in man["files"] if e["path"] in out]
    put(out, MANIFEST_NAME, man)
    v = verify_files_in(tmp_path, rechain(out))
    assert not v.accepted and "RUN_RECORD_MISSING_BLOB" in codes(v)


def test_a_list_of_unkept_files_that_is_not_of_the_shape_the_runner_writes_is_a_finding(up, tmp_path):
    files = golden("overcap")
    files[K.NOT_KEPT_PATH] = dumps_canonical({"schema": K.NOT_KEPT_SCHEMA, "schema_version": K.SCHEMA_VERSION, "names": ["../../etc/passwd"]})
    v = verify_files_in(tmp_path, rechain(files))
    assert not v.accepted and "NOT_KEPT_MALFORMED" in codes(v)


def test_a_list_of_unkept_files_in_a_bundle_whose_report_does_not_say_it_is_incomplete_is_an_unexpected_file(up, tmp_path):
    files = dict(golden("none"))
    data = dumps_canonical({"schema": K.NOT_KEPT_SCHEMA, "schema_version": K.SCHEMA_VERSION, "names": []})
    files[K.NOT_KEPT_PATH] = data
    man = load(files, MANIFEST_NAME)
    man["files"].append({"path": K.NOT_KEPT_PATH, "role": "log", "digest": sha256_bytes(data), "size": len(data)})
    man["files"].sort(key=lambda e: e["path"])
    put(files, MANIFEST_NAME, man)
    v = verify_files_in(tmp_path, rechain(files))
    assert not v.accepted and "UNEXPECTED_FILE" in codes(v)


# ---- R2-2: a rejected bundle's own claim is not shown as a result --------------------------------------------------------------------------------
def test_a_rejected_bundle_shows_no_claimed_outcome_in_text_or_json_and_keeps_its_findings(up, tmp_path):
    forged = rechain(edit_json(golden("discount"), "report.json", lambda r: [x["verdict"].update(state="VERIFIED", reason_code="EQUALS_EXPECTED") for x in r["accounting"]["results"]
                                                                             if x["assertion_id"] == "A-ORDER-RULE"]))
    v = verify_files_in(tmp_path, forged)
    assert not v.accepted and v.findings
    doc = v.to_json()
    assert doc["accepted"] is False and doc["run_outcome"] is None and doc["engine_verifier_disagreements"] == [] and doc["findings"]
    text = render_text("b", v)
    assert "REJECTED" in text and "recorded run outcome" not in text and "ENGINE_VERIFIER_DISAGREE" not in text
    assert v.outcome is not None                      # kept internally (the accepted case needs it); only the display is withheld


def drop_suite_file(listed):
    def edit(lid, o):
        o = over_cap(lid, o)
        if lid == "robot":
            o = replace(o, files={p: v for p, v in o.files.items() if p != "lanes/robot/suite/OrderApi.py"})
        return o
    logs = {K.NOT_KEPT_PATH: dumps_canonical({"schema": K.NOT_KEPT_SCHEMA, "schema_version": K.SCHEMA_VERSION, "names": ["lanes/robot/suite/OrderApi.py"] if listed else []})}
    return edit, logs


@pytest.mark.parametrize("listed,accepted", [(True, True), (False, False)])
def test_a_reviewed_suite_file_may_be_absent_from_a_lane_over_the_cap_only_when_the_run_lists_it(up, tmp_path, listed, accepted):
    edit, logs = drop_suite_file(listed)
    v = verify_files_in(tmp_path, forge_consistently(up, golden("none"), edit_lane=edit, extensions=INCOMPLETE, logs_extra=logs))
    assert v.accepted is accepted and (accepted or "SUITE_FILE_MISMATCH" in codes(v)), codes(v)


def test_report_json_of_a_rejected_bundle_has_no_claimed_outcome_in_its_nested_recomputation(up, tmp_path):
    import io
    from qa_evidence.build import write_archive
    from qa_runner.cli import main
    forged = rechain(edit_json(golden("discount"), "report.json", lambda r: [x["verdict"].update(state="VERIFIED", reason_code="EQUALS_EXPECTED") for x in r["accounting"]["results"]
                                                                             if x["assertion_id"] == "A-ORDER-RULE"]))
    target = tmp_path / "forged.tar"
    write_archive(dict(forged), str(target))
    out, err = io.StringIO(), io.StringIO()
    code = main(["report", str(target), "--format", "json"], out, err)
    doc = json.loads(out.getvalue())
    assert code == K.EXIT_REJECTED and doc["content_trusted"] is False and doc["recomputation"]["run_outcome"] is None and doc["recomputation"]["findings"]
    assert "VERIFIED" not in json.dumps({k: v for k, v in doc.items() if k != "recomputation"}) and doc["recomputation"]["accepted"] is False
