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

INCOMPLETE = {"evidence_incomplete": "0 file(s) not kept: forged"}
BLOB_DIR = "lanes/browser/native/blobs/"


def over_cap(lid, o):
    return replace(o, native_status="NATIVE_ERROR", raw_status="evidence-over-cap", counts=None)


def declared(n):
    return {"evidence_incomplete": f"{n} file(s) not kept: forged"}


def not_kept(names):
    return {K.NOT_KEPT_PATH: dumps_canonical({"schema": K.NOT_KEPT_SCHEMA, "schema_version": K.SCHEMA_VERSION, "names": names})}


def lose(lanes, *paths):
    """Lanes declared over the cap that really lost these files (as bundle paths): removed from the lane outcome before the builder runs."""
    def edit(lid, o):
        if lid not in lanes:
            return o
        o = over_cap(lid, o)
        native = {k: v for k, v in o.native_files.items() if f"lanes/{lid}/native/{k}" not in paths}
        return replace(o, files={p: v for p, v in o.files.items() if p not in paths}, native_files=native)
    return edit


def without(files, *paths):
    """What a forger does after deleting files: the files and their manifest entries gone, every digest recomputed."""
    out = {p: d for p, d in files.items() if p not in paths}
    man = load(out, MANIFEST_NAME)
    man["files"] = [e for e in man["files"] if e["path"] in out]
    put(out, MANIFEST_NAME, man)
    return rechain(out)


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
    lost = ["lanes/browser/target-requests.jsonl", "lanes/robot/target-requests.jsonl"]
    v = verify_files_in(tmp_path, forge_consistently(up, golden("none"), edit_lane=lose(("browser", "robot"), *lost), extensions=declared(2), logs_extra=not_kept(lost)))
    assert v.accepted and v.outcome["outcome"] != "VERIFIED" and v.exit_code == K.EXIT_ENVIRONMENT, codes(v)


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


@pytest.mark.parametrize("listed,accepted", [(True, True), (False, False)])
def test_a_reviewed_suite_file_may_be_absent_from_a_lane_over_the_cap_only_when_the_run_lists_it(up, tmp_path, listed, accepted):
    path = "lanes/robot/suite/OrderApi.py"
    files = forge_consistently(up, golden("none"), edit_lane=lose(("robot",), path), extensions=declared(1 if listed else 0), logs_extra=not_kept([path] if listed else []))
    v = verify_files_in(tmp_path, files)
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


# ---- round 3 ---------------------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("base,lane,outcome", [("discount", "robot", "FAILED"), ("none", "robot", "VERIFIED"), ("none", "browser", "VERIFIED")])
def test_a_lane_cannot_be_declared_over_the_cap_when_nothing_of_it_is_missing(up, tmp_path, base, lane, outcome):
    """R3-1: a real FAILED or VERIFIED run, one lane declared `evidence-over-cap` with every file kept and an empty list, was accepted as an INCONCLUSIVE exit 3. A demonstrated failure is not
    hidden behind a status a CI may read as 'retry'."""
    assert load(golden(base), "report.json")["verdict"]["outcome"] == outcome
    v = verify_files_in(tmp_path, forge_consistently(up, golden(base), edit_lane=lose((lane,)), extensions=declared(0), logs_extra=not_kept([])))
    assert not v.accepted and "EVIDENCE_OVER_CAP_NOT_SUPPORTED" in codes(v)


def test_a_declared_lane_needs_a_listed_file_that_belongs_to_it_and_is_really_absent(up, tmp_path):
    present = "lanes/robot/target-requests.jsonl"
    other = "lanes/browser/target-requests.jsonl"
    # a file of ANOTHER lane is listed and absent: the declared lane (robot) still lost nothing
    v = verify_files_in(tmp_path, forge_consistently(up, golden("none"), edit_lane=lambda lid, o: (lose(("robot",))(lid, replace(o, files={p: d for p, d in o.files.items() if p != other}) if lid == "browser" else o)),
                                                     extensions=declared(1), logs_extra=not_kept([other])))
    assert not v.accepted and "EVIDENCE_OVER_CAP_NOT_SUPPORTED" in codes(v)
    # a file of the lane is listed but it is present
    v = verify_files_in(tmp_path, forge_consistently(up, golden("none"), edit_lane=lose(("robot",)), extensions=declared(1), logs_extra=not_kept([present])))
    assert not v.accepted and "EVIDENCE_OVER_CAP_NOT_SUPPORTED" in codes(v)


def test_the_lane_s_own_result_file_missing_supports_the_declaration(up, tmp_path):
    result = "lanes/robot/native/adapter-result.json"
    v = verify_files_in(tmp_path, forge_consistently(up, golden("none"), edit_lane=lose(("robot",), result), extensions=declared(0), logs_extra=not_kept([])))
    assert v.accepted and v.exit_code == K.EXIT_ENVIRONMENT, codes(v)


@pytest.mark.parametrize("said", ["0 file(s) not kept: forged", "5 file(s) not kept: forged", "many files were not kept", ""])
def test_the_count_in_the_report_is_the_length_of_the_list(up, tmp_path, said):
    lost = "lanes/robot/target-requests.jsonl"
    v = verify_files_in(tmp_path, forge_consistently(up, golden("none"), edit_lane=lose(("robot",), lost), extensions={"evidence_incomplete": said}, logs_extra=not_kept([lost])))
    assert not v.accepted and "EVIDENCE_OVER_CAP_NOT_SUPPORTED" in codes(v)


@pytest.mark.parametrize("path", ["lanes/browser/gateway-log.jsonl", "lanes/browser/browser-guard-log.jsonl", "lanes/robot/egress-profile.json", "lanes/browser/egress-profile.json",
                                  "lanes/browser/target-requests.jsonl", "logs/orchestrator.log", "logs/target-requests.jsonl", "lanes/robot/suite/OrderApi.py", "lanes/robot/native/robot-summary.json"])
def test_a_file_every_run_of_the_plan_writes_cannot_just_be_missing(up, tmp_path, path):
    """R3-2: these were deleted from a VERIFIED run (digests recomputed) and the bundle was accepted as VERIFIED, exit 0."""
    v = verify_files_in(tmp_path, without(golden("none"), path))
    assert not v.accepted and "EXPECTED_FILE_MISSING" in codes(v), codes(v)


def test_the_suite_copies_of_a_lane_that_is_not_complete_are_still_required_unless_the_run_lists_them(up, tmp_path):
    """R3-2: `_check_lock` skipped a lane that 'never started', so an over-cap lane could lack both suite copies, listed or not (J4, J2)."""
    both = ["lanes/robot/suite/OrderApi.py", "lanes/robot/suite/order_discount.robot"]
    none_listed = verify_files_in(tmp_path, forge_consistently(up, golden("none"), edit_lane=lose(("robot",), *both), extensions=declared(0), logs_extra=not_kept([])))
    assert not none_listed.accepted and "EXPECTED_FILE_MISSING" in codes(none_listed) and "SUITE_FILE_MISMATCH" in codes(none_listed)       # both checks: the lock check no longer skips the lane
    one_listed = verify_files_in(tmp_path, forge_consistently(up, golden("none"), edit_lane=lose(("robot",), *both), extensions=declared(1), logs_extra=not_kept([both[0]])))
    assert not one_listed.accepted and "EXPECTED_FILE_MISSING" in codes(one_listed)
    all_listed = verify_files_in(tmp_path, forge_consistently(up, golden("none"), edit_lane=lose(("robot",), *both), extensions=declared(2), logs_extra=not_kept(sorted(both))))
    assert all_listed.accepted, codes(all_listed)


def test_a_lane_that_did_not_complete_for_another_reason_has_nothing_required_of_it(up, tmp_path):
    from qr_tamper import lane_outcomes_from
    def timed_out(lid, o):
        if lid != "robot":
            return o
        return replace(o, native_status="NATIVE_TIMEOUT", raw_status="timeout", exit_code=None, counts=None, native_files={},
                       files={p: v for p, v in o.files.items() if p.startswith("logs/")})
    v = verify_files_in(tmp_path, forge_consistently(up, golden("none"), edit_lane=timed_out))
    assert "EXPECTED_FILE_MISSING" not in codes(v)


def test_the_list_of_unkept_files_must_be_sorted_and_unique(up, tmp_path):
    """R3-3: a list with a duplicate (or out of order) was accepted; the runner writes the canonical form."""
    lost = ["lanes/robot/target-requests.jsonl", "lanes/robot/egress-profile.json"]
    for names in (sorted(lost) + [sorted(lost)[0]], list(reversed(sorted(lost)))):
        files = forge_consistently(up, golden("none"), edit_lane=lose(("robot",), *lost), extensions=declared(len(names)), logs_extra=not_kept(names))
        v = verify_files_in(tmp_path, files)
        assert not v.accepted and "NOT_KEPT_MALFORMED" in codes(v)
    ok = forge_consistently(up, golden("none"), edit_lane=lose(("robot",), *lost), extensions=declared(2), logs_extra=not_kept(sorted(lost)))
    assert verify_files_in(tmp_path, ok).accepted


def test_the_names_the_run_lists_are_bundle_paths_and_their_count_is_the_one_the_report_gives():
    from qa_runner.orchestrate import _bundle_name, _not_kept_names
    assert _bundle_name("browser", "gateway-log.jsonl") == "lanes/browser/gateway-log.jsonl" and _bundle_name("browser", "browser-guard-log.jsonl") == "lanes/browser/browser-guard-log.jsonl"
    assert _bundle_name("browser", "blobs/ab") == "lanes/browser/native/blobs/ab" and _bundle_name("robot", "native/output.xml") == "lanes/robot/native/output.xml"
    assert _bundle_name("robot", "lanes/robot/suite/x") == "lanes/robot/suite/x" and _bundle_name(None, "logs/target-requests.jsonl") == "logs/target-requests.jsonl"
    assert _not_kept_names(["b", "a", "b"]) == ["a", "b"]
    files = golden("overcap")
    names = loads_strict(files[K.NOT_KEPT_PATH])["names"]
    assert names == sorted(set(names)) and load(files, "report.json")["extensions"]["evidence_incomplete"].startswith(f"{len(names)} file(s) not kept")


# ---- round 4 -----------------------------------------------------------------------------------------------------------------------------------
def test_a_run_that_lost_only_a_run_level_file_is_accepted_as_an_incomplete_not_verified_result(up, tmp_path):
    """R4-1: no lane is an engine error here (the target's own request log belongs to no lane); the builder downgrades every VERIFIED assertion (EVIDENCE_INCOMPLETE) and `verify` recomputes the
    same with the same rule: accepted, never VERIFIED, exit 3. Before, the honest run was rejected as EVIDENCE_INCOMPLETE_BUT_VERIFIED."""
    lost = "logs/target-requests.jsonl"
    files = forge_consistently(up, golden("none"), edit_lane=lambda lid, o: o, extensions=declared(1), logs_extra={**not_kept([lost]), lost: b""})
    report = load(files, "report.json")
    assert report["verdict"]["outcome"] == "INCONCLUSIVE" and {x["verdict"]["reason_code"] for x in report["accounting"]["results"]} == {"EVIDENCE_INCOMPLETE"}
    v = verify_files_in(tmp_path, files)
    assert v.accepted and v.exit_code == K.EXIT_ENVIRONMENT and v.outcome["outcome"] == "INCONCLUSIVE", codes(v)
    assert verify_files_in(tmp_path, golden("none")).accepted                                    # the complete run is unchanged


def test_a_forger_cannot_keep_verified_verdicts_in_a_report_that_declares_incomplete_evidence(up, tmp_path):
    """The report says VERIFIED for every assertion and also `evidence_incomplete` (no lane over the cap): rejected, by the finding and by the recomputation."""
    forged = rechain(edit_json(golden("none"), "report.json", lambda r: r["extensions"].update(declared(1))))
    v = verify_files_in(tmp_path, forged)
    assert not v.accepted and "EVIDENCE_INCOMPLETE_BUT_VERIFIED" in codes(v)


@pytest.mark.parametrize("name,ok", [("lanes/browser/native/blobs/" + "a" * 64, True), ("lanes/robot/native/blobs/" + "a" * 64, False), ("lanes/nowhere/target-requests.jsonl", False),
                                     ("logs/anything-else.txt", False), ("lanes/browser/native/blobs/short", False), ("lanes/robot/suite/OrderApi.py", True)])
def test_a_listed_name_must_be_one_a_run_of_the_plan_can_write(up, tmp_path, name, ok):
    """R4-2: a fabricated name used to be accepted in the list."""
    files = forge_consistently(up, golden("overcap"), edit_lane=lambda lid, o: o, extensions=declared(len(sorted(set(loads_strict(golden("overcap")[K.NOT_KEPT_PATH])["names"] + [name])))),
                               logs_extra=not_kept(sorted(set(loads_strict(golden("overcap")[K.NOT_KEPT_PATH])["names"] + [name]))))
    v = verify_files_in(tmp_path, files)
    assert (v.accepted or "NOT_KEPT_MALFORMED" not in codes(v)) if ok else (not v.accepted and "NOT_KEPT_MALFORMED" in codes(v)), codes(v)
