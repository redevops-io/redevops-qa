# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Regression tests for the findings of the independent review of this package (B1, H1-H3, M1-M7, L1-L9). Each test failed on the first
version of the package; the mutation suite has a mutant for each guard."""
import copy
import os
import re
import unicodedata

import pytest

from qa_evidence.build import build_bundle, write_archive
from qa_evidence.canon import dumps_canonical, safe_text, sha256_bytes
from qa_evidence.cli import main
from qa_evidence.constants import ANCHOR_NAME, MANIFEST_NAME, REPORT_NAME
from qa_evidence.report import assemble_report, assertion_set_digest, check_report, compute_outcome, evidence_set_digest
from qa_evidence.schemas import check_document
from qa_evidence.sources import MemorySource, SourceEntry
from qa_evidence.tarfmt import write_tar
from qa_evidence.verify import verify_bundle, verify_files, verify_source

import io

import qe_helpers as H
from qe_helpers import build_base, codes, edit, inputs, load, put, rechain, try_build

NON_OBJECTS = [b"null\n", b"[]\n", b"0\n", b'""\n', b"false\n", b"true\n", b"[{}]\n"]


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


# ---- B1: a document that parses to a non-object is never "ok" --------------------------------------------------------------------------------
@pytest.mark.parametrize("literal", NON_OBJECTS)
def test_b1_a_non_object_manifest_never_verifies(literal):
    r = verify_files({MANIFEST_NAME: literal, REPORT_NAME: b"garbage", "evil.bin": b"x"})
    assert not r.ok and "MANIFEST_UNREADABLE" in codes(r) and "INCOMPLETE_VERIFICATION" in codes(r) and r.complete is False
    assert r.to_json()["complete"] is False and r.assurance == "failed"
    assert not verify_files({**build_base().files, MANIFEST_NAME: literal}).ok
    assert not verify_files({MANIFEST_NAME: literal}).ok


@pytest.mark.parametrize("literal", NON_OBJECTS)
def test_b1_a_non_object_report_never_verifies(literal):
    files = dict(build_base().files)
    files[REPORT_NAME] = literal
    r = verify_files(rechain(files))
    assert not r.ok and "REPORT_UNREADABLE" in codes(r)


@pytest.mark.parametrize("literal", NON_OBJECTS)
def test_b1_a_non_object_anchor_sidecar_is_a_finding(literal):
    files = dict(build_base().files)
    files[ANCHOR_NAME] = literal
    r = verify_files(files)
    assert not r.ok and r.anchor.state == "invalid" and "ANCHOR_UNREADABLE" in codes(r)


def test_b1_the_cli_does_not_verify_or_name_a_digest_for_a_null_manifest(tmp_path):
    d = tmp_path / "nulldir"
    d.mkdir()
    (d / MANIFEST_NAME).write_bytes(b"null\n")
    (d / REPORT_NAME).write_bytes(b"anything at all\n")
    (d / "PASS.txt").write_bytes(b"whatever\n")
    assert run("verify", str(d))[0] == 1 and run("inspect", str(d))[0] == 1
    code, out, err = run("digest", str(d))
    assert code == 1 and out == ""


def test_b1_ok_needs_both_documents_parsed_and_valid():
    from qa_evidence.model import AnchorResult, VerifyResult
    anchor = AnchorResult("absent", None, None, None, None, None)
    incomplete = VerifyResult(findings=[], anchor=anchor, manifest_digest=None, informational=[], notes=[], file_count=0, form="memory", complete=False,
                              plan=None)
    assert not incomplete.ok and not incomplete.internally_consistent and incomplete.assurance == "failed"
    r, docs = verify_source(MemorySource(build_base().files))
    assert r.complete and docs.manifest is not None and docs.report is not None


# ---- H1: a lane that did not complete, or that accounts for nothing, cannot be part of a VERIFIED run ----------------------------------------
@pytest.mark.parametrize("status", ["NATIVE_ERROR", "NATIVE_TIMEOUT", "NATIVE_UNAVAILABLE", "NATIVE_SKIPPED"])
def test_h1_a_lane_that_did_not_complete_caps_the_outcome_at_inconclusive(status):
    report, files, tools = inputs(robot_obs=H.ROBOT_OBS_GOOD, robot_state="VERIFIED", robot_reason="EQUALS_EXPECTED", robot_status=status, robot_exit=None)
    assert report["accounting"]["failed"] == 0 and report["accounting"]["verified"] == 3
    assert report["verdict"]["outcome"] == "INCONCLUSIVE" and report["verdict"]["reason_code"] == "ENGINE_DID_NOT_COMPLETE"
    # a report that claims VERIFIED anyway is refused
    forged = copy.deepcopy(report)
    forged["verdict"].update({"outcome": "VERIFIED", "reason_code": "ALL_ASSERTIONS_VERIFIED"})
    assert "VERDICT_OUTCOME_MISMATCH" in try_build(forged, files, tools)[0]


def test_h1_compute_outcome_knows_the_lane_statuses():
    assert compute_outcome(["VERIFIED"], 1, ["NATIVE_PASS"]) == "VERIFIED"
    assert compute_outcome(["VERIFIED"], 1, ["NATIVE_PASS", "NATIVE_FAIL"]) == "VERIFIED"      # the engine said fail, the verifier verified: shown as a disagreement
    for status in ("NATIVE_ERROR", "NATIVE_TIMEOUT", "NATIVE_UNAVAILABLE", "NATIVE_SKIPPED"):
        assert compute_outcome(["VERIFIED"], 1, ["NATIVE_PASS", status]) == "INCONCLUSIVE"
        assert compute_outcome(["FAILED"], 1, ["NATIVE_PASS", status]) == "FAILED"


def test_h1_a_lane_with_no_frozen_assertion_is_a_finding():
    report, files, tools = inputs()
    frozen = [a for a in report["assertion_set"]["assertions"] if a["lane_id"] == "browser"]
    results = [{"assertion_id": r["assertion_id"], "native_status": r["native_status"], "state": r["verdict"]["state"], "reason_code": r["verdict"]["reason_code"],
                "evidence": r["verdict"]["provenance"]["evidence"]} for r in report["accounting"]["results"] if r["lane_id"] == "browser"]
    lanes = H.lanes(robot_status="NATIVE_TIMEOUT", robot_exit=None)
    thin = assemble_report(run_id="r0-test", started_at=report["started_at"], finished_at=report["finished_at"], plan_digest=assertion_set_digest(frozen),
                           environment=H.ENV, lanes=lanes, frozen=frozen, results=results, verifier=H.VERIFIER)
    assert "LANE_WITHOUT_ASSERTIONS" in try_build(thin, files, tools)[0]


def test_h1_a_forger_who_drops_the_failing_assertion_and_marks_the_lane_errored_is_still_flagged_as_a_lane_without_assertions():
    base = build_base()

    def drop(r):
        r["assertion_set"]["assertions"] = [a for a in r["assertion_set"]["assertions"] if a["assertion_id"] != "A-TOTAL"]
        r["accounting"]["results"] = [x for x in r["accounting"]["results"] if x["assertion_id"] != "A-TOTAL"]
        r["assertion_set"]["digest"] = assertion_set_digest(r["assertion_set"]["assertions"])
        r["plan_digest"] = r["assertion_set"]["digest"]
        r["accounting"].update(frozen=2, verified=2, failed=0)
        r["verdict"].update(outcome="VERIFIED", reason_code="ALL_ASSERTIONS_VERIFIED")
        r["verdict"]["provenance"]["assertion_set_digest"] = r["assertion_set"]["digest"]
        if "plan_digest" in r["verdict"]["provenance"]:
            r["verdict"]["provenance"]["plan_digest"] = r["plan_digest"]
        r["verdict"]["provenance"]["evidence_set_digest"] = evidence_set_digest(r["accounting"]["results"])
        r["lanes"][1]["native"]["status"] = "NATIVE_ERROR"
    files = edit(base.files, REPORT_NAME, drop)
    assert "LANE_WITHOUT_ASSERTIONS" in codes(verify_files(rechain(files)))


def test_h1_the_inspection_surfaces_every_lane_whose_native_status_and_verdicts_disagree():
    from qa_evidence.inspector import summarise
    report, files, tools = inputs(robot_obs=H.ROBOT_OBS_GOOD, robot_state="VERIFIED", robot_reason="EQUALS_EXPECTED", robot_status="NATIVE_TIMEOUT", robot_exit=None)
    d = summarise(None, report)["engine_verifier_disagreements"]
    assert [(x["lane_id"], x["native_status"]) for x in d] == [("robot", "NATIVE_TIMEOUT")]


# ---- H2: verdict evidence is never a native artifact, whatever the label says ---------------------------------------------------------------
def test_h2_evidence_with_the_bytes_of_a_native_artifact_is_refused():
    report, files, tools = inputs(robot_obs=H.ROBOT_NATIVE, robot_state="VERIFIED", robot_reason="EQUALS_EXPECTED")
    assert "EVIDENCE_IS_NATIVE_BYTES" in try_build(report, files, tools)[0]


def test_h2_evidence_inside_a_lanes_native_output_directory_is_refused_even_labelled_observation():
    report, files, tools = inputs(robot_obs=H.ROBOT_OBS_GOOD, robot_state="VERIFIED", robot_reason="EQUALS_EXPECTED", robot_obs_path="lanes/robot/native/observations.json")
    assert "EVIDENCE_IN_NATIVE_DIRECTORY" in try_build(report, files, tools)[0]


def test_h2_a_native_artifact_must_live_in_its_lanes_native_directory():
    report, files, tools = inputs()
    moved = copy.deepcopy(report)
    moved["lanes"][1]["native"]["artifacts"][0]["path"] = "lanes/robot/output.xml"
    assert "NATIVE_ARTIFACT_LOCATION" in {c for c, _, _ in check_report(moved)}          # the report alone is enough to see it
    files = dict(files)
    files["lanes/robot/output.xml"] = files.pop("lanes/robot/native/output.xml")
    assert "NATIVE_ARTIFACT_LOCATION" in try_build(moved, files, tools)[0]


def test_h2_a_file_that_is_a_byte_copy_of_a_native_artifact_cannot_be_evidence_even_with_a_different_label_and_path():
    base = build_base()
    files = dict(base.files)
    files["lanes/robot/copy.json"] = files["lanes/robot/native/output.xml"]

    def go(r):
        res = next(x for x in r["accounting"]["results"] if x["assertion_id"] == "A-TOTAL")
        res["verdict"]["provenance"]["evidence"] = {"path": "lanes/robot/copy.json", "digest": sha256_bytes(files["lanes/robot/copy.json"])}
        r["verdict"]["provenance"]["evidence_set_digest"] = evidence_set_digest(r["accounting"]["results"])

    def man(m):
        m["files"].append({"path": "lanes/robot/copy.json", "digest": sha256_bytes(files["lanes/robot/copy.json"]), "size": len(files["lanes/robot/copy.json"]),
                           "role": "observation"})
        m["files"].sort(key=lambda e: e["path"])
    files = rechain(edit(files, REPORT_NAME, go))
    files = edit(files, MANIFEST_NAME, man)
    assert "EVIDENCE_IS_NATIVE_BYTES" in codes(verify_files(files))


# ---- H3: nothing a bundle contains reaches the terminal raw ---------------------------------------------------------------------------------
HOSTILE_NAMES = ["x\x1b[2A\x1b[2KOK: internally consistent\x1b[2B\r", "y\n  OK: internally consistent\n", "z  　  ", "w‮​⁦",
                 "v\x07\x08\x7f\x9b"]


def _printable_or_newline(text):
    return all(c == "\n" or (c.isprintable() and unicodedata.category(c) != "Zs" or c == " ") for c in text)


@pytest.mark.parametrize("name", HOSTILE_NAMES)
@pytest.mark.parametrize("command", ["verify", "inspect"])
def test_h3_hostile_names_never_reach_the_terminal_raw(tmp_path, name, command):
    files = dict(build_base().files)
    files[name] = b"x"
    write_archive(files, str(tmp_path / "h.tar"))
    code, out, err = run(command, str(tmp_path / "h.tar"))
    assert code == 1 and _printable_or_newline(out) and _printable_or_newline(err)
    first = out.split("\n")[0]
    assert first.startswith("FAILED") or command == "inspect"
    assert [ln for ln in out.split("\n") if ln.lstrip().startswith("OK")] == []


def test_h3_a_hostile_name_cannot_forge_an_ok_line(tmp_path):
    files = dict(build_base().files)
    files["y\n  OK: internally consistent\n"] = b"x"
    write_archive(files, str(tmp_path / "h.tar"))
    out = run("verify", str(tmp_path / "h.tar"))[1]
    lines = [ln for ln in out.split("\n") if ln]
    assert len(lines) == 4 and lines[0].startswith("FAILED") and lines[3].startswith("  PATH_UNSAFE")      # headline, anchor, plan, one finding
    assert [ln for ln in lines if ln.strip().startswith("OK")] == []


def test_h3_a_name_that_is_not_valid_utf8_does_not_crash_the_command_line(monkeypatch, tmp_path):
    """On Linux a file name can hold bytes that are not UTF-8; Python hands them over as lone surrogates."""
    from qa_evidence import cli
    bad = "lanes/a\udcff\udc80.txt"

    def fake(location, anchor=None, plan_digest=None, **kw):
        src = MemorySource(build_base().files)
        src.entries = src.entries + [SourceEntry(bad, 1)]
        from qa_evidence.inspector import Inspection, summarise
        result, docs = verify_source(src)
        return Inspection(result, summarise(docs.manifest, docs.report), result.ok, [])
    monkeypatch.setattr(cli, "inspect_bundle", fake)
    for command in ("verify", "inspect", "html"):
        out, err = io.StringIO(), io.StringIO()
        assert cli.main([command, "ignored"], out=out, err=err) == 1
        text = out.getvalue() + err.getvalue()
        text.encode("utf-8")                    # would raise on a lone surrogate
        assert "\\udcff" in text


def test_h3_safe_text_escapes_every_space_separator_but_the_plain_space():
    for ch in (" ", " ", " ", " ", " ", " ", "　"):
        assert ch not in safe_text("a" + ch + "b") and "\\u" in safe_text("a" + ch + "b")
    assert safe_text("a b") == "a b"


def test_h3_error_messages_are_sanitised_too(tmp_path):
    code, _, err = run("verify", str(tmp_path / "missing\x1b[31m"))
    assert code == 2 and "\x1b" not in err


# ---- M1: every byte of the archive matters --------------------------------------------------------------------------------------------------
def test_m1_padding_after_an_entrys_data_must_be_zero(tmp_path):
    data = bytearray(write_tar({"a.txt": b"x" * 5, "b.txt": b"y"}))
    data[512 + 5 + 3] = 1            # inside the padding of the first entry
    (tmp_path / "p.tar").write_bytes(bytes(data))
    from qa_evidence.sources import TarSource
    src = TarSource(str(tmp_path / "p.tar"))
    try:
        assert "ARCHIVE_NONCANONICAL" in {c for c, _, _ in src.problems}
    finally:
        src.close()


def test_m1_every_single_byte_change_of_the_golden_archive_is_a_finding(tmp_path):
    """With the golden manifest digest as the anchor, no single-byte change of the archive verifies. Without it, the only changes that still
    verify are inside bundle-manifest.json and touch descriptive metadata no other field is bound to (producer, tool names and versions, the
    minor schema version); every one of them moves the manifest digest, which is exactly what the anchor compares."""
    built = build_base()
    golden = bytearray(built.archive_bytes())
    path = str(tmp_path / "g.tar")
    assert len(golden) % 10240 == 0
    from qa_evidence.tarfmt import scan_tar
    with open(path, "wb") as fh:
        fh.write(golden)
    with open(path, "rb") as fh:
        entries, problems = scan_tar(fh, len(golden))
    assert problems == []
    manifest_entry = next(e for e in entries if e.path == MANIFEST_NAME)
    inside = range(manifest_entry.offset, manifest_entry.offset + manifest_entry.size)
    unanchored_survivors = []
    for i in range(len(golden)):
        mutated = bytearray(golden)
        mutated[i] ^= 0x01
        with open(path, "wb") as fh:
            fh.write(mutated)
        result = verify_bundle(path, anchor=built.manifest_digest)
        assert not result.ok, i
        if {f.code for f in result.findings} == {"ANCHOR_MISMATCH"}:          # nothing but the anchor noticed it
            unanchored_survivors.append(i)
    assert unanchored_survivors and all(i in inside for i in unanchored_survivors)


# ---- M2: a trailing newline is not part of any identifier ------------------------------------------------------------------------------------
@pytest.mark.parametrize("bad", ["a.txt\n", "logs/x\n/y", "A1\n", "\nA1"])
def test_m2_paths_with_newlines_are_refused(bad):
    from qa_evidence.paths import path_problems
    assert path_problems(bad)


def test_m2_ids_and_paths_that_differ_by_a_trailing_newline_are_not_accepted():
    report, files, tools = inputs()
    files = dict(files)
    files["logs/orchestrator.log\n"] = (b"second\n", "log")
    assert {"PATH_UNSAFE"} & try_build(report, files, tools)[0]
    report, files, tools = inputs()
    forged = copy.deepcopy(report)
    forged["assertion_set"]["assertions"][1]["assertion_id"] = "A-STATUS\n"
    assert any(i for i in check_document(forged, "qa-evidence/run-report")[0] if i[0] == "SCHEMA_INVALID")


@pytest.mark.parametrize("pointer,value", [(["run_id"], "r0-test\n"), (["started_at"], "2026-01-01T00:00:00Z\n"), (["schema_version"], "1.0\n"),
                                           (["plan_digest"], "sha256:" + "a" * 64 + "\n"), (["verdict", "reason_code"], "ASSERTION_FAILED\n"),
                                           (["environment", "python"], "3.12.3\n"), (["lanes", 0, "engine", "version"], "1.64.1\n")])
def test_m2_every_pattern_is_a_full_match(pointer, value):
    report = copy.deepcopy(inputs()[0])
    node = report
    for k in pointer[:-1]:
        node = node[k]
    node[pointer[-1]] = value
    assert check_document(report, "qa-evidence/run-report")[0]


def test_m2_an_anchor_value_with_a_trailing_newline_is_malformed():
    base = build_base()
    assert verify_files(base.files, anchor=base.manifest_digest + "\n").anchor.state == "invalid"


def test_m2_schema_patterns_must_be_anchored_so_that_other_validators_agree():
    from qa_evidence.minischema import SchemaError, Validator
    with pytest.raises(SchemaError):
        Validator({"type": "string", "pattern": "abc"})
    with pytest.raises(SchemaError):
        Validator({"type": "string", "pattern": "^abc"})
    Validator({"type": "string", "pattern": "^abc$"})
    with pytest.raises(SchemaError):
        Validator({"type": "object", "additionalProperties": {"type": "string"}, "propertyNames": {"pattern": "^k"}})


# ---- M5: lanes belong to the run -----------------------------------------------------------------------------------------------------------
def test_m5_a_lane_run_id_must_be_the_run_id_and_the_lane_id():
    report, files, tools = inputs()
    forged = copy.deepcopy(report)
    forged["lanes"][0]["run_id"] = "other-run-zzz"
    forged["lanes"][1]["run_id"] = "another-run-yyy"
    assert "LANE_RUN_ID_MISMATCH" in try_build(forged, files, tools)[0]
    assert "LANE_RUN_ID_MISMATCH" in {c for c, _, _ in check_report(forged)}
    assert [x for x in check_report(report) if x[0] == "LANE_RUN_ID_MISMATCH"] == []


def test_m5_the_manifest_lanes_are_bound_to_the_run_too():
    base = build_base()
    files = edit(base.files, MANIFEST_NAME, lambda m: m["lanes"][0].update({"run_id": "elsewhere.browser"}))
    assert "LANE_RUN_ID_MISMATCH" in codes(verify_files(files))


# ---- M7: report fields that must agree -----------------------------------------------------------------------------------------------------
def _edited(mutate):
    report, files, tools = inputs()
    forged = copy.deepcopy(report)
    mutate(forged)
    return try_build(forged, files, tools)[0]


def test_m7_native_status_counts_and_exit_code_must_agree():
    assert "NATIVE_STATUS_INCONSISTENT" in _edited(lambda r: r["lanes"][0]["native"]["counts"].update(failed=1))
    assert "NATIVE_STATUS_INCONSISTENT" in _edited(lambda r: r["lanes"][0]["native"]["counts"].update(errored=2))
    assert "NATIVE_STATUS_INCONSISTENT" in _edited(lambda r: r["lanes"][0]["native"].update(exit_code=1))
    assert "NATIVE_STATUS_INCONSISTENT" in _edited(lambda r: r["lanes"][1]["native"].update(exit_code=3))

    def fail_with_zero(r):
        r["lanes"][0]["native"].update(status="NATIVE_FAIL", exit_code=0)
    assert "NATIVE_STATUS_INCONSISTENT" in _edited(fail_with_zero)

    def fail_without_failures(r):
        r["lanes"][0]["native"].update(status="NATIVE_FAIL", exit_code=1, counts={"passed": 2, "failed": 0, "errored": 0, "skipped": 0})
    assert "NATIVE_STATUS_INCONSISTENT" in _edited(fail_without_failures)

    def fail_with_failures_but_exit_zero(r):
        r["lanes"][0]["native"].update(status="NATIVE_FAIL", exit_code=0, counts={"passed": 1, "failed": 1, "errored": 0, "skipped": 0})
    report, files, tools = inputs()
    forged = copy.deepcopy(report)
    fail_with_failures_but_exit_zero(forged)
    assert [m for c, _, m in check_report(forged) if c == "NATIVE_STATUS_INCONSISTENT"] == ["a failing lane has exit code 0"]


@pytest.mark.parametrize("state,reason", [("VERIFIED", "EXPECTED_VALUE_DIFFERS"), ("FAILED", "EQUALS_EXPECTED"), ("INCONCLUSIVE", "EQUALS_EXPECTED"),
                                          ("VERIFIED", "NO_RESULT_RECORDED"), ("VERIFIED", "ANYTHING_AT_ALL")])
def test_m7_a_reason_code_must_belong_to_the_state(state, reason):
    def go(r):
        res = next(x for x in r["accounting"]["results"] if x["assertion_id"] == "A-STATUS")
        res["verdict"]["state"] = state
        res["verdict"]["reason_code"] = reason
        counts = [x["verdict"]["state"] for x in r["accounting"]["results"]]
        r["accounting"].update({k.lower(): counts.count(k) for k in ("VERIFIED", "FAILED", "INCONCLUSIVE", "UNACCOUNTED")})
    assert "REASON_CODE_STATE_MISMATCH" in _edited(go)


def test_m7_the_run_level_reason_code_must_belong_to_the_outcome():
    assert "REASON_CODE_STATE_MISMATCH" in _edited(lambda r: r["verdict"].update(reason_code="ALL_ASSERTIONS_VERIFIED"))


def test_m7_the_manifest_tools_must_name_the_verifier_the_report_names():
    base = build_base()
    assert "TOOLS_VERIFIER_MISMATCH" in codes(verify_files(edit(base.files, MANIFEST_NAME, lambda m: m["tools"].update({"qa-verify": "9.9.9"}))))
    assert "TOOLS_VERIFIER_MISMATCH" in codes(verify_files(edit(base.files, MANIFEST_NAME, lambda m: m["tools"].pop("qa-verify"))))


def test_m7_redaction_cannot_claim_rules_that_were_not_applied():
    assert "REDACTION_INCONSISTENT" in _edited(lambda r: r["redaction"].update(applied=False))


# ---- M3: ASCII paths -------------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("ch", ["\U00016d40", "͸", "é", "́", "‮", "\U0001f600"])
def test_m3_a_non_ascii_path_is_refused_with_its_own_code(ch):
    report, files, tools = inputs()
    files = dict(files)
    files["logs/a" + ch + ".log"] = (b"x", "log")
    assert "PATH_NOT_ASCII" in try_build(report, files, tools)[0]


# ---- M4: the frozen assertion set is bound to a plan digest and a lock file ------------------------------------------------------------------
def test_m4_the_report_manifest_and_verdict_carry_one_plan_digest_equal_to_the_digest_of_the_assertion_lock():
    b = build_base()
    report, man = load(b.files, REPORT_NAME), load(b.files, MANIFEST_NAME)
    lock_digest = sha256_bytes(b.files["assertion-lock.json"])
    assert report["plan_digest"] == man["plan_digest"] == report["verdict"]["provenance"]["plan_digest"] == report["assertion_set"]["digest"] == lock_digest
    assert [f["role"] for f in man["files"] if f["path"] == "assertion-lock.json"] == ["assertion-lock"]


def test_m4_a_null_plan_digest_is_refused_by_the_schema_and_the_assembler():
    report = copy.deepcopy(inputs()[0])
    report["plan_digest"] = None
    assert any(c == "SCHEMA_INVALID" for c, _, _ in check_document(report, "qa-evidence/run-report")[0])
    with pytest.raises(ValueError):
        assemble_report(run_id="r", started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:00Z", plan_digest=None, environment=H.ENV, lanes=[], frozen=[],
                        results=[], verifier=H.VERIFIER)


def _drop_assertion_and_rechain(files):
    """The forger of the review: remove the failing assertion everywhere and recompute every digest, the lock and the plan digest included."""
    files = dict(files)

    def go(r):
        r["assertion_set"]["assertions"] = [a for a in r["assertion_set"]["assertions"] if a["assertion_id"] != "A-TOTAL"]
        r["accounting"]["results"] = [x for x in r["accounting"]["results"] if x["assertion_id"] != "A-TOTAL"]
        digest = assertion_set_digest(r["assertion_set"]["assertions"])
        r["assertion_set"]["digest"] = r["plan_digest"] = r["verdict"]["provenance"]["assertion_set_digest"] = r["verdict"]["provenance"]["plan_digest"] = digest
        r["accounting"].update(frozen=2, verified=2, failed=0)
        r["lanes"] = [x for x in r["lanes"] if x["lane_id"] != "robot"]
        r["verdict"].update(outcome="VERIFIED", reason_code="ALL_ASSERTIONS_VERIFIED")
        r["verdict"]["provenance"]["evidence_set_digest"] = evidence_set_digest(r["accounting"]["results"])
    files = edit(files, REPORT_NAME, go)
    from qa_evidence.report import assertion_lock_bytes
    rep = load(files, REPORT_NAME)
    files["assertion-lock.json"] = assertion_lock_bytes(rep["assertion_set"]["assertions"])
    files = rechain(files)
    return edit(files, MANIFEST_NAME, lambda m: (m.update(plan_digest=rep["plan_digest"], assertion_set_digests=[rep["assertion_set"]["digest"]]),
                                                m.update(lanes=[x for x in m["lanes"] if x["lane_id"] != "robot"])))


def test_m4_a_failing_assertion_removed_and_every_digest_recomputed_verifies_internally_but_the_plan_digest_catches_it():
    base = build_base()
    forged = _drop_assertion_and_rechain(base.files)
    internal = verify_files(forged)
    assert internal.ok, internal.findings                                  # unkeyed: nothing inside the bundle can tell
    assert internal.plan.state == "absent" and "declared by the producer" in internal.plan.notice
    original_plan = load(base.files, REPORT_NAME)["plan_digest"]           # what the freeze step printed, obtained from outside the bundle
    r = verify_files(forged, plan_digest=original_plan)
    assert not r.ok and r.plan.state == "mismatch" and "PLAN_DIGEST_MISMATCH" in codes(r)
    assert verify_files(base.files, plan_digest=original_plan).plan.state == "verified"
    assert verify_files(base.files, plan_digest=original_plan).ok


@pytest.mark.parametrize("value", ["", "sha256:abc", "0" * 64, "sha256:" + "a" * 64 + "\n", "SHA256:" + "a" * 64])
def test_m4_a_malformed_plan_digest_is_refused(value):
    r = verify_files(build_base().files, plan_digest=value)
    assert not r.ok and r.plan.state == "invalid" and "PLAN_VALUE_MALFORMED" in codes(r)


def test_m4_the_assertion_lock_is_required_and_must_match():
    base = build_base()
    without = {k: v for k, v in base.files.items() if k != "assertion-lock.json"}
    def unlist(m):
        m["files"] = [e for e in m["files"] if e["path"] != "assertion-lock.json"]
    assert "ASSERTION_LOCK_MISSING" in codes(verify_files(edit(without, MANIFEST_NAME, unlist)))
    other = dict(base.files)
    other["assertion-lock.json"] = dumps_canonical([])
    assert "ASSERTION_LOCK_MISMATCH" in codes(verify_files(rechain(other)))

    def relabel(m):
        for e in m["files"]:
            if e["path"] == "assertion-lock.json":
                e["role"] = "other"
    assert "ASSERTION_LOCK_MISSING" in codes(verify_files(edit(base.files, MANIFEST_NAME, relabel)))


def test_m4_plan_digests_must_agree_everywhere():
    base = build_base()
    assert "MANIFEST_REPORT_MISMATCH" in codes(verify_files(edit(base.files, MANIFEST_NAME, lambda m: m.update(plan_digest="sha256:" + "5" * 64))))

    def where(files):
        return {f.path.split("#")[-1] for f in verify_files(files).findings if f.code == "PLAN_DIGEST_MISMATCH"}
    assert "/plan_digest" in where(rechain(edit(base.files, REPORT_NAME, lambda r: r.update(plan_digest="sha256:" + "5" * 64))))
    assert where(rechain(edit(base.files, REPORT_NAME, lambda r: r["verdict"]["provenance"].update(plan_digest="sha256:" + "5" * 64)))) == {"/verdict/provenance/plan_digest"}


def test_m4_the_cli_takes_the_plan_digest_and_says_when_it_was_not_checked(tmp_path):
    b = build_base()
    b.write_archive(str(tmp_path / "b.tar"))
    plan = load(b.files, REPORT_NAME)["plan_digest"]
    code, out, _ = run("verify", str(tmp_path / "b.tar"))
    assert code == 0 and "frozen assertion set: frozen assertion set not checked against an external plan digest" in out
    assert run("verify", str(tmp_path / "b.tar"), "--plan-digest", plan)[0] == 0
    code, out, _ = run("verify", str(tmp_path / "b.tar"), "--plan-digest", "sha256:" + "0" * 64)
    assert code == 1 and "PLAN_DIGEST_MISMATCH" in out
    assert json_plan_state(run("verify", str(tmp_path / "b.tar"), "--json")[1]) == "absent"
    assert json_plan_state(run("verify", str(tmp_path / "b.tar"), "--json", "--plan-digest", plan)[1]) == "verified"
    from qa_evidence.inspector import inspect_bundle
    from qa_evidence.render import render_html, render_text
    ins = inspect_bundle(str(tmp_path / "b.tar"))
    assert "Frozen assertion set: " + ins.verification.plan.notice in render_text(ins)
    assert "Frozen assertion set: " in render_html(ins)


def json_plan_state(text):
    import json
    return json.loads(text)["plan"]["state"]


# ---- M6: a match with a supplied value is not "integrity established" ----------------------------------------------------------------------
def test_m6_the_result_says_it_matches_a_supplied_value_and_never_says_established():
    base = build_base()
    r = verify_files(base.files, anchor=base.manifest_digest)
    j = r.to_json()
    assert r.anchor.matches and j["anchor"]["matches_supplied_value"] is True and "established" not in j["anchor"]
    assert r.assurance == "matches-supplied-anchor" and "matches the supplied anchor value" in r.anchor.notice
    assert "not proof of integrity" in r.anchor.notice and "did not authenticate" in r.anchor.notice
    assert not hasattr(r.anchor, "established")


def test_m6_digest_and_anchor_output_carry_the_provenance_sentence(tmp_path):
    from qa_evidence.constants import DIGEST_ORIGIN_NOTICE
    build_base().write_archive(str(tmp_path / "b.tar"))
    code, out, err = run("digest", str(tmp_path / "b.tar"))
    assert code == 0 and DIGEST_ORIGIN_NOTICE in err and "trusted external channel" in err and out.startswith("sha256:")
    code, out, err = run("anchor", str(tmp_path / "b.tar"), "--type", "ci-artifact-attestation", "--reference", "run-17")
    assert code == 0 and DIGEST_ORIGIN_NOTICE in err and DIGEST_ORIGIN_NOTICE not in out
    import json
    json.loads(out)                    # stdout stays pure data


def test_m6_require_anchor_success_says_it_is_a_match_not_a_proof(tmp_path):
    b = build_base()
    b.write_archive(str(tmp_path / "b.tar"))
    code, out, err = run("verify", str(tmp_path / "b.tar"), "--anchor", b.manifest_digest, "--require-anchor")
    assert code == 0 and "matches the supplied value" in err and "not checked" in err


# ---- L1: minischema never ignores a rule silently --------------------------------------------------------------------------------------
def test_l1_a_ref_with_a_sibling_keyword_or_pointing_at_another_ref_is_refused():
    from qa_evidence.minischema import SchemaError, Validator
    base = {"type": "object", "additionalProperties": False, "properties": {"a": {"$ref": "#/$defs/x", "maxLength": 3}}, "$defs": {"x": {"type": "string"}}}
    with pytest.raises(SchemaError, match="beside a \\$ref"):
        Validator(base)
    chained = {"type": "object", "additionalProperties": False, "properties": {"a": {"$ref": "#/$defs/outer"}},
               "$defs": {"outer": {"$ref": "#/$defs/inner"}, "inner": {"type": "integer", "maximum": 5}}}
    with pytest.raises(SchemaError, match="another \\$ref"):
        Validator(chained)
    ok = {"type": "object", "additionalProperties": False, "properties": {"a": {"$ref": "#/$defs/x", "description": "annotations are fine"}}, "$defs": {"x": {"type": "string"}}}
    Validator(ok)


def test_l1_unique_items_compares_objects_regardless_of_key_order_and_an_unknown_type_name_is_a_schema_error():
    from qa_evidence.minischema import SchemaError, Validator
    v = Validator({"type": "array", "uniqueItems": True})
    assert any(i.code == "UNIQUE" for i in v.validate([{"a": 1, "b": 2}, {"b": 2, "a": 1}])[0])
    with pytest.raises(SchemaError):
        Validator({"type": "float"})


# ---- L4, L5, L8, L9 --------------------------------------------------------------------------------------------------------------------------
def test_l4_an_empty_directory_in_a_directory_bundle_is_a_finding(tmp_path):
    from qa_evidence.build import write_directory
    write_directory(build_base().files, str(tmp_path / "d"))
    os.makedirs(tmp_path / "d" / "secret" / "deeper")
    r = verify_bundle(str(tmp_path / "d"))
    assert "EMPTY_DIRECTORY" in codes(r) and not r.ok
    assert "secret/deeper" in {f.path for f in r.findings if f.code == "EMPTY_DIRECTORY"}


def test_l5_signed_bundle_is_not_an_accepted_anchor_type():
    from qa_evidence.build import BuildError, anchor_document
    from qa_evidence.constants import ANCHOR_TYPES
    assert ANCHOR_TYPES == ("ci-artifact-attestation",)
    with pytest.raises(BuildError):
        anchor_document("signed-bundle", "ref", "sha256:" + "a" * 64)
    assert run("anchor", "x", "--type", "signed-bundle", "--reference", "r")[0] == 2
    files = dict(build_base().files)
    files[ANCHOR_NAME] = dumps_canonical({"schema": "qa-evidence/anchor", "schema_version": "1.0", "anchor_type": "signed-bundle", "anchor_reference": "r",
                                          "manifest_digest": build_base().manifest_digest})
    assert verify_files(files).anchor.state == "invalid"


def test_l8_a_crash_has_its_own_exit_status_and_leaks_nothing_from_the_bundle(monkeypatch, tmp_path):
    from qa_evidence import cli
    build_base().write_archive(str(tmp_path / "b.tar"))

    def boom(*a, **k):
        raise RuntimeError("secret \x1b[31m detail from the bundle")
    monkeypatch.setattr(cli, "inspect_bundle", boom)
    code, out, err = run("verify", str(tmp_path / "b.tar"))
    assert code == 4 and err == "internal error: RuntimeError\n" and out == ""


def test_l9_ids_that_differ_only_in_case_are_a_finding():
    report, files, tools = inputs()
    forged = copy.deepcopy(report)
    forged["assertion_set"]["assertions"][1]["assertion_id"] = "a-status"
    forged["assertion_set"]["digest"] = forged["plan_digest"] = forged["verdict"]["provenance"]["assertion_set_digest"] = forged["verdict"]["provenance"]["plan_digest"] = \
        assertion_set_digest(forged["assertion_set"]["assertions"])
    assert "DUPLICATE_ID_CASE" in {c for c, _, _ in check_report(forged)}
    lanes_forged = copy.deepcopy(report)
    lanes_forged["lanes"][1]["lane_id"] = "Browser"
    assert "DUPLICATE_ID_CASE" in {c for c, _, _ in check_report(lanes_forged)}


# ---- the guards behind the guards: found by the mutation suite, kept as tests ------------------------------------------------------------------
def test_h2_evidence_with_the_bytes_of_a_native_artifact_the_manifest_does_not_list_is_still_refused():
    """The lane's report lists a native artifact that is not in the manifest; the evidence file is a byte copy of it."""
    report, files, tools = inputs()
    ghost = b"engine output that is only named in the report\n"
    forged = copy.deepcopy(report)
    forged["lanes"][1]["native"]["artifacts"].append({"path": "lanes/robot/native/ghost.xml", "digest": sha256_bytes(ghost), "size": len(ghost)})
    res = next(x for x in forged["accounting"]["results"] if x["assertion_id"] == "A-TOTAL")
    res["verdict"]["provenance"]["evidence"] = {"path": "lanes/robot/observations.json", "digest": sha256_bytes(ghost)}
    forged["verdict"]["provenance"]["evidence_set_digest"] = evidence_set_digest(forged["accounting"]["results"])
    files = dict(files)
    files["lanes/robot/observations.json"] = (ghost, "observation")
    assert "EVIDENCE_IS_NATIVE_BYTES" in try_build(forged, files, tools)[0]


def test_h2_the_manifest_labels_must_agree_with_the_native_directory():
    base = build_base()

    def relabel_native(m):
        for e in m["files"]:
            if e["path"] == "lanes/robot/native/output.xml":
                e["role"] = "observation"
    r = verify_files(edit(base.files, MANIFEST_NAME, relabel_native))
    assert "NATIVE_ARTIFACT_LOCATION" in codes(r)
    assert any("native directory" in f.message for f in r.findings if f.code == "NATIVE_ARTIFACT_LOCATION")

    def mislabel_outside(m):
        for e in m["files"]:
            if e["path"] == "logs/orchestrator.log":
                e["role"] = "native-artifact"
    r = verify_files(edit(base.files, MANIFEST_NAME, mislabel_outside))
    assert any("not under lanes/<lane>/native/" in f.message for f in r.findings if f.code == "NATIVE_ARTIFACT_LOCATION")


def test_m2_a_schema_version_with_a_trailing_newline_is_a_shape_error_not_a_version():
    r = verify_files(edit(build_base().files, MANIFEST_NAME, lambda m: m.update(schema_version="2.0\n")))
    assert [f.code for f in r.findings if f.path.startswith(MANIFEST_NAME)] == ["SCHEMA_INVALID"]


@pytest.mark.parametrize("key", ["label\n", "Label", "9label", "la bel"])
def test_m2_informational_names_are_full_matches(key):
    r = verify_files(edit(build_base().files, MANIFEST_NAME, lambda m: m.update(extensions={key: "x"})))
    assert "SCHEMA_INVALID" in codes(r) and not r.ok


def test_h3_the_error_for_a_location_that_cannot_be_opened_is_a_single_clean_line(tmp_path):
    code, out, err = run("verify", str(tmp_path / "no\x1b[2Jfile"))
    assert code == 2 and out == "" and err.count("\n") == 1 and "\x1b" not in err and "\\u001b" in err


def test_h1_the_inspection_shows_a_lane_without_assertions():
    from qa_evidence.inspector import summarise
    report = inputs()[0]
    frozen = [a for a in report["assertion_set"]["assertions"] if a["lane_id"] == "browser"]
    results = [{"assertion_id": r["assertion_id"], "native_status": r["native_status"], "state": r["verdict"]["state"], "reason_code": r["verdict"]["reason_code"],
                "evidence": r["verdict"]["provenance"]["evidence"]} for r in report["accounting"]["results"] if r["lane_id"] == "browser"]
    thin = assemble_report(run_id="r0-test", started_at=report["started_at"], finished_at=report["finished_at"], plan_digest=assertion_set_digest(frozen), environment=H.ENV,
                           lanes=H.lanes(), frozen=frozen, results=results, verifier=H.VERIFIER)
    assert summarise(None, thin)["engine_verifier_disagreements"] == [
        {"code": "ENGINE_VERIFIER_DISAGREE", "lane_id": "robot", "native_status": "NATIVE_PASS", "verdict_states": []}]


def test_h2_native_directory_bytes_count_whatever_the_label():
    """The evidence is a byte copy of a file that sits in a lane's native directory but is labelled as a log, not as a native artifact."""
    report, files, tools = inputs(robot_obs=b"engine log that the producer labelled as a log\n", robot_state="VERIFIED", robot_reason="EQUALS_EXPECTED")
    files = dict(files)
    files["lanes/robot/native/engine.log"] = (b"engine log that the producer labelled as a log\n", "log")
    assert "EVIDENCE_IS_NATIVE_BYTES" in try_build(report, files, tools)[0]
