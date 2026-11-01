# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The run report: schema validation (positive and negative), the semantic checks, and the assembly helper."""
import copy

import pytest

from qa_evidence import constants
from qa_evidence.report import (assemble_report, assertion_set_digest, check_report, compute_outcome, evidence_set_digest,
                                standard_limitations)
from qa_evidence.schemas import check_document

from qe_helpers import inputs

REPORT_ID = constants.REPORT_SCHEMA


@pytest.fixture()
def report():
    return copy.deepcopy(inputs()[0])


def schema_codes(doc):
    return {(c, p) for c, p, _ in check_document(doc, REPORT_ID)[0]}


def semantic_codes(doc):
    return {c for c, _, _ in check_report(doc)}


def test_the_assembled_report_is_valid_and_consistent(report):
    assert check_document(report, REPORT_ID) == ([], [], [])
    assert check_report(report) == []


def test_the_report_keeps_native_and_verdict_in_separate_fields_with_disjoint_words(report):
    lane = report["lanes"][1]
    res = next(x for x in report["accounting"]["results"] if x["assertion_id"] == "A-TOTAL")
    assert lane["native"]["status"] == "NATIVE_PASS" and res["verdict"]["state"] == "FAILED"
    assert set(lane["native"]) == {"status", "raw_status", "exit_code", "artifacts"}
    assert set(res) == {"assertion_id", "lane_id", "native_status", "verdict"} and set(res["verdict"]) == {"state", "reason_code", "provenance"}
    assert set(res["verdict"]["provenance"]) == {"verifier", "assertion_digest", "evidence"}
    assert set(report["verdict"]["provenance"]) == {"verifier", "plan_digest", "assertion_set_digest", "evidence_set_digest"}


REQUIRED_TOP = ["schema", "schema_version", "run_id", "started_at", "finished_at", "plan_digest", "environment", "lanes", "assertion_set", "accounting",
                "verdict", "redaction", "limitations"]


@pytest.mark.parametrize("key", REQUIRED_TOP)
def test_every_required_top_level_field_is_required(report, key):
    del report[key]
    assert (("WRONG_SCHEMA" if key == "schema" else "SCHEMA_INVALID"), "/" + key) in schema_codes(report)


def _total(r):
    return next(x for x in r["accounting"]["results"] if x["assertion_id"] == "A-TOTAL")


def _set(path, value):
    def go(r):
        node = r
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = value
    return go


NEGATIVE = [
    ("wrong schema id", _set(["schema"], "other"), "WRONG_SCHEMA"),
    ("bad version shape", _set(["schema_version"], "one"), "SCHEMA_INVALID"),
    ("major 2", _set(["schema_version"], "2.0"), "UNSUPPORTED_MAJOR_VERSION"),
    ("major 0", _set(["schema_version"], "0.9"), "UNSUPPORTED_MAJOR_VERSION"),
    ("run id with a slash", _set(["run_id"], "a/b"), "SCHEMA_INVALID"),
    ("time without zone", _set(["started_at"], "2026-01-01T00:00:00"), "SCHEMA_INVALID"),
    ("plan digest wrong shape", _set(["plan_digest"], "md5:abc"), "SCHEMA_INVALID"),
    ("environment without os", lambda r: r["environment"].pop("os"), "SCHEMA_INVALID"),
    ("no lanes", _set(["lanes"], []), "SCHEMA_INVALID"),
    ("native status is a verdict word", _set(["lanes", 0, "native", "status"], "VERIFIED"), "SCHEMA_INVALID"),
    ("native status is a bare engine word", _set(["lanes", 0, "native", "status"], "PASS"), "SCHEMA_INVALID"),
    ("verdict state is a native word", _set(["accounting", "results", 0, "verdict", "state"], "NATIVE_PASS"), "SCHEMA_INVALID"),
    ("verdict state PASS", _set(["accounting", "results", 0, "verdict", "state"], "PASS"), "SCHEMA_INVALID"),
    ("outcome UNACCOUNTED", _set(["verdict", "outcome"], "UNACCOUNTED"), "SCHEMA_INVALID"),
    ("native exit code float", _set(["lanes", 0, "native", "exit_code"], 0.5), "SCHEMA_INVALID"),
    ("native exit code bool", _set(["lanes", 0, "native", "exit_code"], True), "SCHEMA_INVALID"),
    ("artifact digest wrong shape", _set(["lanes", 0, "native", "artifacts", 0, "digest"], "sha256:xyz"), "SCHEMA_INVALID"),
    ("artifact digest upper case", _set(["lanes", 0, "native", "artifacts", 0, "digest"], "sha256:" + "A" * 64), "SCHEMA_INVALID"),
    ("artifact size negative", _set(["lanes", 0, "native", "artifacts", 0, "size"], -1), "SCHEMA_INVALID"),
    ("counts missing a key", lambda r: r["lanes"][0]["native"]["counts"].pop("errored"), "SCHEMA_INVALID"),
    ("assertion digest wrong shape", _set(["assertion_set", "assertions", 0, "digest"], "123"), "SCHEMA_INVALID"),
    ("reason code lower case", _set(["verdict", "reason_code"], "ok"), "SCHEMA_INVALID"),
    ("accounting count as string", _set(["accounting", "verified"], "2"), "SCHEMA_INVALID"),
    ("provenance verifier missing version", lambda r: r["accounting"]["results"][0]["verdict"]["provenance"]["verifier"].pop("version"), "SCHEMA_INVALID"),
    ("redaction rule count negative", _set(["redaction", "rules", 0, "count"], -1), "SCHEMA_INVALID"),
    ("redaction notes not strings", _set(["redaction", "notes"], [1]), "SCHEMA_INVALID"),
    ("no limitations", _set(["limitations"], []), "SCHEMA_INVALID"),
    ("unknown top-level field", _set(["verified"], True), "UNKNOWN_FIELD"),
    ("unknown field in a lane", _set(["lanes", 0, "passed"], True), "UNKNOWN_FIELD"),
    ("unknown field in native", _set(["lanes", 0, "native", "verified"], True), "UNKNOWN_FIELD"),
    ("unknown field in a verdict", _set(["accounting", "results", 0, "verdict", "trusted"], True), "UNKNOWN_FIELD"),
    ("unknown field in redaction", _set(["redaction", "secret"], "x"), "UNKNOWN_FIELD"),
    ("nested object in an informational field", _set(["extensions"], {"k": {"a": 1}}), "SCHEMA_INVALID"),
]


@pytest.mark.parametrize("name,mutate,code", NEGATIVE, ids=[n[0] for n in NEGATIVE])
def test_the_schema_refuses(report, name, mutate, code):
    mutate(report)
    assert code in {c for c, _, _ in check_document(report, REPORT_ID)[0]}


def test_informational_additions_are_listed_not_refused(report):
    report["environment"]["kernel"] = "6.8"
    report["extensions"] = {"run-label": "nightly", "retries": 0}
    problems, info, notes = check_document(report, REPORT_ID)
    assert problems == [] and sorted(info) == ["/environment/kernel", "/extensions/retries", "/extensions/run-label"] and notes == []


def test_a_document_that_is_not_an_object_is_refused():
    for doc in ([], "x", 1, None):
        assert check_document(doc, REPORT_ID)[0][0][0] == "SCHEMA_INVALID"


# ---- semantic checks -------------------------------------------------------------------------------------------------------------------
SEMANTIC = [
    ("duplicate lane id", lambda r: r["lanes"][1].update({"lane_id": "browser"}), "DUPLICATE_LANE_ID"),
    ("duplicate lane run id", lambda r: r["lanes"][1].update({"run_id": "r0-test.browser"}), "DUPLICATE_RUN_ID"),
    ("duplicate artifact in a lane", lambda r: r["lanes"][0]["native"]["artifacts"].append(dict(r["lanes"][0]["native"]["artifacts"][0])), "DUPLICATE_ARTIFACT"),
    ("finished before started", lambda r: r.update({"finished_at": "2025-01-01T00:00:00Z"}), "TIME_ORDER"),
    ("duplicate frozen assertion", lambda r: r["assertion_set"]["assertions"][1].update({"assertion_id": "A-STATUS"}), "DUPLICATE_ASSERTION_ID"),
    ("frozen assertion on an unknown lane", lambda r: r["assertion_set"]["assertions"][0].update({"lane_id": "ghost"}), "UNKNOWN_LANE"),
    ("assertion set digest wrong", lambda r: r["assertion_set"].update({"digest": "sha256:" + "0" * 64}), "ASSERTION_SET_DIGEST_MISMATCH"),
    ("a frozen assertion is not accounted", lambda r: r["accounting"]["results"].pop(), "ACCOUNTING_MISSING"),
    ("an assertion is accounted twice", lambda r: r["accounting"]["results"].append(copy.deepcopy(r["accounting"]["results"][0])), "ACCOUNTING_DUPLICATE"),
    ("an assertion outside the frozen set is accounted", lambda r: r["accounting"]["results"][0].update({"assertion_id": "A-GHOST"}), "ACCOUNTING_UNKNOWN"),
    ("result on another lane", lambda r: r["accounting"]["results"][0].update({"lane_id": "robot"}), "ACCOUNTING_LANE_MISMATCH"),
    ("frozen count wrong", lambda r: r["accounting"].update({"frozen": 4}), "ACCOUNTING_COUNT_MISMATCH"),
    ("verified count wrong", lambda r: r["accounting"].update({"verified": 3}), "ACCOUNTING_COUNT_MISMATCH"),
    ("failed count wrong", lambda r: r["accounting"].update({"failed": 0}), "ACCOUNTING_COUNT_MISMATCH"),
    ("inconclusive count wrong", lambda r: r["accounting"].update({"inconclusive": 1}), "ACCOUNTING_COUNT_MISMATCH"),
    ("unaccounted count wrong", lambda r: r["accounting"].update({"unaccounted": 1}), "ACCOUNTING_COUNT_MISMATCH"),
    ("UNACCOUNTED with provenance", lambda r: r["accounting"]["results"][0]["verdict"].update({"state": "UNACCOUNTED"}), "PROVENANCE_RULE"),
    ("VERIFIED without provenance", lambda r: r["accounting"]["results"][0]["verdict"].update({"provenance": None}), "PROVENANCE_RULE"),
    ("VERIFIED without evidence", lambda r: r["accounting"]["results"][0]["verdict"]["provenance"].update({"evidence": None}), "PROVENANCE_RULE"),
    ("verdict over another assertion digest", lambda r: r["accounting"]["results"][0]["verdict"]["provenance"].update({"assertion_digest": "sha256:" + "0" * 64}),
     "VERDICT_ASSERTION_DIGEST_MISMATCH"),
    ("another verifier per assertion", lambda r: r["accounting"]["results"][0]["verdict"]["provenance"]["verifier"].update({"version": "9"}), "VERIFIER_MISMATCH"),
    ("outcome VERIFIED while one failed", lambda r: r["verdict"].update({"outcome": "VERIFIED"}), "VERDICT_OUTCOME_MISMATCH"),
    ("outcome FAILED while all verified", lambda r: (_total(r)["verdict"].update({"state": "VERIFIED"}), r["accounting"].update({"verified": 3, "failed": 0})), "VERDICT_OUTCOME_MISMATCH"),
    ("verdict bound to another assertion set", lambda r: r["verdict"]["provenance"].update({"assertion_set_digest": "sha256:" + "0" * 64}), "VERDICT_ASSERTION_DIGEST_MISMATCH"),
    ("verdict bound to other evidence", lambda r: r["verdict"]["provenance"].update({"evidence_set_digest": "sha256:" + "0" * 64}), "EVIDENCE_SET_DIGEST_MISMATCH"),
    ("required limitation missing", lambda r: r["limitations"].pop(0), "LIMITATION_MISSING"),
    ("required limitation altered", lambda r: r["limitations"][0].update({"text": "all is well"}), "LIMITATION_ALTERED"),
    ("limitation id repeated", lambda r: r["limitations"].append(dict(r["limitations"][0])), "LIMITATION_DUPLICATE"),
]


@pytest.mark.parametrize("name,mutate,code", SEMANTIC, ids=[n[0] for n in SEMANTIC])
def test_the_semantic_check_refuses(report, name, mutate, code):
    mutate(report)
    assert check_document(report, REPORT_ID)[0] == []
    assert code in semantic_codes(report)


def test_an_extra_limitation_is_allowed(report):
    report["limitations"].append({"id": "own-note", "text": "this run used a seeded defect"})
    assert check_report(report) == []


# ---- assembly ----------------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("states,frozen,outcome", [
    (["VERIFIED", "VERIFIED"], 2, "VERIFIED"), (["VERIFIED", "FAILED"], 2, "FAILED"), (["FAILED", "UNACCOUNTED"], 2, "FAILED"),
    (["VERIFIED", "INCONCLUSIVE"], 2, "INCONCLUSIVE"), (["VERIFIED", "UNACCOUNTED"], 2, "INCONCLUSIVE"), ([], 0, "INCONCLUSIVE"),
    (["VERIFIED"], 2, "INCONCLUSIVE")])
def test_the_run_outcome_comes_only_from_the_verdicts(states, frozen, outcome):
    assert compute_outcome(states, frozen) == outcome


def test_a_frozen_assertion_without_a_result_is_recorded_as_unaccounted():
    rep, _, _ = inputs()
    results = [r for r in _results(rep) if r["assertion_id"] != "A-URL"]
    out = assemble_report(run_id="r0-test", started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:09Z", plan_digest=rep["plan_digest"],
                          environment=rep["environment"], lanes=rep["lanes"], frozen=rep["assertion_set"]["assertions"], results=results,
                          verifier={"id": "qa-verify", "version": "0.1.0"})
    entry = next(e for e in out["accounting"]["results"] if e["assertion_id"] == "A-URL")
    assert entry["verdict"] == {"state": "UNACCOUNTED", "reason_code": "NO_RESULT_RECORDED", "provenance": None}
    assert out["accounting"]["unaccounted"] == 1 and out["verdict"]["outcome"] == "FAILED" and check_report(out) == []


def _results(rep):
    out = []
    for e in rep["accounting"]["results"]:
        p = e["verdict"]["provenance"]
        out.append({"assertion_id": e["assertion_id"], "native_status": e["native_status"], "state": e["verdict"]["state"],
                    "reason_code": e["verdict"]["reason_code"], "evidence": p["evidence"]})
    return out


def test_digests_do_not_depend_on_input_order():
    rep, _, _ = inputs()
    a = rep["assertion_set"]["assertions"]
    assert assertion_set_digest(a) == assertion_set_digest(list(reversed(a)))
    r = rep["accounting"]["results"]
    assert evidence_set_digest(r) == evidence_set_digest(list(reversed(r)))
    assert assertion_set_digest(a[:2]) != assertion_set_digest(a)


def test_standard_limitations_are_the_required_ones():
    assert [x["id"] for x in standard_limitations()] == list(constants.REQUIRED_LIMITATION_IDS)
    assert "UNKEYED" in constants.LIMITATION_TEXTS["unkeyed-hash-chain"]
