# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The Playwright-only view and the full view: two views of the same run data, never a second run."""
import ast
import copy
import inspect
import json
from pathlib import Path

import pytest

from redevops_qa_checks import cli, views as V

PKG = Path(__file__).resolve().parents[1]
H = "rcv1:" + "a" * 64


def res(aid, executor, verdict="PASS", **extra):
    return {"assertion_id": aid, "assertion_set_hash": H, "expected_hash": "rcv1:" + "b" * 64, "executor": executor,
            "check": {"check_id": aid, "verdict": verdict, "determinism": "DETERMINISTIC", "evidence_refs": extra.pop("evidence", [])},
            "verifier": {"id": "v", "version": "1"}, **extra}


RESULTS = [res("a-ui-1", "PLAYWRIGHT"), res("a-ui-2", "PLAYWRIGHT", "FAIL", reason_code=None), res("a-img", "SCRIPT"),
           res("a-net", "SCRIPT", "INDETERMINATE", reason_code="SUBJECT_UNRESOLVED"), res("a-ui-3", "PLAYWRIGHT", "INDETERMINATE", reason_code="SUBJECT_AMBIGUOUS")]


def test_the_playwright_view_is_exactly_the_playwright_rows_of_the_full_view():
    run = V.run_data(RESULTS)
    full, pw = V.full_view(run), V.playwright_view(run)
    assert [r["assertion_id"] for r in pw["rows"]] == ["a-ui-1", "a-ui-2", "a-ui-3"]
    assert pw["rows"] == [r for r in full["rows"] if r["executor"] == "PLAYWRIGHT"]
    assert all(r in full["rows"] for r in pw["rows"]) and full["totals"]["total"] == 5 and pw["totals"]["total"] == 3


def test_totals_reconcile_and_are_reported_as_data():
    run = V.run_data(RESULTS)
    rec = V.reconciliation(run)
    assert rec["reconciles"] is True and rec["problems"] == []
    assert (rec["full_total"], rec["playwright_total"], rec["script_total"], rec["unknown_executor_total"]) == (5, 3, 2, 0)
    full = V.full_view(run)["totals"]
    assert full["by_executor"] == {"PLAYWRIGHT": 3, "SCRIPT": 2} and full["by_verdict"] == {"FAIL": 1, "INDETERMINATE": 2, "PASS": 2}
    assert V.playwright_view(run)["totals"]["by_verdict"] == {"FAIL": 1, "INDETERMINATE": 1, "PASS": 1}
    V.assert_reconciles(run)


def test_both_views_name_the_same_source_run():
    run = V.run_data(RESULTS)
    assert V.full_view(run)["source_run_digest"] == V.playwright_view(run)["source_run_digest"] == V.script_view(run)["source_run_digest"] == run.digest


def test_the_views_are_pure_functions_of_the_run_data_and_repeat_exactly():
    run = V.run_data(RESULTS)
    assert V.full_view(run) == V.full_view(V.run_data(list(reversed(RESULTS)))) and V.playwright_view(run) == V.playwright_view(V.run_data(RESULTS))
    assert V.run_data(RESULTS).digest == V.run_data(list(reversed(RESULTS))).digest


def test_a_view_takes_the_run_data_and_nothing_else_so_it_cannot_run_anything():
    for fn in (V.full_view, V.playwright_view, V.script_view, V.reconciliation):
        assert list(inspect.signature(fn).parameters) == ["run"]


def test_the_views_module_imports_no_adapter_runner_process_or_file_code():
    tree = ast.parse((PKG / "src/redevops_qa_checks/views.py").read_text(encoding="utf-8"))
    absolute, relative, calls = set(), set(), set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            absolute |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            (relative if n.level else absolute).add((n.module or "").split(".")[0])
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
            calls.add(n.func.id)
    assert absolute <= {"__future__", "collections", "dataclasses", "typing"} and relative <= {"canonical", "errors"}
    assert not calls & {"open", "exec", "eval", "compile", "__import__"}


def test_an_executor_this_version_does_not_know_is_non_certifying_and_in_no_executor_view():
    run = V.run_data(RESULTS + [res("a-new", "FUTURE_EXECUTOR")])
    full = V.full_view(run)
    row = [r for r in full["rows"] if r["assertion_id"] == "a-new"][0]
    assert row["executor_known"] is False
    assert all(r["assertion_id"] != "a-new" for r in V.playwright_view(run)["rows"] + V.script_view(run)["rows"])
    rec = V.reconciliation(run)
    assert rec["reconciles"] is True and rec["unknown_executor_total"] == 1 and rec["full_total"] == 6


def test_results_of_two_assertion_sets_are_not_one_run():
    other = copy.deepcopy(RESULTS[0])
    other["assertion_set_hash"] = "rcv1:" + "c" * 64
    other["assertion_id"] = "a-other"
    with pytest.raises(V.ViewRefused):
        V.run_data(RESULTS + [other])


@pytest.mark.parametrize("bad", [{"executor": "SCRIPT", "check": {"verdict": "PASS"}}, {"assertion_id": "a", "check": {"verdict": "PASS"}},
                                 {"assertion_id": "a", "executor": "SCRIPT"}, {"assertion_id": "", "executor": "SCRIPT", "check": {"verdict": "PASS"}},
                                 {"assertion_id": "a", "executor": 5, "check": {"verdict": "PASS"}}, "x", 5, None])
def test_a_malformed_result_is_refused(bad):
    with pytest.raises(V.ViewRefused):
        V.run_data([bad])


def test_two_results_for_one_assertion_are_refused():
    with pytest.raises(V.ViewRefused):
        V.run_data([res("a", "SCRIPT"), res("a", "PLAYWRIGHT")])


def test_the_manifest_coverage_lists_and_a_mismatch_with_the_results_are_reported():
    manifest = {"assertion_set_hash": H, "assertions_declared": ["a-ui-1", "a-ui-2", "a-ui-3", "a-img", "a-net", "a-skipped-ui"],
                "assertions_executed": ["a-ui-1", "a-ui-2", "a-ui-3", "a-img", "a-net"],
                "assertions_skipped": [{"assertion_id": "a-skipped-ui", "reason_code": "NOT_REACHED"}]}
    assertions = [{"assertion_id": a, "executor": e} for a, e in [("a-ui-1", "PLAYWRIGHT"), ("a-ui-2", "PLAYWRIGHT"), ("a-ui-3", "PLAYWRIGHT"),
                                                                 ("a-skipped-ui", "PLAYWRIGHT"), ("a-img", "SCRIPT"), ("a-net", "SCRIPT")]]
    run = V.run_data(RESULTS, manifest=manifest, assertions=assertions)
    pw = V.playwright_view(run)["coverage"]
    assert pw["declared"] == 4 and pw["skipped"] == [{"assertion_id": "a-skipped-ui", "reason_code": "NOT_REACHED"}] and pw["declared_not_executed"] == ["a-skipped-ui"]
    assert V.script_view(run)["coverage"]["declared"] == 2 and V.reconciliation(run)["reconciles"] is True
    bad = dict(manifest, assertions_executed=["a-ui-1"])
    rec = V.reconciliation(V.run_data(RESULTS, manifest=bad))
    assert rec["reconciles"] is False and "a-img" in rec["manifest_executed_differs_on"]
    with pytest.raises(V.ViewRefused):
        V.assert_reconciles(V.run_data(RESULTS, manifest=bad))


def test_a_manifest_for_another_assertion_set_is_refused():
    with pytest.raises(V.ViewRefused):
        V.run_data(RESULTS, manifest={"assertion_set_hash": "rcv1:" + "d" * 64, "assertions_declared": []})


def test_the_views_carry_no_pooled_number_across_runs():
    text = json.dumps([V.full_view(V.run_data(RESULTS)), V.playwright_view(V.run_data(RESULTS))])
    for word in ("pooled", "overall", "combined", "average", "rate"):
        assert word not in text


# -- real results from the harness verifier ---------------------------------------------------------------------------------------------------------

def test_views_over_the_results_of_one_real_run_with_both_executors(case_root, registry, neutral):
    from agent_harness.qa import records as R, specstore, verifier
    from redevops_qa_checks.adapter import CheckAdapter
    from redevops_qa_checks.manifests import tree_digest

    class FakeQA:
        def assert_(self, s, subject):
            return R.ObservedValue(resolution=R.Resolution.RESOLVED, match_count=1, value="Saved")
    pid = "manifest.structure.counts"
    ref = {"id": pid, "version": "1.0.0", "program_hash": registry.registered_program_hash(pid, "1.0.0")}
    docs = [
        {"schema_id": "runtime-contracts/qa/assertion-spec", "schema_version": "0.1", "assertion_id": "a-saved", "executor": "PLAYWRIGHT",
         "determinism": "DETERMINISTIC", "on_unresolvable": "INDETERMINATE", "predicate": {"op": "EQUALS", "expected": "Saved"},
         "subject": {"kind": "UI_ELEMENT", "inputs": [], "locator": {"frame_path": [], "test_id": "save-status"}, "subject_alternates": []},
         "verifier_id": verifier.VERIFIER_ID, "verifier_version_range": ">=0.0,<99"},
        {"schema_id": "runtime-contracts/qa/assertion-spec", "schema_version": "0.1", "assertion_id": "a-wrong", "executor": "PLAYWRIGHT",
         "determinism": "DETERMINISTIC", "on_unresolvable": "INDETERMINATE", "predicate": {"op": "EQUALS", "expected": "Other"},
         "subject": {"kind": "UI_ELEMENT", "inputs": [], "locator": {"frame_path": [], "test_id": "x"}, "subject_alternates": []},
         "verifier_id": verifier.VERIFIER_ID, "verifier_version_range": ">=0.0,<99"},
        {"schema_id": "runtime-contracts/qa/assertion-spec", "schema_version": "0.1", "assertion_id": "a-docs", "executor": "SCRIPT",
         "check_program_ref": ref, "determinism": "DETERMINISTIC", "on_unresolvable": "INDETERMINATE", "predicate": {"op": "EXISTS"},
         "subject": {"kind": "RESOURCE_INPUTS", "inputs": [{"kind": "MANIFEST_PATH", "path": "."}], "subject_alternates": []},
         "verifier_id": verifier.VERIFIER_ID, "verifier_version_range": ">=0.0,<99"}]
    pin = verifier.assertion_set_pin(tuple(R.AssertionSpec.from_json(d) for d in docs))
    adapter = CheckAdapter(case_root, registry=registry)
    w = adapter.open_workspace(R.CheckProfile(case_root_digest=tree_digest(case_root), tier=R.CheckTier.OFFLINE))
    results = verifier.DeterministicVerifier(programs=registry, qa_adapter=FakeQA(), check_adapter=adapter).verify_run(
        specstore.InMemorySpecStore({pin: docs}), pin, lineage=verifier.ApprovedLineage([pin]), session=None, workspace=w)
    run = V.run_data([r.to_json() for r in results], assertions=docs)
    full, pw = V.full_view(run), V.playwright_view(run)
    assert [r["assertion_id"] for r in full["rows"]] == ["a-docs", "a-saved", "a-wrong"]
    assert [(r["assertion_id"], r["verdict"]) for r in pw["rows"]] == [("a-saved", "PASS"), ("a-wrong", "FAIL")]
    assert V.reconciliation(run)["reconciles"] is True and V.script_view(run)["totals"]["total"] == 1
    assert pw["rows"] == [r for r in full["rows"] if r["executor"] == "PLAYWRIGHT"]
    run2 = V.run_data([r for r in results], assertions=docs)               # records themselves are accepted too
    assert run2.digest == run.digest


# -- the command line ----------------------------------------------------------------------------------------------------------------------------------

def test_the_view_command_prints_a_view_and_writes_nothing(tmp_path, capsys):
    f = tmp_path / "run.json"
    f.write_text(json.dumps({"results": RESULTS}), encoding="utf-8")
    before = sorted(p.name for p in tmp_path.iterdir())
    for name, key in (("full", "full"), ("playwright", "playwright-only"), ("script", "script-only")):
        assert cli.main(["view", "--results", str(f), "--view", name]) == 0
        assert json.loads(capsys.readouterr().out)["view"] == key
    assert cli.main(["view", "--results", str(f), "--view", "reconciliation"]) == 0 and json.loads(capsys.readouterr().out)["reconciles"] is True
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_the_view_command_refuses_a_bad_file(tmp_path, capsys):
    f = tmp_path / "run.json"
    f.write_text("{not json", encoding="utf-8")
    assert cli.main(["view", "--results", str(f), "--view", "full"]) == 2
    g = tmp_path / "g.json"
    g.write_text(json.dumps({"results": [res("a", "SCRIPT"), res("a", "SCRIPT")]}), encoding="utf-8")
    assert cli.main(["view", "--results", str(g), "--view", "full"]) == 2
    assert cli.main(["view", "--results", str(tmp_path / "missing.json"), "--view", "full"]) == 2
