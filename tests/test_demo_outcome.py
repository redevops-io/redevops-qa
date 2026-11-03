# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""tools/check_demo_outcome.py: what the public CI demo must show for each seeded defect, and what the second job's verification must show. Synthetic bundles and outputs; the real
ones are produced by the demo jobs. A checker that accepted a wrong outcome would make the three jobs say nothing, so every way of being wrong is tried."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from bundle_helpers import ROOT, load_tool

cd = load_tool("check_demo_outcome")
PLAN = "sha256:" + "3" * 64
FAILING = {"none": None, "discount": "robot", "settings": "browser"}
EXIT = {"none": 0, "discount": 1, "settings": 1}
NATIVE = {"none": ("NATIVE_PASS", "NATIVE_PASS"), "discount": ("NATIVE_PASS", "NATIVE_FAIL"), "settings": ("NATIVE_FAIL", "NATIVE_PASS")}


def make_bundle(root: Path, defect: str, *, mutate=None):
    results = [{"assertion_id": a, "lane_id": lane, "verdict": {"state": state, "reason_code": reason}} for a, (lane, state, reason) in cd.EXPECT[defect]["assertions"].items()]
    failed = sum(1 for r in results if r["verdict"]["state"] == "FAILED")
    report = {"run_id": "r0-test", "plan_digest": PLAN,
              "verdict": {"outcome": "FAILED" if failed else "VERIFIED", "reason_code": "ASSERTION_FAILED" if failed else "ALL_ASSERTIONS_VERIFIED"},
              "accounting": {"frozen": 4, "verified": 4 - failed, "failed": failed, "inconclusive": 0, "unaccounted": 0, "results": results},
              "lanes": [{"lane_id": "browser", "native": {"status": NATIVE[defect][0]}}, {"lane_id": "robot", "native": {"status": NATIVE[defect][1]}}]}
    manifest = b'{"files": []}\n'
    if mutate:
        report, manifest = mutate(report, manifest)
    bundle = root / "evidence" / "r0-test"
    bundle.mkdir(parents=True)
    (bundle / "report.json").write_text(json.dumps(report))
    (bundle / "bundle-manifest.json").write_bytes(manifest)
    digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    output = (f"run r0-test: {report['verdict']['outcome']}\n  external anchor: no external anchor: integrity NOT established\n  plan digest: {PLAN}   (the value)\n"
              f"  manifest digest: {digest}   (an anchor only if published)\n  re-verification in a fresh process: ACCEPTED as internally consistent; 4 of 4\n")
    return root / "evidence", output, digest


def run(root, defect, output, exit_code=None, evidence=None):
    return cd.check_run(defect, EXIT[defect] if exit_code is None else exit_code, output, evidence or root / "evidence")


@pytest.mark.parametrize("defect", ["none", "discount", "settings"])
def test_each_seeded_defect_has_exactly_one_accepted_outcome(tmp_path, defect):
    evidence, output, digest = make_bundle(tmp_path, defect)
    problems, info = run(tmp_path, defect, output)
    assert problems == [] and info["anchor"] == digest and info["plan_digest"] == PLAN and info["run_id"] == "r0-test"
    for other in ("none", "discount", "settings"):
        if other != defect:
            assert run(tmp_path, other, output)[0], f"the {defect} bundle was accepted as the {other} one"


def test_the_expected_exit_statuses_are_the_matrix_of_the_workflow():
    import yaml
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8"))
    for job in ("demo", "demo-verify"):
        assert {m["defect"]: m["exit"] for m in wf["jobs"][job]["strategy"]["matrix"]["include"]} == {d: cd.EXPECT[d]["exit"] for d in cd.EXPECT} == EXIT


def test_a_wrong_exit_status_is_refused(tmp_path):
    _, output, _ = make_bundle(tmp_path, "none")
    assert any("exited 1" in p for p in run(tmp_path, "none", output, exit_code=1)[0])


def test_a_clean_outcome_with_a_defect_that_was_not_found_is_refused(tmp_path):
    _, output, _ = make_bundle(tmp_path, "none")
    problems, _ = run(tmp_path, "discount", output, exit_code=1)
    assert any("outcome is VERIFIED" in p for p in problems) and any("assertion A-ORDER-RULE" in p for p in problems)


def test_a_failure_in_the_wrong_lane_is_refused(tmp_path):
    _, output, _ = make_bundle(tmp_path, "discount")
    problems, _ = run(tmp_path, "settings", output)
    assert any("assertion A-NOTIF-ON" in p for p in problems) and any("assertion A-ORDER-RULE" in p for p in problems)


def test_an_unaccounted_or_inconclusive_assertion_is_refused(tmp_path):
    def unaccounted(report, manifest):
        report["accounting"]["unaccounted"] = 1
        report["accounting"]["verified"] = 3
        report["accounting"]["results"][0]["verdict"]["state"] = "UNACCOUNTED"
        return report, manifest
    _, output, _ = make_bundle(tmp_path, "none", mutate=unaccounted)
    problems, _ = run(tmp_path, "none", output)
    assert any("the accounting is" in p for p in problems) and any("assertion A-SAVED" in p for p in problems)


def test_a_printed_anchor_that_is_not_the_digest_of_the_manifest_is_refused(tmp_path):
    _, output, digest = make_bundle(tmp_path, "none")
    problems, _ = run(tmp_path, "none", output.replace(digest, "sha256:" + "0" * 64))
    assert any("is not the sha256 of bundle-manifest.json" in p for p in problems)
    assert any("printed 0 manifest digests" in p for p in run(tmp_path, "none", output.replace("manifest digest:", "digest of the manifest:"))[0])
    assert any("printed 2 manifest digests" in p for p in run(tmp_path, "none", output + output.splitlines()[3] + "\n")[0])


def test_a_plan_digest_that_is_not_the_reports_is_refused(tmp_path):
    _, output, _ = make_bundle(tmp_path, "none")
    assert any("plan digest" in p for p in run(tmp_path, "none", output.replace(PLAN, "sha256:" + "4" * 64))[0])


def test_the_demos_own_reverification_and_its_honest_anchor_line_are_required(tmp_path):
    _, output, _ = make_bundle(tmp_path, "none")
    assert any("re-verification" in p for p in run(tmp_path, "none", output.replace("ACCEPTED as internally consistent", "REJECTED"))[0])
    assert any("no external anchor" in p for p in run(tmp_path, "none", output.replace("no external anchor", "anchored"))[0])


def test_the_engines_native_statuses_must_be_the_expected_ones(tmp_path):
    def swapped(report, manifest):
        report["lanes"][0]["native"]["status"] = "NATIVE_FAIL"
        return report, manifest
    _, output, _ = make_bundle(tmp_path, "none", mutate=swapped)
    assert any("engines reported" in p for p in run(tmp_path, "none", output)[0])


def test_no_bundle_two_bundles_or_an_unreadable_one_are_refused(tmp_path):
    (tmp_path / "empty").mkdir()
    assert any("found 0" in p for p in cd.check_run("none", 0, "", tmp_path / "empty")[0])
    evidence, output, _ = make_bundle(tmp_path, "none")
    (evidence / "r0-other").mkdir()
    assert any("found 2" in p for p in run(tmp_path, "none", output)[0])
    (evidence / "r0-other").rmdir()
    (evidence / "r0-test" / "report.json").write_text("{")
    assert any("cannot be read" in p for p in run(tmp_path, "none", output)[0])


def verify_result(defect, **over):
    base = {"accepted": True, "exit_code": EXIT[defect], "findings": [], "anchor": {"state": "matches-supplied-value", "matches_supplied_value": True},
            "plan": {"state": "verified", "matches_supplied_value": True}, "recomputed_assertions": 4, "agreeing_assertions": 4,
            "run_outcome": {"outcome": "VERIFIED" if defect == "none" else "FAILED"}, "engine_verifier_disagreements": []}
    base.update(over)
    return base


@pytest.mark.parametrize("defect", ["none", "discount", "settings"])
def test_a_second_verification_that_accepts_the_bundle_with_the_anchor_passes(defect):
    assert cd.check_verify(defect, EXIT[defect], verify_result(defect)) == []


@pytest.mark.parametrize("over,needle", [({"accepted": False}, "not accepted"), ({"findings": [{"code": "X"}]}, "not accepted"),
                                         ({"anchor": {"state": "absent", "matches_supplied_value": False}}, "anchor did not match"),
                                         ({"plan": {"state": "absent", "matches_supplied_value": False}}, "plan digest did not match"),
                                         ({"agreeing_assertions": 3}, "3 of 4"), ({"recomputed_assertions": 3}, "of 3"),
                                         ({"run_outcome": {"outcome": "FAILED"}}, "recomputed outcome"), ({"engine_verifier_disagreements": [{}]}, "disagree"),
                                         ({"exit_code": 5}, "verify exited")])
def test_a_second_verification_that_shows_anything_else_is_refused(over, needle):
    problems = cd.check_verify("none", 0, verify_result("none", **over))
    assert any(needle in p for p in problems), problems


def test_the_exit_status_of_the_verify_command_must_be_the_runs():
    assert cd.check_verify("discount", 0, verify_result("discount"))             # an accepted failing run exits 1, not 0
    assert cd.check_verify("none", 5, verify_result("none"))


def test_the_command_line_writes_the_anchor_only_when_everything_holds(tmp_path):
    evidence, output, digest = make_bundle(tmp_path, "settings")
    (tmp_path / "demo.out").write_text(output)
    argv = [sys.executable, "-I", str(ROOT / "tools" / "check_demo_outcome.py"), "run", "--defect", "settings", "--exit-code", "1", "--output", str(tmp_path / "demo.out"),
            "--evidence-root", str(evidence), "--anchor-out", str(tmp_path / "anchor" / "a.txt")]
    done = subprocess.run(argv, capture_output=True, text=True, cwd=str(tmp_path))
    assert done.returncode == 0 and f"ANCHOR defect=settings run_id=r0-test {digest}" in done.stdout
    assert (tmp_path / "anchor" / "a.txt").read_text() == f"defect=settings\nrun_id=r0-test\nanchor={digest}\nplan_digest={PLAN}\nbundle=r0-test\n"
    (tmp_path / "anchor" / "a.txt").unlink()
    argv[argv.index("--exit-code") + 1] = "0"
    bad = subprocess.run(argv, capture_output=True, text=True, cwd=str(tmp_path))
    assert bad.returncode == 1 and "FAIL settings" in bad.stderr and not (tmp_path / "anchor" / "a.txt").exists()
    (tmp_path / "v.json").write_text(json.dumps(verify_result("settings")))
    ok = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "check_demo_outcome.py"), "verify", "--defect", "settings", "--exit-code", "1", "--result", str(tmp_path / "v.json")],
                        capture_output=True, text=True, cwd=str(tmp_path))
    assert ok.returncode == 0 and "OK verify settings" in ok.stdout
    missing = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "check_demo_outcome.py"), "verify", "--defect", "none", "--exit-code", "0", "--result", str(tmp_path / "nothing.json")],
                             capture_output=True, text=True, cwd=str(tmp_path))
    assert missing.returncode == 1


# ------------------------------------------------------------------------------------------------------------- exact expectations: the seeded defect and nothing more
def edit_results(fn):
    def mutate(report, manifest):
        fn(report["accounting"]["results"], report)
        res = report["accounting"]["results"]
        report["accounting"]["failed"] = sum(1 for r in res if r["verdict"]["state"] == "FAILED")
        report["accounting"]["verified"] = sum(1 for r in res if r["verdict"]["state"] == "VERIFIED")
        report["accounting"]["frozen"] = len(res)
        return report, manifest
    return mutate


def set_state(results, aid, state, reason=None):
    for r in results:
        if r["assertion_id"] == aid:
            r["verdict"]["state"] = state
            if reason:
                r["verdict"]["reason_code"] = reason


def test_a_settings_report_in_which_the_whole_browser_lane_fails_is_not_the_seeded_defect(tmp_path):
    """The reviewer's case: every browser verdict FAILED (a broken login or navigation) used to be accepted as 'the settings defect was found'."""
    def whole_lane(results, report):
        for aid in ("A-SAVED", "A-NOTIF-ON", "A-URL"):
            set_state(results, aid, "FAILED", "EXPECTED_VALUE_DIFFERS")
    _, output, _ = make_bundle(tmp_path, "settings", mutate=edit_results(whole_lane))
    problems, _ = run(tmp_path, "settings", output)
    assert any("assertion A-SAVED" in p for p in problems) and any("assertion A-URL" in p for p in problems) and any("the accounting is" in p for p in problems)


@pytest.mark.parametrize("defect,extra", [("settings", "A-SAVED"), ("settings", "A-ORDER-RULE"), ("discount", "A-URL"), ("discount", "A-NOTIF-ON"), ("none", "A-ORDER-RULE")])
def test_an_extra_failing_assertion_is_refused(tmp_path, defect, extra):
    _, output, _ = make_bundle(tmp_path, defect, mutate=edit_results(lambda res, rep: set_state(res, extra, "FAILED", "EXPECTED_VALUE_DIFFERS")))
    problems, _ = run(tmp_path, defect, output)
    assert any(f"assertion {extra}" in p for p in problems)


@pytest.mark.parametrize("defect,missing", [("settings", "A-NOTIF-ON"), ("discount", "A-ORDER-RULE")])
def test_the_seeded_assertion_that_does_not_fail_is_refused(tmp_path, defect, missing):
    _, output, _ = make_bundle(tmp_path, defect, mutate=edit_results(lambda res, rep: set_state(res, missing, "VERIFIED", "EQUALS_EXPECTED")))
    assert any(f"assertion {missing}" in p for p in run(tmp_path, defect, output)[0])


@pytest.mark.parametrize("defect,aid", [("settings", "A-NOTIF-ON"), ("discount", "A-ORDER-RULE")])
def test_the_failing_assertion_must_fail_for_the_expected_reason(tmp_path, defect, aid):
    _, output, _ = make_bundle(tmp_path, defect, mutate=edit_results(lambda res, rep: set_state(res, aid, "FAILED", "OBSERVATION_MISSING")))
    problems, _ = run(tmp_path, defect, output)
    assert any(f"assertion {aid}" in p and "OBSERVATION_MISSING" in p for p in problems)


def test_an_assertion_that_moved_to_another_lane_or_is_missing_or_unknown_is_refused(tmp_path):
    def moved(res, rep):
        next(r for r in res if r["assertion_id"] == "A-URL")["lane_id"] = "robot"
    _, output, _ = make_bundle(tmp_path, "none", mutate=edit_results(moved))
    assert any("assertion A-URL" in p for p in run(tmp_path, "none", output)[0])
    _, output, _ = make_bundle(tmp_path / "b", "none", mutate=edit_results(lambda res, rep: res.pop()))
    assert any("A-ORDER-RULE is missing" in p for p in run(tmp_path / "b", "none", output)[0])
    _, output, _ = make_bundle(tmp_path / "c", "none", mutate=edit_results(lambda res, rep: res.append({"assertion_id": "A-EXTRA", "lane_id": "browser", "verdict": {"state": "VERIFIED", "reason_code": "EQUALS_EXPECTED"}})))
    assert any("A-EXTRA is not one of the plan's" in p for p in run(tmp_path / "c", "none", output)[0])
    _, output, _ = make_bundle(tmp_path / "d", "none", mutate=edit_results(lambda res, rep: res.append(dict(res[0]))))
    assert any("appears twice" in p for p in run(tmp_path / "d", "none", output)[0])


def test_a_verified_state_with_the_wrong_reason_code_is_refused_even_for_a_clean_run(tmp_path):
    _, output, _ = make_bundle(tmp_path, "none", mutate=edit_results(lambda res, rep: set_state(res, "A-URL", "VERIFIED", "EQUALS_EXPECTED")))
    assert any("assertion A-URL" in p and "EQUALS_EXPECTED" in p for p in run(tmp_path, "none", output)[0])


def test_the_exact_table_is_what_the_demo_page_and_the_demo_itself_say():
    """The counts the docs promise (settings 2 of 3 browser + 1 of 1 Robot, discount 3 of 3 + 0 of 1) follow from the table, and the table equals what the real runs printed."""
    count = lambda d, lane, st: sum(1 for (l, s, _r) in cd.EXPECT[d]["assertions"].values() if l == lane and s == st)
    assert (count("settings", "browser", "VERIFIED"), count("settings", "robot", "VERIFIED")) == (2, 1) and count("settings", "browser", "FAILED") == 1
    assert (count("discount", "browser", "VERIFIED"), count("discount", "robot", "VERIFIED")) == (3, 0) and count("discount", "robot", "FAILED") == 1
    assert sum(1 for (_l, s, _r) in cd.EXPECT["none"]["assertions"].values() if s == "VERIFIED") == 4
    assert {a for a, v in cd.EXPECT["settings"]["assertions"].items() if v[1] == "FAILED"} == {"A-NOTIF-ON"} and {a for a, v in cd.EXPECT["discount"]["assertions"].items() if v[1] == "FAILED"} == {"A-ORDER-RULE"}
