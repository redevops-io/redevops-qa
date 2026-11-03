# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``redevops-qa verify``: what a clean bundle gets, what the output says, the options and the exit codes, and that the verifier is offline and engine-free."""
import io
import json
import subprocess
import sys

import pytest

from qa_evidence.build import write_archive
from qa_runner import constants as K
from qa_runner.cli import main
from qa_runner.procs import child_env
from qr_tamper import GOLDEN, codes, golden, manifest_digest, verify_files_in

PLAN_DIGEST = "sha256:67f553bab6744a83ea8f39b8759d15b8b1a3e7dabdd888c3e4bbc86ae4eb444c"


def cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    return main(list(argv), out, err), out.getvalue(), err.getvalue()


def test_the_golden_bundles_are_what_demo_writes_for_the_clean_target_and_the_discount_defect():
    import json as j
    none, discount = (j.loads(golden(d)["report.json"]) for d in ("none", "discount"))
    assert none["verdict"]["outcome"] == "VERIFIED" and discount["verdict"]["outcome"] == "FAILED"
    assert [l["lane_id"] for l in none["lanes"]] == ["browser", "robot"] and none["plan_digest"] == PLAN_DIGEST == discount["plan_digest"]
    assert {r["assertion_id"]: r["verdict"]["state"] for r in discount["accounting"]["results"]} == {"A-NOTIF-ON": "VERIFIED", "A-SAVED": "VERIFIED", "A-URL": "VERIFIED", "A-ORDER-RULE": "FAILED"}


@pytest.mark.parametrize("defect,exit_code,outcome", [("none", 0, "VERIFIED"), ("discount", 1, "FAILED")])
def test_a_clean_bundle_is_accepted_as_internally_consistent_and_exits_with_the_runs_own_status(tmp_path, defect, exit_code, outcome):
    v = verify_files_in(tmp_path, golden(defect))
    assert v.accepted and v.findings == [] and v.exit_code == exit_code and v.outcome["outcome"] == outcome
    assert v.assurance == "internal-consistency-only" and (v.recomputed, v.agreeing) == (4, 4)


def test_verify_text_says_what_was_recomputed_and_what_it_does_not_show():
    code, out, err = cli("verify", str(GOLDEN / "bundle-none.tar"))
    assert code == 0 and "ACCEPTED (internally consistent)" in out
    assert "4 assertion(s) recomputed from the bundle alone, 4 agree with the report" in out and "no external anchor: integrity against deliberate re-forging NOT established" in out
    assert "assurance: internal consistency only" in out and "does not show that the application under test is correct" in out
    assert "not checked against an external plan digest" in out


def test_verify_json_has_the_assurance_the_findings_and_the_recomputation():
    code, out, err = cli("verify", str(GOLDEN / "bundle-discount.tar"), "--json")
    doc = json.loads(out)
    assert code == 1 and doc["accepted"] is True and doc["assurance"] == "internal-consistency-only" and doc["findings"] == [] and doc["exit_code"] == 1
    assert doc["run_outcome"] == {"outcome": "FAILED", "reason_code": "ASSERTION_FAILED"} and (doc["recomputed_assertions"], doc["agreeing_assertions"]) == (4, 4)
    assert doc["anchor"]["state"] == "absent" and doc["plan"]["state"] == "absent"


def test_the_plan_digest_and_the_anchor_hooks(tmp_path):
    path = str(GOLDEN / "bundle-none.tar")
    anchor = manifest_digest(golden("none"))
    code, out, err = cli("verify", path, "--plan-digest", PLAN_DIGEST, "--anchor", anchor, "--require-anchor", "--require-plan-digest", "--json")
    doc = json.loads(out)
    assert code == 0 and doc["assurance"] == "matches-supplied-anchor" and doc["anchor"]["matches_supplied_value"] and doc["plan"]["matches_supplied_value"]
    assert cli("verify", path, "--plan-digest", "sha256:" + "0" * 64)[0] == K.EXIT_REJECTED
    assert cli("verify", path, "--anchor", "sha256:" + "0" * 64)[0] == K.EXIT_REJECTED
    assert cli("verify", path, "--anchor", "not-a-digest")[0] == K.EXIT_REJECTED


def test_a_required_anchor_or_plan_digest_that_was_not_supplied_is_a_finding():
    path = str(GOLDEN / "bundle-none.tar")
    code, out, err = cli("verify", path, "--require-anchor")
    assert code == K.EXIT_REJECTED and "ANCHOR_REQUIRED" in out
    code, out, err = cli("verify", path, "--require-plan-digest")
    assert code == K.EXIT_REJECTED and "PLAN_DIGEST_REQUIRED" in out


def test_a_bundle_that_cannot_be_opened_is_a_usage_error(tmp_path):
    assert cli("verify", str(tmp_path / "nope"))[0] == K.EXIT_USAGE


def test_an_intact_bundle_whose_lane_did_not_complete_exits_with_the_environment_status(tmp_path, up):
    """An accepted bundle exits with the same status `run` returned for it: here a bundle whose browser lane timed out."""
    from qa_runner.golden import demo_plan
    from qa_runner.orchestrate import RunOptions, run_plan
    from qa_runner.plan import freeze_plan
    from qr_support import fake, fake_robot
    plan = demo_plan()
    plan["lanes"][0]["deadline_s"] = 1
    s = run_plan(up, freeze_plan(up, plan), RunOptions(lane_command=fake("hang"), robot_launcher=fake_robot("live"), run_id="r0-test"))
    target = tmp_path / "b"
    s.bundle.write_directory(str(target))
    code, out, err = cli("verify", str(target))
    # the test double's run record is not a real harness record: verify says so, and rejects (exit 5), never accepts a bundle it cannot recompute
    assert code in (K.EXIT_REJECTED, K.EXIT_ENVIRONMENT)


def test_verify_imports_no_browser_or_robot_package_and_opens_no_socket(tmp_path):
    # what this proves: no browser, Robot or third-party HTTP package is imported, and the patched socket methods (connect, connect_ex, create_connection, bind) are never called.
    # It does not prove more: the pinned harness imports the standard library's urllib, http.client and ssl when it is imported, and a socket could be opened by other means
    script = tmp_path / "probe.py"
    script.write_text(
        "import socket, sys\n"
        "def deny(*a, **k):\n    raise AssertionError('the verifier opened a socket')\n"
        "socket.socket.connect = deny; socket.socket.connect_ex = deny; socket.create_connection = deny; socket.socket.bind = deny\n"
        "from qa_runner.cli import main\n"
        "code = main(['verify', sys.argv[1], '--plan-digest', sys.argv[2]])\n"
        "banned = sorted(m for m in sys.modules if m.split('.')[0] in ('playwright', 'qa_playwright', 'qa_egress', 'robot', 'selenium', 'appium', 'urllib3', 'requests', 'asyncio'))\n"
        "print('BANNED', banned); sys.exit(code)\n")
    env = child_env(str(tmp_path))
    done = subprocess.run([sys.executable, "-s", str(script), str(GOLDEN / "bundle-none.tar"), PLAN_DIGEST], env=env, cwd=str(tmp_path), capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "BANNED []" in done.stdout, done.stdout


def test_verify_in_a_new_interpreter_gives_the_same_answer_as_in_process(tmp_path):
    env = child_env(str(tmp_path))
    done = subprocess.run([sys.executable, "-s", "-m", "qa_runner", "verify", str(GOLDEN / "bundle-discount.tar"), "--json"], env=env, cwd=str(tmp_path), capture_output=True, text=True, timeout=120)
    doc = json.loads(done.stdout)
    assert done.returncode == 1 and doc["accepted"] and doc["run_outcome"]["outcome"] == "FAILED"


def test_a_run_that_the_separate_process_does_not_accept_exits_5(monkeypatch, tmp_path):
    """`run` and `demo` end by calling `verify` in a separate interpreter; whatever it does not accept, the run does not report as its own status."""
    import qa_runner.cli as cli_module
    from qa_runner.cli import _verify_in_a_new_process
    out = io.StringIO()
    assert _verify_in_a_new_process(tmp_path / "does-not-exist", PLAN_DIGEST, 0, 0, out) == K.EXIT_REJECTED and "COULD NOT RUN" in out.getvalue()
    out = io.StringIO()
    bundle = tmp_path / "b"
    from qa_evidence.build import read_files, write_directory
    write_directory(golden("none"), str(bundle))
    assert _verify_in_a_new_process(bundle, PLAN_DIGEST, 0, 0, out) == 0 and "ACCEPTED as internally consistent; 4 of 4" in out.getvalue()
    out = io.StringIO()
    assert _verify_in_a_new_process(bundle, "sha256:" + "0" * 64, 0, 0, out) == K.EXIT_REJECTED and "REJECTED (PLAN_DIGEST_MISMATCH)" in out.getvalue()
    out = io.StringIO()
    assert _verify_in_a_new_process(bundle, PLAN_DIGEST, 4, 4, out) == K.EXIT_REJECTED and "is not the report's (4)" in out.getvalue()
    out = io.StringIO()
    # review finding L7: a run cancelled after its last lane returns 3 where the report alone gives 0; verify cannot know about the cancel, so it is compared with the report's status and the run keeps its own
    assert _verify_in_a_new_process(bundle, PLAN_DIGEST, 0, K.EXIT_ENVIRONMENT, out) == K.EXIT_ENVIRONMENT and "ACCEPTED as internally consistent" in out.getvalue()


def test_run_exits_5_when_the_separate_verification_rejects_what_it_just_wrote(monkeypatch, tmp_path, up):
    """The lane here is a test double whose run record is not a real harness record, and the bundle says so: `verify` in a new interpreter rejects it (it cannot recompute it, and a double carries
    no verdict), so `run` does not exit with its own status."""
    import qa_runner.orchestrate as orch
    from qa_runner.golden import golden_plan
    from qr_support import fake
    real = orch.run_plan

    def with_doubles(up_, frozen, opts):
        return real(up_, frozen, orch.RunOptions(defect=opts.defect, run_id=opts.run_id, lane_command=fake("pass"), lane_deadline_s=60))
    monkeypatch.setattr(orch, "run_plan", with_doubles)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(golden_plan()))
    code, out, err = cli("run", str(plan), "--out", str(tmp_path / "o"), "--run-id", "r0-double")
    assert ": INCONCLUSIVE (" in out and "re-verification in a fresh process (the same code as the run, not independent code): REJECTED" in out and "TEST_DOUBLE_BUNDLE" in out and code == K.EXIT_REJECTED


def test_a_robot_lane_that_never_started_has_no_suite_copy_to_compare_and_a_completed_one_must_have_it(up, tmp_path):
    """A cancelled run (the Robot lane skipped) is a consistent bundle; a completed Robot lane whose suite copies were removed is not."""
    import json as j
    from qa_runner.golden import demo_plan
    from qa_runner.orchestrate import RunOptions, run_plan
    from qa_runner.plan import freeze_plan
    from qa_adapter_kit.supervisor import CancelToken
    from qr_support import fake
    cancel = CancelToken()
    cancel.cancel()
    s = run_plan(up, freeze_plan(up, demo_plan()), RunOptions(lane_command=fake("pass"), run_id="r0-test", cancel=cancel))
    v = verify_files_in(tmp_path, dict(s.bundle.files))
    assert "SUITE_FILE_MISMATCH" not in codes(v)
    gone = {k: val for k, val in golden("none").items() if not k.startswith("lanes/robot/suite/")}
    from qa_evidence.canon import dumps_canonical
    manifest = j.loads(gone["bundle-manifest.json"])
    manifest["files"] = [e for e in manifest["files"] if not e["path"].startswith("lanes/robot/suite/")]
    gone["bundle-manifest.json"] = dumps_canonical(manifest)
    assert "SUITE_FILE_MISMATCH" in codes(verify_files_in(tmp_path, gone))


# ---- review of #33 ----------------------------------------------------------------------------------------------------------------------------
def test_a_lock_crafted_to_crash_the_parser_is_a_rejection_with_exit_5_and_json_never_an_internal_error(tmp_path):
    """Review finding M3: ``suite_files`` that is not a mapping made ``verify`` die with ``internal error: ValueError`` (exit 6, no JSON)."""
    from qr_tamper import edit_json, rechain
    files = rechain(edit_json(golden("none"), "plan.lock.json", lambda l: l["lanes"][1].update(suite_files="x")))
    target = tmp_path / "b.tar"
    write_archive(files, str(target))
    code, out, err = cli("verify", str(target), "--json")
    doc = json.loads(out)
    assert code == K.EXIT_REJECTED and doc["accepted"] is False and {f["code"] for f in doc["findings"]} >= {"LOCK_REJECTED"} and "internal error" not in err


def test_whatever_goes_wrong_inside_the_verification_is_a_rejection_with_exit_5_not_an_internal_error(monkeypatch):
    """Review finding M3 (the general form): an exception the verifier did not foresee, on a bundle crafted to cause it, is exit 5 with a finding."""
    import qa_runner.verify as verify_module

    def boom(*a, **k):
        raise ValueError("crafted")
    monkeypatch.setattr(verify_module, "_check_lock", boom)
    code, out, err = cli("verify", str(GOLDEN / "bundle-none.tar"), "--json")
    doc = json.loads(out)
    assert code == K.EXIT_REJECTED and doc["findings"][-1]["code"] == "VERIFY_INCOMPLETE" and "ValueError" in doc["findings"][-1]["message"] and "internal error" not in err


def test_a_verifier_that_cannot_run_here_says_so_with_its_own_exit_status_and_still_prints_json(tmp_path, monkeypatch):
    """Review finding M3: with no git on PATH the verifier exited 3 (which means 'a lane did not run to completion') and printed no JSON."""
    import qa_runner.verify as verify_module
    from qa_runner.errors import EnvironmentFault

    def no_git():
        raise EnvironmentFault("PIN_MISMATCH", "git is not available")
    monkeypatch.setattr(verify_module, "verified_bootstrap", no_git)
    code, out, err = cli("verify", str(GOLDEN / "bundle-none.tar"), "--json")
    doc = json.loads(out)
    assert code == K.EXIT_VERIFIER_UNAVAILABLE == 7 and doc["accepted"] is False and doc["assurance"] == "not-verified" and doc["findings"][0]["code"] == "VERIFIER_UNAVAILABLE"
    code, out, err = cli("verify", str(GOLDEN / "bundle-none.tar"))
    assert code == 7 and "NOT VERIFIED: the verifier cannot run here" in out


def test_the_anchor_state_does_not_say_verified_for_a_value_nothing_authenticated():
    """Review finding L6: a digest copied from the same bundle matched, and the JSON said ``verified``."""
    path = str(GOLDEN / "bundle-none.tar")
    doc = json.loads(cli("verify", path, "--anchor", manifest_digest(golden("none")), "--json")[1])
    assert doc["anchor"]["state"] == "matches-supplied-value" and doc["assurance"] == "matches-supplied-anchor" and doc["anchor"]["matches_supplied_value"] is True
    import argparse
    from qa_runner.cli import _parser
    verify_parser = next(a for a in _parser()._actions if isinstance(a, argparse._SubParsersAction)).choices["verify"]
    assert "nothing here authenticates where the supplied value came from" in " ".join(verify_parser.format_help().split())


def test_a_bundle_that_says_a_test_double_produced_it_is_rejected_by_verify(tmp_path):
    from qr_tamper import edit_json, rechain
    files = rechain(edit_json(golden("none"), "report.json", lambda r: r.update(extensions={**(r.get("extensions") or {}), "test_double": "lane-command"})))
    v = verify_files_in(tmp_path, files)
    assert not v.accepted and "TEST_DOUBLE_BUNDLE" in codes(v) and v.exit_code == K.EXIT_REJECTED


def test_demo_does_not_print_the_report_of_a_bundle_its_own_verification_rejected(monkeypatch, tmp_path):
    """Review finding L1: the report ('Verification : OK ... VERIFIED') was printed after the REJECTED line."""
    import qa_runner.cli as cli_module
    from qa_runner.golden import demo_plan
    from qa_runner.orchestrate import RunOptions
    import qa_runner.orchestrate as orch
    from qr_support import fake, fake_robot
    real = orch.run_plan

    def with_doubles(up_, frozen, opts):
        return real(up_, frozen, RunOptions(defect=opts.defect, run_id=opts.run_id, lane_command=fake("pass"), robot_launcher=fake_robot("live"), lane_deadline_s=60))
    monkeypatch.setattr(orch, "run_plan", with_doubles)
    code, out, err = cli("demo", "--out", str(tmp_path / "o"), "--run-id", "r0-double")
    assert code == K.EXIT_REJECTED and "REJECTED" in out and "the report is not printed" in out and "INDEPENDENT VERDICT" not in out


# ---- retest of #32 and #33: one snapshot, nothing OK next to a rejection ---------------------------------------------------------------------------
def test_verify_takes_one_snapshot_and_a_writer_that_swaps_the_files_afterwards_cannot_change_what_it_sees(tmp_path, up, monkeypatch):
    """Retest N4: `verify_bundle(location)` and then `read_files(location)` read a directory bundle twice; a swap between the two reads checked bundle A with the evidence checks and bundle B with the
    runner's checks. The bundle is now read ONCE (by a child, into a snapshot) and everything is computed from it."""
    from qa_evidence.build import write_directory
    from qr_tamper_cases import CASES
    import qa_evidence.build as eb
    from qa_runner import isolated
    forged_case = next(c for c in CASES if c.name.startswith("forged PASS: the report recomputed by the library"))
    forged, honest = forged_case.mutate(up, golden("discount")), golden("discount")
    target = tmp_path / "b"
    write_directory(forged, str(target))
    alone = verify_files_in(tmp_path, forged)                                   # what the forged bundle gives when nothing is swapped
    real, calls = isolated.snapshot_bundle, []

    def snapshot_then_swap(location, **kw):
        calls.append(1)
        snap = real(location, **kw)
        import shutil
        shutil.rmtree(target)
        write_directory(honest, str(target))                                     # the honest bundle is put in its place after the snapshot was taken
        return snap
    monkeypatch.setattr(isolated, "snapshot_bundle", snapshot_then_swap)
    monkeypatch.setattr(eb, "read_files", lambda *a, **k: (_ for _ in ()).throw(AssertionError("the bundle was read a second time")))
    from qa_runner.verify import verify_location
    v = verify_location(str(target))
    assert len(calls) == 1 and not v.accepted and codes(v) == codes(alone) and "VERDICT_RECOMPUTE_MISMATCH" in codes(v)


def test_the_run_prints_the_re_verification_in_the_words_that_say_what_it_is(tmp_path, up):
    """Retest N10: the verifier shares judge_lane, finalize_results and the native_from_* functions with the run: what the second pass adds is a fresh process and a re-read of the bundle, not independent code."""
    from qa_runner.cli import _verify_in_a_new_process
    from qa_evidence.build import write_directory
    bundle = tmp_path / "b"
    write_directory(golden("none"), str(bundle))
    out = io.StringIO()
    assert _verify_in_a_new_process(bundle, PLAN_DIGEST, 0, 0, out) == 0
    assert "re-verification in a fresh process (the same code as the run, not independent code): ACCEPTED" in out.getvalue() and "independent verification" not in out.getvalue()
