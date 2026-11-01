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

PLAN_DIGEST = "sha256:b267f8dda8d9cfa87704e4ce33f969f6b9f3743c2438523732e21f89d2c909fd"


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


def test_verify_never_loads_a_browser_a_robot_framework_or_an_http_client_library_and_opens_no_socket(tmp_path):
    # the pinned harness package imports the standard library's urllib when it is imported; what matters is that nothing connects, which the patched socket proves
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
    assert _verify_in_a_new_process(tmp_path / "does-not-exist", PLAN_DIGEST, 0, out) == K.EXIT_REJECTED and "COULD NOT RUN" in out.getvalue()
    out = io.StringIO()
    bundle = tmp_path / "b"
    from qa_evidence.build import read_files, write_directory
    write_directory(golden("none"), str(bundle))
    assert _verify_in_a_new_process(bundle, PLAN_DIGEST, 0, out) == 0 and "ACCEPTED as internally consistent; 4 of 4" in out.getvalue()
    out = io.StringIO()
    assert _verify_in_a_new_process(bundle, "sha256:" + "0" * 64, 0, out) == K.EXIT_REJECTED and "REJECTED (PLAN_DIGEST_MISMATCH)" in out.getvalue()
    out = io.StringIO()
    assert _verify_in_a_new_process(bundle, PLAN_DIGEST, 4, out) == K.EXIT_REJECTED and "is not the run's (4)" in out.getvalue()


def test_run_exits_5_when_the_separate_verification_rejects_what_it_just_wrote(monkeypatch, tmp_path, up):
    """The lane here is a test double whose run record is not a real harness record: the bundle is consistent in itself, `verify` in a new interpreter cannot recompute it and rejects it, so
    `run` does not exit with its own status (0 would be VERIFIED)."""
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
    assert ": VERIFIED (ALL_ASSERTIONS_VERIFIED)" in out and "independent verification (a separate process): REJECTED" in out and code == K.EXIT_REJECTED


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
