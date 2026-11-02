# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``freeze``, ``report``, ``inspect`` and the demo plan: the commands that need no engine."""
import copy
import io
import json
from pathlib import Path

import pytest

from qa_evidence.canon import dumps_canonical
from qa_runner import constants as K
from qa_runner.cli import main
from qa_runner.golden import demo_plan, golden_plan
from qa_runner.inspect_cmd import chain_heads
from qa_runner.orchestrate import RunOptions, run_plan
from qa_runner.plan import freeze_plan, load_plan_or_lock
from qr_support import fake, fake_robot

DEMO_PLAN_DIGEST = "sha256:3e53d5b170e6541bd7fb37188a17c99c766af1d161d5aed452af68a56e68b943"
DEMO_EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "demo-plan.json"


def cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    return main(list(argv), out, err), out.getvalue(), err.getvalue()


def write_plan(tmp_path, plan, name="plan.json"):
    p = tmp_path / name
    p.write_text(json.dumps(plan))
    return str(p)


# ---- the demo plan -----------------------------------------------------------------------------------------------------------------------
def test_the_demo_plan_has_the_browser_lane_then_the_robot_lane_with_every_assertion_once(up):
    frozen = freeze_plan(up, demo_plan())
    assert [l.lane_id for l in frozen.lanes] == ["browser", "robot"] and frozen.plan_digest == DEMO_PLAN_DIGEST
    ids = [r["assertion_id"] for r in frozen.rows]
    assert sorted(ids) == ["A-NOTIF-ON", "A-ORDER-RULE", "A-SAVED", "A-URL"] and len(set(ids)) == 4


def test_the_demo_example_file_is_the_demo_plan():
    assert DEMO_EXAMPLE.read_bytes() == (json.dumps(demo_plan(), indent=2, sort_keys=True) + "\n").encode("utf-8")


def test_doctor_with_the_demo_plan_checks_both_engines(monkeypatch):
    import qa_runner.doctor as doctor
    monkeypatch.setattr(doctor, "check_playwright", lambda run=None: doctor.Check("playwright", "OK", "stub"))
    monkeypatch.setattr(doctor, "check_robot", lambda: doctor.Check("robot framework", "OK", "stub"))
    code, out, err = cli("doctor", "--plan", str(DEMO_EXAMPLE), "--json")
    assert code == 0 and {"playwright", "robot framework"} <= {r["check"] for r in json.loads(out)}


# ---- freeze ------------------------------------------------------------------------------------------------------------------------------
def test_freeze_writes_the_lock_and_prints_the_plan_digest(tmp_path, up):
    lock = tmp_path / "plan.lock.json"
    code, out, err = cli("freeze", str(DEMO_EXAMPLE), "--out", str(lock))
    frozen = freeze_plan(up, demo_plan())
    assert code == 0 and lock.read_bytes() == frozen.lock_bytes()
    assert f"plan digest: {DEMO_PLAN_DIGEST}" in out and f"sha256 {frozen.lock_digest}" in out and "2 lane(s), 4 assertion(s)" in out
    assert "where whoever runs the plan cannot rewrite it" in err


def test_freezing_twice_gives_the_same_bytes(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    assert cli("freeze", str(DEMO_EXAMPLE), "--out", str(a))[0] == 0 and cli("freeze", str(DEMO_EXAMPLE), "--out", str(b))[0] == 0
    assert a.read_bytes() == b.read_bytes()


def test_freeze_never_overwrites_a_lock(tmp_path):
    lock = tmp_path / "plan.lock.json"
    lock.write_text("keep me")
    code, out, err = cli("freeze", str(DEMO_EXAMPLE), "--out", str(lock))
    assert code == K.EXIT_USAGE and "OUTPUT_EXISTS" in err and lock.read_text() == "keep me"


def test_freeze_refuses_a_plan_with_an_unknown_field_and_writes_nothing(tmp_path):
    plan = demo_plan()
    plan["lanes"][0]["spec"]["assertions"][0]["verdict"] = "PASS"
    lock = tmp_path / "plan.lock.json"
    code, out, err = cli("freeze", write_plan(tmp_path, plan), "--out", str(lock))
    assert code == K.EXIT_USAGE and "SPEC_REJECTED" in err and not lock.exists()


def test_freeze_refuses_a_lock_and_a_missing_file(tmp_path, up):
    lock = tmp_path / "plan.lock.json"
    cli("freeze", str(DEMO_EXAMPLE), "--out", str(lock))
    code, out, err = cli("freeze", str(lock), "--out", str(tmp_path / "again.json"))
    assert code == K.EXIT_USAGE and "ALREADY_A_LOCK" in err
    assert cli("freeze", str(tmp_path / "nope.json"), "--out", str(tmp_path / "x.json"))[0] == K.EXIT_USAGE


def test_run_refuses_an_edited_lock_before_anything_starts(tmp_path):
    lock = tmp_path / "plan.lock.json"
    cli("freeze", str(DEMO_EXAMPLE), "--out", str(lock))
    doc = json.loads(lock.read_text())
    doc["lanes"][0]["assertions"][0]["predicate"]["expected"] = "forged"                     # an expected value edited after freezing
    lock.write_bytes(dumps_canonical(doc))
    code, out, err = cli("run", str(lock), "--out", str(tmp_path / "o"))
    assert code == K.EXIT_USAGE and ("LOCK_MISMATCH" in err or "SPEC_REJECTED" in err) and not (tmp_path / "o").exists()


def test_run_accepts_the_lock_freeze_wrote(tmp_path, up):
    lock = tmp_path / "plan.lock.json"
    cli("freeze", str(DEMO_EXAMPLE), "--out", str(lock))
    frozen, kind = load_plan_or_lock(up, lock.read_bytes())
    assert kind == "lock" and frozen.plan_digest == DEMO_PLAN_DIGEST


# ---- two lanes in one run -----------------------------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def demo_frozen(up):
    return freeze_plan(up, demo_plan())


def two(up, frozen, browser="pass", robot="live", defect="none", **kw):
    return run_plan(up, frozen, RunOptions(defect=defect, lane_command=fake(browser), robot_launcher=fake_robot(robot), lane_deadline_s=60, run_id="r0-test", **kw))


def rep(s):
    return json.loads(s.bundle.files["report.json"])


def test_both_lanes_are_native_passes_and_carry_no_verdict_because_both_engines_are_doubles(up, demo_frozen):
    """Doubles never carry a verdict (VERIFIED for the two real engines is in ``tests/e2e``)."""
    s = two(up, demo_frozen)
    assert (s.outcome, s.exit_code, s.lanes) == ("INCONCLUSIVE", K.EXIT_INCONCLUSIVE, (("browser", "NATIVE_PASS"), ("robot", "NATIVE_PASS")))
    r = rep(s)
    assert r["accounting"]["frozen"] == r["accounting"]["inconclusive"] == 4 and r["accounting"]["unaccounted"] == 0
    assert {x["verdict"]["reason_code"] for x in r["accounting"]["results"]} == {"TEST_DOUBLE"}


def test_the_lanes_share_one_run_id_and_their_run_ids_are_run_dot_lane(up, demo_frozen):
    r = rep(two(up, demo_frozen))
    assert r["run_id"] == "r0-test" and [(l["lane_id"], l["run_id"]) for l in r["lanes"]] == [("browser", "r0-test.browser"), ("robot", "r0-test.robot")]


def test_the_lanes_run_serially_in_plan_order_against_one_target(up, demo_frozen):
    s = two(up, demo_frozen)
    log = s.bundle.files["logs/orchestrator.log"].decode().splitlines()
    assert [i for i, l in enumerate(log) if l.startswith("lane ")] == sorted(i for i, l in enumerate(log) if l.startswith("lane "))
    assert log.index("target started on loopback") < next(i for i, l in enumerate(log) if l.startswith("lane browser")) < next(i for i, l in enumerate(log) if l.startswith("lane robot"))
    assert sum(1 for l in log if l == "target started on loopback") == 1
    requests = [json.loads(l)["target"] for l in s.bundle.files["logs/target-requests.jsonl"].decode().splitlines()]
    assert "/api/orders/101" in requests                          # the Robot lane's requests reached the same target


def test_the_discount_defect_is_a_native_fail_of_the_robot_lane_only_and_the_browser_lane_is_still_recorded(up, demo_frozen):
    s = two(up, demo_frozen, defect="discount")
    assert s.lanes == (("browser", "NATIVE_PASS"), ("robot", "NATIVE_FAIL")) and s.outcome == "INCONCLUSIVE"


def test_a_failing_browser_lane_is_a_native_fail_of_that_lane_only_and_the_robot_lane_is_still_recorded(up, demo_frozen):
    s = two(up, demo_frozen, browser="settings-bug")
    assert s.lanes == (("browser", "NATIVE_FAIL"), ("robot", "NATIVE_PASS")) and s.outcome == "INCONCLUSIVE"


def test_partial_success_a_lane_that_times_out_leaves_the_other_lanes_result_and_the_run_inconclusive(up):
    plan = demo_plan()
    plan["lanes"][0]["deadline_s"] = 1                        # the browser lane gets one second, and its double hangs
    s = run_plan(up, freeze_plan(up, plan), RunOptions(lane_command=fake("hang"), robot_launcher=fake_robot("live"), run_id="r0-test"))
    r = rep(s)
    states = {x["assertion_id"]: x["verdict"]["state"] for x in r["accounting"]["results"]}
    assert s.lanes == (("browser", "NATIVE_TIMEOUT"), ("robot", "NATIVE_PASS")) and (s.outcome, s.exit_code) == ("INCONCLUSIVE", K.EXIT_ENVIRONMENT)
    assert set(states.values()) == {"INCONCLUSIVE"}              # the Robot lane is a double too: no verdict; the real partial success is in tests/e2e
    assert r["accounting"]["frozen"] == 4 and r["verdict"]["reason_code"] != "ALL_ASSERTIONS_VERIFIED"


def test_a_timeout_never_gives_verified_whatever_the_other_lane_says(up):
    plan = demo_plan()
    plan["lanes"][1]["deadline_s"] = 2
    s = run_plan(up, freeze_plan(up, plan), RunOptions(lane_command=fake("pass"), robot_launcher=fake_robot("hang"), run_id="r0-test"))
    assert s.outcome == "INCONCLUSIVE" and s.lanes == (("browser", "NATIVE_PASS"), ("robot", "NATIVE_TIMEOUT"))


def test_cancelling_during_the_first_lane_skips_the_second_and_still_accounts_for_all_four(up, demo_frozen):
    import threading
    from qa_adapter_kit.supervisor import CancelToken
    cancel = CancelToken()
    threading.Timer(1.0, cancel.cancel).start()
    s = run_plan(up, demo_frozen, RunOptions(lane_command=fake("hang"), robot_launcher=fake_robot("live"), run_id="r0-test", cancel=cancel))
    r = rep(s)
    assert s.cancelled and s.exit_code == K.EXIT_ENVIRONMENT and s.outcome == "INCONCLUSIVE"
    assert dict(s.lanes) == {"browser": "NATIVE_ERROR", "robot": "NATIVE_SKIPPED"} and r["accounting"]["frozen"] == 4 and r["accounting"]["inconclusive"] == 4


# ---- report and inspect ------------------------------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def bundle_dir(tmp_path_factory):
    """The bundle `demo` wrote for the discount defect with the real engines (golden/regen_bundles.py): report and inspect are exercised over a real one."""
    from qa_evidence.build import write_directory
    from qr_tamper import golden
    target = tmp_path_factory.mktemp("bundle") / "b"
    write_directory(golden("discount"), str(target))
    return target


def test_report_text_is_the_evidence_report_and_exits_zero_for_a_bundle_that_verifies(bundle_dir):
    code, out, err = cli("report", str(bundle_dir))
    assert code == 0 and "INDEPENDENT VERDICT" in out and "A-ORDER-RULE [robot] native=NATIVE_FAIL verdict=FAILED" in out and "does not mean the" in out and err == ""


def test_report_json_carries_the_verification_and_the_summary(bundle_dir):
    code, out, err = cli("report", str(bundle_dir), "--format", "json")
    doc = json.loads(out)
    assert code == 0 and doc["verification"]["ok"] is True and doc["summary"]["independent_verdict"]["outcome"] == "FAILED"


def test_report_html_is_one_file_with_no_script_and_a_content_security_policy(bundle_dir, tmp_path):
    out_file = tmp_path / "r.html"
    code, out, err = cli("report", str(bundle_dir), "--format", "html", "-o", str(out_file))
    html = out_file.read_text()
    assert code == 0 and "Content-Security-Policy" in html and "<script" not in html.lower() and out == ""
    assert cli("report", str(bundle_dir), "--format", "html", "-o", str(out_file))[0] == K.EXIT_USAGE            # never overwritten


def test_report_with_a_plan_digest_says_whether_it_matches(bundle_dir):
    good = cli("report", str(bundle_dir), "--plan-digest", DEMO_PLAN_DIGEST)
    bad = cli("report", str(bundle_dir), "--plan-digest", "sha256:" + "0" * 64)
    assert good[0] == 0 and "matches the supplied value" in good[1]
    assert bad[0] == K.EXIT_REJECTED and "PLAN_DIGEST_MISMATCH" in bad[1] and "did not verify" in bad[2]


def test_report_of_a_tampered_bundle_exits_one_and_warns(bundle_dir, tmp_path):
    import shutil
    copy = tmp_path / "t"
    shutil.copytree(bundle_dir, copy)
    (copy / "lanes" / "robot" / "observations.json").write_bytes(b"{}\n")
    code, out, err = cli("report", str(copy))
    assert code == K.EXIT_REJECTED and out.startswith("Recomputation : REJECTED") and "Verification : OK" not in out and "did not verify" in err


def test_report_and_inspect_of_something_that_is_not_a_bundle_are_usage_errors(tmp_path):
    assert cli("report", str(tmp_path / "nope"))[0] == K.EXIT_USAGE and cli("inspect", str(tmp_path / "nope"))[0] == K.EXIT_USAGE


def test_inspect_lists_the_files_the_tools_the_lanes_and_the_verdict_and_never_recomputes(bundle_dir):
    code, out, err = cli("inspect", str(bundle_dir))
    assert code == 0 and "verification: OK, internally consistent" in out
    assert "tools: " in out and "redevops-qa-verify" in out and "lane browser:" in out and "lane robot:" in out and "verdict: FAILED (ASSERTION_FAILED)" in out
    assert "native-artifact" in out and "lanes/robot/native/output.xml" in out and "plan.lock.json" in out and "files:" in out


def test_inspect_exits_one_for_a_bundle_that_does_not_verify(bundle_dir, tmp_path):
    import shutil
    copy = tmp_path / "t"
    shutil.copytree(bundle_dir, copy)
    (copy / "plan.lock.json").write_bytes(b"{}\n")
    code, out, err = cli("inspect", str(copy))
    assert code == K.EXIT_REJECTED and "recomputation: REJECTED" in out and "verification: OK" not in out and "verdict:" not in out


def test_chain_heads_are_read_from_the_run_record_as_stored():
    record = {"events": [{"kind": "RunStarted", "event_hash": "canon-v1:" + "a" * 64}, {"kind": "RunSealed", "event_hash": "canon-v1:" + "b" * 64,
                                                                                     "payload": {"classification": {"outcome": "PASS"}}}],
              "receipt_links": [{"link_hash": "canon-v1:" + "c" * 64}]}
    heads = chain_heads({"lanes/browser/native/run-record.json": dumps_canonical(record), "lanes/robot/native/output.xml": b"<robot/>"})
    assert heads == [{"lane": "browser", "events": 2, "event_head": "canon-v1:" + "b" * 64, "receipts": 1, "receipt_head": "canon-v1:" + "c" * 64, "sealed": True, "sealed_outcome": "PASS"}]
    assert chain_heads({"lanes/browser/native/run-record.json": b"{not json"})[0]["events"] is None
    assert chain_heads({"lanes/browser/native/run-record.json": dumps_canonical({"events": [], "receipt_links": []})})[0]["sealed"] is False


def test_hostile_text_in_a_bundle_is_escaped_in_inspect(bundle_dir, tmp_path):
    import shutil
    copy = tmp_path / "t"
    shutil.copytree(bundle_dir, copy)
    (copy / "x\x1b[2Jy.txt").write_bytes(b"x")
    code, out, err = cli("inspect", str(copy))
    assert "\x1b" not in out and "\x1b" not in err


# ---- review of #32: what report and inspect do not show, the run summary, the plan read, the origin rule --------------------------------------------
def forged_bundle(up, tmp_path):
    """The bundle of the discount run with the failing verdict reported as VERIFIED by this package's own report builder, so every digest, count and the manifest agree (a forgery that the
    bundle's own checks cannot see)."""
    from qa_evidence.build import write_directory
    from qr_tamper import golden
    from qr_tamper_cases import CASES
    case = next(c for c in CASES if c.name.startswith("forged PASS: the report recomputed by the library"))
    target = tmp_path / "forged"
    write_directory(case.mutate(up, golden(case.base)), str(target))
    return target


def test_report_and_inspect_recompute_the_verdicts_and_do_not_print_ok_for_evidence_verify_rejects(up, bundle_dir, tmp_path):
    """Review finding H1: for a forged bundle `verify` exited 5 while `report` printed 'Verification : OK - internally consistent ... VERIFIED' and exited 0."""
    forged = forged_bundle(up, tmp_path)
    code, out, err = cli("report", str(forged))
    assert code == K.EXIT_REJECTED and "REJECTED: the bundle does not verify" in out.splitlines()[0] and "VERDICT_RECOMPUTE_MISMATCH" in out.splitlines()[0] and "did not verify" in err
    assert "Verification : OK" not in out and "INDEPENDENT VERDICT" not in out and "ALL_ASSERTIONS" not in out          # retest N5: nothing of the forged body is shown next to the rejection
    code, out, err = cli("inspect", str(forged))
    assert code == K.EXIT_REJECTED and "recomputation: REJECTED" in out.splitlines()[1] and "verification: OK" not in out
    doc = json.loads(cli("report", str(forged), "--format", "json")[1])
    assert doc["recomputation"]["accepted"] is False and "VERDICT_RECOMPUTE_MISMATCH" in {f["code"] for f in doc["recomputation"]["findings"]}
    assert doc["content_trusted"] is False and doc["verification"] == {"ok": False} and "summary" not in doc          # the old keys do not say OK next to a rejection
    html_file = tmp_path / "r.html"
    assert cli("report", str(forged), "--format", "html", "-o", str(html_file))[0] == K.EXIT_REJECTED
    assert 'banner bad">REJECTED' in html_file.read_text()


def test_report_and_inspect_say_what_was_recomputed_for_a_bundle_that_verifies(bundle_dir):
    code, out, err = cli("report", str(bundle_dir))
    assert code == 0 and out.splitlines()[0] == "Recomputation : verdicts recomputed from the bundle alone: 4 of 4 agree with the report (ACCEPTED as internally consistent)"
    doc = json.loads(cli("report", str(bundle_dir), "--format", "json")[1])
    assert doc["verdicts_recomputed"] is True and doc["recomputation"]["accepted"] is True and doc["recomputation"]["recomputed_assertions"] == 4
    assert cli("inspect", str(bundle_dir))[1].splitlines()[2].startswith("recomputation: verdicts recomputed from the bundle alone: 4 of 4 agree")


def test_the_run_summary_says_that_integrity_against_re_forging_is_not_established(up, demo_frozen):
    """Review finding H3: the summary of `run` ended with an exit 0 VERIFIED and did not carry the sentence."""
    from qa_runner.cli import _print_summary
    s = two(up, demo_frozen)
    buf = io.StringIO()
    _print_summary(s, Path("/x"), buf)
    lines = buf.getvalue().splitlines()
    assert "integrity against deliberate re-forging NOT established" in lines[1] and lines[0].startswith("run r0-test:")


def test_a_plan_that_is_not_a_regular_file_is_refused_without_being_read(tmp_path):
    """Review finding M5: ``stat().st_size`` is 0 for /dev/zero and a FIFO; the read had no cap (134 GB resident in 8 seconds)."""
    import os
    fifo = tmp_path / "plan.fifo"
    os.mkfifo(fifo)
    for path in ("/dev/zero", str(fifo)):
        code, out, err = cli("freeze", path, "--out", str(tmp_path / "l.json"))
        assert code == K.EXIT_USAGE and "not a regular file" in err, path


def test_a_plan_over_the_cap_is_refused_by_what_is_read(tmp_path):
    (tmp_path / "big.json").write_bytes(b" " * (1024 * 1024 + 1))
    code, out, err = cli("freeze", str(tmp_path / "big.json"), "--out", str(tmp_path / "l.json"))
    assert code == K.EXIT_USAGE and "at most" in err


def test_freeze_refuses_a_plan_the_run_would_refuse_for_its_origin_placeholder(up):
    """Review finding L3: `{origin}` twice in a step value was accepted by freeze and refused by the run, after the target had started."""
    from qa_runner.errors import PlanError
    plan = golden_plan()
    plan["lanes"][0]["spec"]["steps"][0]["action"]["value"] = "{origin}/login?next={origin}"
    with pytest.raises(PlanError) as exc:
        freeze_plan(up, plan)
    assert exc.value.code == "BAD_ORIGIN_PLACEHOLDER"


# ---- retest round 2, R2-3: at this part nothing recomputes a verdict, and nothing reads as if something had --------------------------------------------
def test_run_and_demo_say_right_under_the_outcome_that_no_command_recomputes_the_verdicts(up, demo_frozen):
    from qa_runner.cli import RUNNER_ONLY, _print_summary
    buf = io.StringIO()
    _print_summary(two(up, demo_frozen), Path("/x"), buf)
    lines = buf.getvalue().splitlines()
    assert lines[0].startswith("run r0-test:") and RUNNER_ONLY in lines[2] and "not an independent verification" in RUNNER_ONLY
