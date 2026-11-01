# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Mutation tests: removing a guard of the runner makes the suite fail. Each case names the guard, the source it lives in and the tests that must catch its removal."""
import re

import pytest

from qr_mutation import baseline_result, mutant_result

PLAN = "test_qr_plan.py"
JUDGE = "test_qr_judge.py"
BUNDLE = "test_qr_bundle.py"
ORCH = "test_qr_orchestrate.py"
CLI = "test_qr_cli.py"
PARTS = "test_qr_lane_parts.py"
FREEZE = "test_qr_freeze_cli.py"
CHILD = "test_qr_lane_child.py"
SCRIPT = "test_qr_judge_script.py"
ROBOT = "test_qr_robot_lane.py"


def t(file, name):
    return f"{file}::{name}"


CASES = [
    # ---- plan.py ---------------------------------------------------------------------------------------------------------------------
    ("unknown plan and lane fields are refused", "plan.py", "    if unknown:\n", "    if False:\n", [t(PLAN, "test_an_unknown_field_is_refused_at_every_level")]),
    ("only the declared engines are accepted", "plan.py", 'if not isinstance(lane, dict) or lane.get("engine") not in K.ENGINES:', "if not isinstance(lane, dict):",
     [t(PLAN, "test_structural_refusals")]),
    ("an assertion id may live in one lane only", "plan.py", 'if a["assertion_id"] in seen_ids:', "if False:",
     [t(PLAN, "test_an_assertion_id_in_two_lanes_is_refused_so_every_assertion_is_accounted_once")]),
    ("a lock must equal the freeze of its own plan", "plan.py", "if dumps_canonical(again.lock_document()) != dumps_canonical(lock_doc):", "if False:", [t(PLAN, "test_an_edited_lock_is_refused")]),
    ("the contracts parser refuses what the harness mirror tolerates", "plan.py", "        return c.TestSpec.from_json(copy.deepcopy(dict(doc)))", "        return None",
     [t(PLAN, "test_an_unknown_field_is_refused_at_every_level")]),
    ("the origin placeholder is replaced only at the start of a value", "plan.py", "if not value.startswith(K.ORIGIN_PLACEHOLDER) or value.count(K.ORIGIN_PLACEHOLDER) != 1:", "if False:",
     [t(PLAN, "test_the_origin_replaces_the_placeholder_at_the_start_of_a_value_only")]),
    # ---- judge.py --------------------------------------------------------------------------------------------------------------------
    ("an observation row carries no field but the known ones", "judge.py", "if not isinstance(row, dict) or set(row) != ROW_KEYS:", "if not isinstance(row, dict):",
     [t(JUDGE, "test_a_verdict_or_expected_value_in_an_observation_row_makes_the_file_unusable")]),
    ("an observation file carries no extra top-level field", "judge.py", "if not isinstance(doc, dict) or set(doc) != OBS_KEYS:", "if not isinstance(doc, dict):",
     [t(JUDGE, "test_an_extra_top_level_field_makes_the_file_unusable")]),
    ("an observation file belongs to its own run and lane", "judge.py", 'if doc["lane_id"] != lane_id or doc["run_id"] != run_id:', "if False:",
     [t(JUDGE, "test_an_observation_file_recorded_for_another_run_lane_or_format_is_unusable"), t(JUDGE, "test_a_replay_from_another_run_is_unusable")]),
    ("duplicate observation rows are refused", "judge.py", 'if not isinstance(row["assertion_id"], str) or row["assertion_id"] in out:', 'if not isinstance(row["assertion_id"], str):',
     [t(JUDGE, "test_duplicate_rows_and_duplicate_keys_make_the_file_unusable")]),
    ("the frozen assertions must hash to the pin they were frozen with", "judge.py", "        pin = lane.harness_pin\n",
     "        pin = h.verifier.assertion_set_pin(tuple(h.records.AssertionSpec.from_json(copy.deepcopy(d)) for d in docs))\n",
     [t(JUDGE, "test_a_pin_that_is_not_the_frozen_one_is_an_integrity_failure")]),
    ("a missing observation file is missing evidence", "judge.py", "    if data is None:\n        return _all(lane, \"INCONCLUSIVE\", \"EVIDENCE_MISSING\")",
     "    if data is None:\n        data = b''", [t(JUDGE, "test_no_observation_file_means_missing_evidence_never_a_pass")]),
    ("the verdict comes from the harness comparison", "judge.py", "            result = verifier.verify_assertion(frozen, aid, session=None)\n",
     "            class _R:\n                reason_code = None\n                class check:\n                    verdict = type('V', (), {'value': 'PASS'})()\n            result = _R()\n",
     [t(JUDGE, "test_a_value_that_differs_from_the_frozen_one_fails_that_assertion_only")]),
    # ---- bundle.py -------------------------------------------------------------------------------------------------------------------
    ("the in-run verifier and the recomputation must agree", "bundle.py", 'if seen is not None and r["state"] in ("VERIFIED", "FAILED") and seen != _HARNESS_FOR_STATE[r["state"]]:',
     "if False:", [t(BUNDLE, "test_when_the_in_run_verifier_and_the_recomputation_disagree_nothing_is_certified"), t(ORCH, "test_the_inrun_verifier_disagreeing_with_the_recomputation_certifies_nothing")]),
    ("every lane of the plan has exactly one outcome", "bundle.py", 'if sorted(by_lane) != sorted(l.lane_id for l in frozen.lanes) or len(by_lane) != len(inputs.lanes):', "if False:",
     [t(BUNDLE, "test_every_lane_of_the_plan_needs_exactly_one_outcome")]),
    ("the native status of a result is the lane's", "bundle.py", '"native_status": lane.native_status,', '"native_status": "NATIVE_PASS",',
     [t(BUNDLE, "test_each_result_carries_the_native_status_of_its_own_lane")]),
    # ---- orchestrate.py --------------------------------------------------------------------------------------------------------------
    ("an executor environment failure is an engine error", "orchestrate.py", '    return "NATIVE_ERROR", outcome\n', '    return "NATIVE_PASS", outcome\n',
     [t(ORCH, "test_an_executor_environment_failure_is_an_engine_error_even_when_the_observations_look_right")]),
    ("a product failure is a native failure", "orchestrate.py", '        return "NATIVE_FAIL", "PRODUCT_FAIL"\n', '        return "NATIVE_PASS", "PRODUCT_FAIL"\n',
     [t(ORCH, "test_a_failed_assertion_fails_the_run_and_exits_one")]),
    ("a lane past its deadline is a timeout", "orchestrate.py", "    if proc.error_code == ErrorCode.TIMEOUT:", "    if False:", [t(ORCH, "test_a_lane_that_outlives_its_deadline_is_a_timeout_never_verified")]),
    ("a cancelled lane is an engine error", "orchestrate.py", "    elif proc.error_code == ErrorCode.CANCELLED:", "    elif False:",
     [t(ORCH, "test_cancelling_during_a_lane_ends_the_lane_and_the_run_is_not_verified")]),
    ("a lane that reports an error is an engine error", "orchestrate.py", '    elif result is not None and result.get("status") == "ERROR":\n        raw_status = "lane-error"', '    elif False:\n        raw_status = "lane-error"',
     [t(ORCH, "test_a_gateway_that_cannot_start_fails_the_lane_closed_and_no_browser_is_started")]),
    ("the target is stopped in every case", "orchestrate.py", "    finally:\n        app.stop()\n", "    finally:\n        pass\n", [t(ORCH, "test_the_target_is_stopped_when_the_run_ends")]),
    ("a run cancelled before a lane skips it", "orchestrate.py", "    if opts.cancel is not None and opts.cancel.cancelled:\n        log.append(f\"lane {fl.lane_id}: not started: the run was cancelled\")",
     "    if False:\n        log.append(f\"lane {fl.lane_id}: not started: the run was cancelled\")", [t(ORCH, "test_a_run_cancelled_before_the_lane_starts_skips_it_and_still_accounts_for_every_assertion")]),
    ("a target that did not start leaves the lane unavailable", "orchestrate.py", "    if origin is None:\n        log.append", "    if False:\n        log.append",
     [t(ORCH, "test_a_target_that_does_not_start_leaves_the_lane_unavailable_and_everything_inconclusive")]),
    ("observation rows are recorded as returned, never repaired", "orchestrate.py", "if rows and all(isinstance(r, dict) and isinstance(r.get(\"assertion_id\"), str) for r in rows):",
     "if rows and False:", [t(ORCH, "test_a_forged_verdict_field_in_the_observations_leaves_the_assertions_inconclusive")]),
    ("a bad run id is refused", "orchestrate.py", "    if not K.RUN_ID_RE.fullmatch(run_id):", "    if False:", [t(ORCH, "test_a_bad_run_id_is_refused_before_anything_starts")]),
    ("an unknown defect is refused", "orchestrate.py", "    if opts.defect not in K.DEFECTS:", "    if False:", [t(ORCH, "test_an_unknown_defect_is_refused")]),
    ("the exit code of a failed run", "orchestrate.py", '    if outcome == "FAILED":\n        return K.EXIT_FAILED', '    if outcome == "FAILED":\n        return K.EXIT_INCONCLUSIVE', [t(ORCH, "test_the_exit_code_table")]),
    ("a lane that did not complete is an environment exit", "orchestrate.py", 'if cancelled or any(l["native"]["status"] not in ("NATIVE_PASS", "NATIVE_FAIL") for l in report["lanes"]):',
     "if False:", [t(ORCH, "test_the_exit_code_table")]),
    # ---- the Robot lane: plan.py -----------------------------------------------------------------------------------------------------
    ("a Robot lane holds SCRIPT assertions only", "plan.py", '        if a["executor"] != "SCRIPT":', "        if False:", [t(PLAN, "test_robot_lane_refusals")]),
    ("the check program must be the registered one", "plan.py", '        if given.get("program_hash") != ref["program_hash"]:', "        if False:", [t(PLAN, "test_robot_lane_refusals")]),
    ("the check program must be registered by id and version", "plan.py", '        if given.get("id") != ref["id"] or given.get("version") != ref["version"]:', "        if False:",
     [t(PLAN, "test_robot_lane_refusals")]),
    ("a Robot assertion reads exactly the lane's record", "plan.py", "        if [{k: v for k, v in i.items() if v is not None} for i in inputs] != want:", "        if False:",
     [t(PLAN, "test_robot_lane_refusals")]),
    ("a Robot lane has no steps", "plan.py", "    if spec.steps:", "    if False:", [t(PLAN, "test_robot_lane_refusals")]),
    ("an engine only takes its own egress profile", "plan.py", '        if lane["egress"] not in EGRESS_PROFILES[lane["engine"]]:', "        if False:",
     [t(PLAN, "test_robot_lane_refusals"), t(PLAN, "test_a_browser_lane_may_not_use_the_not_enforced_profile_or_a_script_assertion")]),
    ("the suite files are hashed into the lock", "plan.py", '"suite": l.suite, "suite_files": dict(sorted(l.suite_files.items())), ', "",
     [t(PLAN, "test_the_robot_plan_freezes_with_the_suite_files_and_the_program_hash_pinned")]),
    # ---- the Robot lane: judge.py ------------------------------------------------------------------------------------------------------
    ("the record must be what the importer derives from the engine's report", "judge.py", "        if dumps_canonical(derived_record(native, lane.lane_id, full_run)) != data:", "        if False:",
     [t(SCRIPT, "test_a_record_that_differs_in_any_way_from_the_derived_one_is_unusable"), t(SCRIPT, "test_a_record_that_does_not_belong_to_the_native_report_next_to_it_is_unusable")]),
    ("a record needs its native report", "judge.py", "    if data is None or native is None:", "    if data is None:", [t(SCRIPT, "test_a_missing_record_or_a_missing_native_report_is_missing_evidence")]),
    ("only the record is staged for the check", "judge.py", "            target.write_bytes(data)\n", "            target.write_bytes(data)\n            (root / 'native.xml').write_bytes(native)\n",
     [t(SCRIPT, "test_the_check_program_receives_the_record_alone_and_never_an_expected_value")]),
    ("a replay from another run is refused", "judge.py", "    full_run = f\"{run_id}.{lane.lane_id}\"", "    full_run = 'r0-other.' + lane.lane_id", [t(SCRIPT, "test_a_replay_of_another_runs_record_is_unusable")]),
    # ---- the Robot lane: lane_robot.py ------------------------------------------------------------------------------------------------
    ("suite files must be the frozen ones", "lane_robot.py", "    if {rel: _sha(d) for rel, d in copies.items()} != fl.suite_files:", "    if False:", [t(ROBOT, "test_suite_files_that_changed_after_freezing_are_refused_before_anything_runs")]),
    ("an engine failure is a native failure", "lane_robot.py", '        status, raw = "NATIVE_FAIL", "FAIL"', '        status, raw = "NATIVE_PASS", "FAIL"', [t(ROBOT, "test_the_discount_defect_is_a_native_fail_and_a_failed_assertion")]),
    ("an engine timeout is a timeout", "lane_robot.py", "        if result.error_code is ErrorCode.TIMEOUT:", "        if False:", [t(ROBOT, "test_an_engine_that_hangs_is_a_timeout_and_never_verified")]),
    ("a target that did not start leaves the lane unavailable", "lane_robot.py", "    if origin is None:\n", "    if False:\n", [t(ROBOT, "test_a_target_that_does_not_start_leaves_the_robot_lane_unavailable")]),
    ("a cancelled run skips the lane", "lane_robot.py", "    if cancel is not None and cancel.cancelled:", "    if False:", [t(ROBOT, "test_a_run_cancelled_before_the_lane_starts_skips_it")]),
    ("the egress profile of a Robot lane says not enforced", "lane_robot.py", '"profile": "not-enforced"', '"profile": "gateway"', [t(ROBOT, "test_the_egress_profile_of_a_robot_lane_says_it_is_not_enforced")]),
    # ---- freeze, report, inspect and the child plumbing ---------------------------------------------------------------------------------
    ("freeze never overwrites a lock", "cli.py", '        with open(target, "xb") as fh:', '        with open(target, "wb") as fh:', [t(FREEZE, "test_freeze_never_overwrites_a_lock")]),
    ("freeze takes a plan, not a lock", "cli.py", '    if kind != "plan":', "    if False:", [t(FREEZE, "test_freeze_refuses_a_lock_and_a_missing_file")]),
    ("report exits non-zero for a bundle that does not verify", "cli.py", "    return 0 if ok else 1\n", "    return 0\n", [t(FREEZE, "test_report_of_a_tampered_bundle_exits_one_and_warns")]),
    ("inspect exits non-zero for a bundle that does not verify", "cli.py", '    return 0 if text.splitlines()[1].startswith("verification: OK") else 1', "    return 0",
     [t(FREEZE, "test_inspect_exits_one_for_a_bundle_that_does_not_verify")]),
    ("report writes nothing over an existing file", "cli.py", '            with open(args.output, "x", encoding="utf-8", newline="\\n") as fh:', '            with open(args.output, "w", encoding="utf-8", newline="\\n") as fh:',
     [t(FREEZE, "test_report_html_is_one_file_with_no_script_and_a_content_security_policy")]),
    ("chain heads read the seal of the run record", "inspect_cmd.py", '            sealed = events[-1] if events and events[-1].get("kind") == "RunSealed" else None', "            sealed = None",
     [t(FREEZE, "test_chain_heads_are_read_from_the_run_record_as_stored")]),
    ("the watchdog notices a parent that is gone", "watchdog.py", "            if os.getppid() != parent_pid:", "            if False:", [t(CHILD, "test_the_watchdog_calls_back_when_the_parent_is_not_the_one_it_was_told_about")]),
    ("a file named outside the lane's output directory is refused", "lane_robot.py", "            if out.resolve() not in p.parents or not p.is_file() or p.stat().st_size > limit:",
     "            if not p.is_file() or p.stat().st_size > limit:", [t(CHILD, "test_a_file_the_child_names_outside_its_output_directory_is_refused")]),
    ("an outcome file must be the lane's own", "lane_robot.py", '        if not isinstance(doc, dict) or doc.get("schema") != K.LANE_RESULT_SCHEMA or doc.get("status") != "COMPLETED":',
     "        if not isinstance(doc, dict):", [t(CHILD, "test_no_outcome_file_or_one_that_is_not_ours_is_no_outcome")]),
    # ---- lane_browser.py -------------------------------------------------------------------------------------------------------------
    ("declared preconditions cannot be attested", "lane_browser.py", "        return True if not spec.preconditions else None", "        return True",
     [t(PARTS, "test_preconditions_and_fixtures_nothing_here_can_attest_are_unknown_never_true")]),
    ("declared fixtures cannot be attested", "lane_browser.py", "        return True if not spec.fixtures else None", "        return True",
     [t(PARTS, "test_preconditions_and_fixtures_nothing_here_can_attest_are_unknown_never_true")]),
    ("an unhealthy target is reported unhealthy", "lane_browser.py", '        except Exception:\n            return False', '        except Exception:\n            return True',
     [t(PARTS, "test_a_target_that_does_not_answer_is_unhealthy")]),
    ("the guard decisions are kept before the session closes", "lane_browser.py", "            self.guard_decisions.extend(self._inner.egress_decisions(handle))\n", "            pass\n",
     [t(PARTS, "test_the_recording_adapter_drains_the_guard_decisions_before_the_session_closes")]),
    # ---- egress.py -------------------------------------------------------------------------------------------------------------------
    ("only the http loopback origin is allowed", "egress.py", 'if parts.scheme != "http" or parts.hostname not in ("127.0.0.1",) or parts.port is None:', "if False:",
     [t(PARTS, "test_the_origin_only_profile_refuses_anything_else")]),
    # ---- cli.py and doctor.py --------------------------------------------------------------------------------------------------------
    ("an existing bundle is never overwritten", "cli.py", "    if args.run_id is not None and (target / args.run_id).exists():", "    if False:",
     [t(CLI, "test_an_existing_bundle_directory_is_never_overwritten")]),
    ("a crash is not a product failure", "cli.py", "    except Exception as exc:\n        # the class of the failure", "    except ZeroDivisionError as exc:\n        # the class of the failure", [t(CLI, "test_a_crash_of_the_runner_has_its_own_exit_status_and_leaks_nothing")]),
    ("doctor fails on a playwright of another version", "doctor.py", "    if have != PLAYWRIGHT_PIN:", "    if False:", [t(CLI, "test_another_playwright_version_fails")]),
    ("doctor fails when playwright is missing", "doctor.py", "    if have is None:\n        return Check(\"playwright\"", "    if False:\n        return Check(\"playwright\"",
     [t(CLI, "test_a_missing_playwright_fails_with_the_remedy_and_installs_nothing")]),
    ("doctor fails on a chromium that does not launch", "doctor.py", '    if done.returncode != 0 or not done.stdout.startswith("chromium "):', "    if False:",
     [t(CLI, "test_a_playwright_without_a_launchable_chromium_fails_with_the_install_command")]),
    ("doctor warns outside linux x86_64", "doctor.py", "    if (system, machine) == SUPPORTED_PLATFORM:", "    if True:", [t(CLI, "test_only_linux_x86_64_is_the_supported_platform")]),
    ("doctor fails when the pins do not verify", "doctor.py", "        up = verified_bootstrap()\n    except EnvironmentFault as exc:\n        return Check(\"pinned dependencies\"",
     "        up = bootstrap()\n    except EnvironmentFault as exc:\n        return Check(\"pinned dependencies\"", [t(CLI, "test_pins_that_are_not_the_pinned_trees_fail_and_say_what_to_fetch")]),
]

@pytest.mark.parametrize("name,rel,old,new,tests", CASES, ids=[c[0] for c in CASES])
def test_removing_the_guard_makes_the_tests_fail(tmp_path, name, rel, old, new, tests):
    result = mutant_result(tmp_path, rel, old, new, tests)
    assert result.returncode == 1, f"mutant not killed by a failing test (exit {result.returncode}): {name}\n{result.stdout[-1500:]}"
    assert re.search(r"\b[1-9][0-9]* failed\b", result.stdout), result.stdout[-1500:]


def test_the_selected_tests_pass_on_an_unmodified_copy(tmp_path):
    tests = sorted({x for c in CASES for x in c[4]})
    result = baseline_result(tmp_path, tests)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-1500:]
