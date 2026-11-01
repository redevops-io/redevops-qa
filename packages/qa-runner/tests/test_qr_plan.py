# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Plans and freezing: strict validation first (unknown fields refused, the contracts parser before the harness mirror), digests, the lock."""
import copy
import json
from pathlib import Path

import pytest

from qa_evidence.canon import dumps_canonical
from qa_runner import constants as K
from qa_runner.errors import PlanError
from qa_runner.golden import golden_plan, robot_lane, robot_plan
from qa_runner.plan import freeze_plan, load_plan_or_lock, materialise_spec, thaw_lock

GOLDEN_PLAN_DIGEST = "sha256:378257b9f4a89e763c85dd043aa20487e57b3075d3abf53539f0a847413b8fc6"
EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "golden-plan.json"


def refused(up, plan, code):
    with pytest.raises(PlanError) as exc:
        freeze_plan(up, plan)
    assert exc.value.code == code, exc.value
    return exc.value


def test_the_example_file_is_the_golden_plan():
    assert json.loads(EXAMPLE.read_text(encoding="utf-8")) == golden_plan()
    assert EXAMPLE.read_bytes() == (json.dumps(golden_plan(), indent=2, sort_keys=True) + "\n").encode("utf-8")


def test_freezing_is_deterministic_and_the_plan_digest_is_a_golden_value(up):
    a, b = freeze_plan(up, golden_plan()), freeze_plan(up, golden_plan())
    assert a.lock_bytes() == b.lock_bytes() and a.lock_digest == b.lock_digest
    assert a.plan_digest == GOLDEN_PLAN_DIGEST            # the same constant on every host: it depends on canonical JSON only
    assert [r["assertion_id"] for r in a.rows] == ["A-NOTIF-ON", "A-SAVED", "A-URL"]
    assert a.lane("browser").harness_pin.startswith("rcv1:")


def test_the_lock_carries_the_plan_the_pins_and_every_digest(up, golden_frozen):
    lock = golden_frozen.lock_document()
    assert lock["plan"] == golden_plan() and lock["plan_digest"] == GOLDEN_PLAN_DIGEST
    assert lock["pins"]["harness"] == "0.2.0" and lock["pins"]["contracts"] in ("0.3.15", "0.3.16")
    assert set(lock["lanes"][0]["assertion_digests"]) == {"A-NOTIF-ON", "A-SAVED", "A-URL"}
    assert dumps_canonical(lock) == golden_frozen.lock_bytes()


def test_changing_an_expected_value_changes_the_plan_digest_and_the_lane_pin(up, golden_frozen):
    plan = golden_plan()
    plan["lanes"][0]["spec"]["assertions"][0]["predicate"]["expected"] = "Settings saved!"
    other = freeze_plan(up, plan)
    assert other.plan_digest != golden_frozen.plan_digest and other.lane("browser").harness_pin != golden_frozen.lane("browser").harness_pin


@pytest.mark.parametrize("where", ["plan", "lane", "spec", "assertion", "step"])
def test_an_unknown_field_is_refused_at_every_level(up, where):
    plan = golden_plan()
    target = {"plan": plan, "lane": plan["lanes"][0], "spec": plan["lanes"][0]["spec"], "assertion": plan["lanes"][0]["spec"]["assertions"][0],
              "step": plan["lanes"][0]["spec"]["steps"][0]}[where]
    target["verdict"] = "PASS"
    err = refused(up, plan, "UNKNOWN_FIELD" if where in ("plan", "lane") else "SPEC_REJECTED")
    assert "verdict" in str(err) or "UNKNOWN_FIELD" in str(err)


def test_the_harness_mirror_alone_would_accept_what_the_contracts_parser_refuses(up):
    """The reason freeze runs the contracts parser first: the mirror tolerates the extra field (and the field changes the hash)."""
    doc = copy.deepcopy(golden_plan()["lanes"][0]["spec"])
    doc["assertions"][0]["verdict"] = "PASS"
    mirror = up.harness.records.TestSpec.from_json(copy.deepcopy(doc))
    assert mirror is not None
    clean = up.harness.records.TestSpec.from_json(copy.deepcopy(golden_plan()["lanes"][0]["spec"]))
    assert mirror.canon_hash() != clean.canon_hash()
    refused(up, {**golden_plan(), "lanes": [{**golden_plan()["lanes"][0], "spec": doc}]}, "SPEC_REJECTED")


@pytest.mark.parametrize("edit,code", [
    (lambda p: p.update(schema="other"), "UNSUPPORTED_PLAN_VERSION"),
    (lambda p: p.update(schema_version="2.0"), "UNSUPPORTED_PLAN_VERSION"),
    (lambda p: p.update(plan_id="bad id"), "BAD_PLAN_ID"),
    (lambda p: p.update(target={"kind": "url"}), "BAD_TARGET"),
    (lambda p: p.update(lanes=[]), "BAD_LANES"),
    (lambda p: p["lanes"][0].update(engine="selenium-chrome"), "UNSUPPORTED_ENGINE"),
    (lambda p: p["lanes"][0].update(engine="appium-android"), "UNSUPPORTED_ENGINE"),
    (lambda p: p["lanes"][0].update(lane_id="Browser"), "BAD_LANE_ID"),
    (lambda p: p["lanes"][0].update(egress="open"), "BAD_EGRESS_PROFILE"),
    (lambda p: p["lanes"][0].update(deadline_s=0), "BAD_DEADLINE"),
    (lambda p: p["lanes"][0].update(deadline_s=True), "BAD_DEADLINE"),
    (lambda p: p["lanes"][0].pop("egress"), "MISSING_FIELD"),
])
def test_structural_refusals(up, edit, code):
    plan = golden_plan()
    edit(plan)
    refused(up, plan, code)


def test_a_non_object_plan_is_refused(up):
    for bad in (None, [], "x", 1):
        refused(up, bad, "PLAN_NOT_AN_OBJECT")


def test_an_assertion_id_in_two_lanes_is_refused_so_every_assertion_is_accounted_once(up):
    plan = golden_plan()
    other = copy.deepcopy(plan["lanes"][0])
    other["lane_id"] = "second"
    plan["lanes"].append(other)
    refused(up, plan, "DUPLICATE_ASSERTION")
    other["spec"]["id"] = "second-spec"
    for a in other["spec"]["assertions"]:
        a["assertion_id"] = "B-" + a["assertion_id"]
    frozen = freeze_plan(up, plan)
    assert len(frozen.rows) == 6 and {r["lane_id"] for r in frozen.rows} == {"browser", "second"}


def test_a_duplicate_lane_id_is_refused(up):
    plan = golden_plan()
    plan["lanes"].append(copy.deepcopy(plan["lanes"][0]))
    refused(up, plan, "DUPLICATE_LANE")


def test_a_spec_with_no_assertion_is_refused_by_the_contracts(up):
    plan = golden_plan()
    plan["lanes"][0]["spec"]["assertions"] = []
    refused(up, plan, "SPEC_REJECTED")


def test_a_float_in_a_plan_is_refused_at_load(up):
    text = json.dumps(golden_plan()).replace('"deadline_s": 120', '"deadline_s": 1.5')
    with pytest.raises(PlanError) as exc:
        load_plan_or_lock(up, text.encode())
    assert exc.value.code == "NOT_STRICT_JSON"


def test_a_duplicate_key_in_a_plan_is_refused_at_load(up):
    with pytest.raises(PlanError) as exc:
        load_plan_or_lock(up, b'{"schema": "x", "schema": "y"}')
    assert exc.value.code == "NOT_STRICT_JSON"


def test_a_lock_round_trips_and_is_recognised(up, golden_frozen):
    thawed, kind = load_plan_or_lock(up, golden_frozen.lock_bytes())
    assert kind == "lock" and thawed.lock_bytes() == golden_frozen.lock_bytes()
    assert load_plan_or_lock(up, dumps_canonical(golden_plan()))[1] == "plan"


@pytest.mark.parametrize("name,edit", [
    ("an expected value edited in the lock's assertions", lambda l: l["lanes"][0]["assertions"][0]["predicate"].update(expected="forged")),
    ("an assertion digest edited", lambda l: l["lanes"][0]["assertion_digests"].update({"A-SAVED": "sha256:" + "0" * 64})),
    ("the plan digest edited", lambda l: l.update(plan_digest="sha256:" + "1" * 64)),
    ("the harness pin edited", lambda l: l["lanes"][0].update(harness_pin="rcv1:" + "2" * 64)),
    ("a pinned tool version edited", lambda l: l["pins"].update(harness="9.9.9")),
    ("the plan inside the lock edited but not its digests", lambda l: l["plan"]["lanes"][0]["spec"]["assertions"][0]["predicate"].update(expected="forged")),
    ("an assertion dropped from the lock", lambda l: l["lanes"][0]["assertions"].pop()),
    ("the runner version edited", lambda l: l.update(runner_version="9.9.9")),
])
def test_an_edited_lock_is_refused(up, golden_frozen, name, edit):
    lock = copy.deepcopy(golden_frozen.lock_document())
    edit(lock)
    with pytest.raises(PlanError) as exc:
        thaw_lock(up, lock)
    assert exc.value.code in ("LOCK_MISMATCH", "SPEC_REJECTED"), name


def test_a_lock_of_another_version_is_refused(up, golden_frozen):
    lock = copy.deepcopy(golden_frozen.lock_document())
    lock["schema_version"] = "2.0"
    with pytest.raises(PlanError) as exc:
        thaw_lock(up, lock)
    assert exc.value.code == "UNSUPPORTED_LOCK_VERSION"
    with pytest.raises(PlanError) as exc:
        thaw_lock(up, {"schema": "something-else"})
    assert exc.value.code == "NOT_A_LOCK"


def test_the_origin_replaces_the_placeholder_at_the_start_of_a_value_only(golden_frozen):
    spec = materialise_spec(golden_frozen.lane("browser").spec_template, "http://127.0.0.1:5000")
    assert spec["steps"][0]["action"]["value"] == "http://127.0.0.1:5000/login"
    assert "{origin}" not in json.dumps(spec)
    assert golden_frozen.lane("browser").spec_template["steps"][0]["action"]["value"] == "{origin}/login"       # the frozen template is untouched
    bad = copy.deepcopy(golden_frozen.lane("browser").spec_template)
    bad["steps"][0]["action"]["value"] = "x{origin}/login"
    with pytest.raises(PlanError):
        materialise_spec(bad, "http://127.0.0.1:5000")
    bad["steps"][0]["action"]["value"] = "{origin}{origin}"
    with pytest.raises(PlanError):
        materialise_spec(bad, "http://127.0.0.1:5000")


def test_the_scope_of_this_release_is_playwright_chromium_and_robot_framework_only():
    assert K.ENGINES == (K.ENGINE_PLAYWRIGHT, K.ENGINE_ROBOT)


# ---- the Robot lane ------------------------------------------------------------------------------------------------------------------------
ROBOT_PLAN_DIGEST = "sha256:2e22f5963529fbdd8b4dd38221ad385a226ad9fd7a5b2a0888ca9b6d721460b5"
ROBOT_EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "robot-plan.json"


def test_the_robot_example_file_is_the_robot_plan():
    assert ROBOT_EXAMPLE.read_bytes() == (json.dumps(robot_plan(), indent=2, sort_keys=True) + "\n").encode("utf-8")


def test_the_robot_plan_freezes_with_the_suite_files_and_the_program_hash_pinned(up):
    frozen = freeze_plan(up, robot_plan())
    lane = frozen.lane("robot")
    assert frozen.plan_digest == ROBOT_PLAN_DIGEST and lane.suite == "order-discount" and set(lane.suite_files) == {"OrderApi.py", "order_discount.robot"}
    assert all(d.startswith("sha256:") and len(d) == 71 for d in lane.suite_files.values())
    assert lane.assertions[0]["check_program_ref"]["id"] == "evidence.robot-observations"
    lock = frozen.lock_document()
    assert lock["lanes"][0]["suite_files"] == dict(sorted(lane.suite_files.items()))


def test_the_expected_value_lives_in_the_frozen_assertion_not_in_any_observation_file(up):
    lane = freeze_plan(up, robot_plan()).lane("robot")
    assert lane.assertions[0]["predicate"]["expected"]["observations"]["order_101_total_cents"] == 9450


def test_a_browser_and_a_robot_lane_freeze_together_with_every_assertion_once(up):
    plan = golden_plan()
    plan["lanes"].append(robot_lane())
    frozen = freeze_plan(up, plan)
    assert sorted(r["lane_id"] for r in frozen.rows) == ["browser", "browser", "browser", "robot"]
    assert len({r["assertion_id"] for r in frozen.rows}) == 4


def robot_refused(up, edit, code):
    plan = robot_plan()
    edit(plan["lanes"][0])
    refused(up, plan, code)


@pytest.mark.parametrize("name,edit,code", [
    ("an unknown suite", lambda l: l.update(suite="../../etc/passwd"), "UNKNOWN_SUITE"),
    ("a suite that is not a name", lambda l: l.update(suite=["order-discount"]), "UNKNOWN_SUITE"),
    ("no suite", lambda l: l.pop("suite"), "MISSING_FIELD"),
    ("the browser's egress profile on a robot lane", lambda l: l.update(egress="origin-only"), "BAD_EGRESS_PROFILE"),
    ("steps in a robot spec", lambda l: l["spec"].update(steps=copy.deepcopy(golden_plan()["lanes"][0]["spec"]["steps"][:1])), "ROBOT_LANE_HAS_STEPS"),
    ("a playwright assertion in a robot lane", lambda l: l["spec"].update(assertions=copy.deepcopy(golden_plan()["lanes"][0]["spec"]["assertions"])), "EXECUTOR_MISMATCH"),
    ("a program hash that is not the registered one", lambda l: l["spec"]["assertions"][0]["check_program_ref"].update(program_hash="sha256:" + "0" * 64), "PROGRAM_HASH_MISMATCH"),
    ("a program that is not registered", lambda l: l["spec"]["assertions"][0]["check_program_ref"].update(id="manifest.probes"), "PROGRAM_NOT_REGISTERED"),
    ("a program version that is not registered", lambda l: l["spec"]["assertions"][0]["check_program_ref"].update(version="9.9.9"), "PROGRAM_NOT_REGISTERED"),
    ("an input path that is not the lane's record", lambda l: l["spec"]["assertions"][0]["subject"]["inputs"][0].update(path="lanes/robot/native/output.xml"), "BAD_ASSERTION_INPUTS"),
    ("two inputs", lambda l: l["spec"]["assertions"][0]["subject"]["inputs"].append({"kind": "MANIFEST_PATH", "path": "plan.lock.json"}), "BAD_ASSERTION_INPUTS"),
])
def test_robot_lane_refusals(up, name, edit, code):
    robot_refused(up, edit, code)


def test_a_browser_lane_may_not_use_the_not_enforced_profile_or_a_script_assertion(up):
    plan = golden_plan()
    plan["lanes"][0]["egress"] = "not-enforced"
    refused(up, plan, "BAD_EGRESS_PROFILE")
    plan = golden_plan()
    plan["lanes"][0]["suite"] = "order-discount"
    refused(up, plan, "UNKNOWN_FIELD")


def test_selenium_and_appium_are_not_part_of_this_workflow(up):
    for engine in ("selenium-chrome", "appium-android", "appium-ios"):
        plan = golden_plan()
        plan["lanes"][0]["engine"] = engine
        refused(up, plan, "UNSUPPORTED_ENGINE")


def test_a_lock_with_an_edited_suite_digest_is_refused(up):
    frozen = freeze_plan(up, robot_plan())
    lock = copy.deepcopy(frozen.lock_document())
    lock["lanes"][0]["suite_files"]["OrderApi.py"] = "sha256:" + "0" * 64
    with pytest.raises(PlanError) as exc:
        thaw_lock(up, lock)
    assert exc.value.code == "LOCK_MISMATCH"
    assert thaw_lock(up, copy.deepcopy(frozen.lock_document())).lock_bytes() == frozen.lock_bytes()
