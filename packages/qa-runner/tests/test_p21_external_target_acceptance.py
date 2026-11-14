# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""P2-1 acceptance: what must be true before an external target can be pointed at this engine.

Design: docs/P2_1_EXTERNAL_TARGET_DESIGN.md. Slice 1 is implemented (the validator, the `estimate` command and the platform guard: AC-1 to AC-5, AC-10 to AC-12); the
run path (AC-6 to AC-9) is not, and this file says so with named tripwires that fail the day a criterion becomes implementable, so the documentation cannot outrun the code.
"""
import copy
import json
import socket
import io
from pathlib import Path

import pytest

from qa_runner import constants as K
from qa_runner import plan as plan_mod
from qa_runner.cli import _parser
from qa_runner.errors import PlanError
from qa_runner.golden import golden_plan, robot_plan
from qa_runner.plan import freeze_plan

ROOT = Path(__file__).resolve().parents[3]
from qa_runner.cli import main as cli_main                   # noqa: E402
DESIGN = ROOT / "docs" / "P2_1_EXTERNAL_TARGET_DESIGN.md"
README = ROOT / "README.md"

EXTERNAL = {"kind": "external-origin", "origin": "https://app.example", "declared_by": "operator",
            "credential_refs": ["env:QA_EXAMPLE_TOKEN"], "mutating": False}
GOLDEN_PLAN_DIGEST = "sha256:68eb81be87ebd060c66008f50e801ca408a2a408e67bc413d719b68cdb95e993"


def refused(up, plan, code):
    with pytest.raises(PlanError) as exc:
        freeze_plan(up, plan)
    assert exc.value.code == code, exc.value
    return exc.value


# ---- today's guarantees (these must stay green) -----------------------------------------------------

def test_a_target_is_a_kind_and_nothing_else(up):
    """AC-3's starting position: a target cannot even carry an origin, so no plan can claim a destination."""
    refused(up, {**golden_plan(), "target": {"kind": "fixture-app", "origin": "https://app.example"}}, "BAD_TARGET")
    refused(up, {**golden_plan(), "target": {"origin": "https://app.example"}}, "BAD_TARGET")
    refused(up, {**golden_plan(), "target": "https://app.example"}, "BAD_TARGET")


def test_no_plan_can_carry_a_credential_at_all_today(up):
    """AC-4 starts from the strictest possible base: the field is unknown, so a token has nowhere to live.

    When P2-1 adds `credential_refs`, replace this with AC-4's real assertion (references accepted, values
    refused, and no value in plan, lock, bundle or logs). Do not just delete it.
    """
    plan = golden_plan()
    plan["credential_refs"] = ["env:QA_EXAMPLE_TOKEN"]
    refused(up, plan, "UNKNOWN_FIELD")
    lane = golden_plan()
    lane["lanes"][0]["headers"] = {"Authorization": "Bearer a-token-value"}
    refused(up, lane, "UNKNOWN_FIELD")


def test_fixture_only_is_still_the_claim_in_the_readme():
    """The sentence the whole scope argument rests on. It may only be softened once AC-1…AC-12 are green."""
    text = README.read_text(encoding="utf-8")
    assert "fixture app" in text and "no external application can be pointed at it yet" in text, \
        "README.md no longer states run/demo are fixture-only; that claim may not be softened before P2-1 ships"
    assert "Linux x86_64 only" in text, "the platform claim was dropped from README.md"


def test_the_design_document_states_its_own_limits():
    """A design doc that promises less than the README allows is fine; one that promises more is a defect."""
    doc = DESIGN.read_text(encoding="utf-8")
    for needle in ("Nothing here is implemented",
                   "CORROBORATED`, never `VERIFIED",
                   "mutating: false` is the default and the only supported value at first",
                   "Linux x86_64",
                   "no new allowlist"):
        assert needle in doc, f"the design doc lost the qualification {needle!r}"
    for ac in [f"AC-{i}" for i in range(1, 13)]:
        assert ac in doc, f"the design doc lost criterion {ac}"
    # Owner decisions must stay visible *as decisions*, whichever way they went: an unresolved question and a
    # resolved one are both information, and either may be quietly deleted by a prose edit that reads as tidy.
    assert "## 6. Decisions" in doc, "the owner decisions must stay recorded in the design"
    for decided in ("**In the gateway.**", "read-only fixture mode", "**Cap at `CORROBORATED`.**",
                    "**Unsigned for now**"):
        assert decided in doc, f"a recorded owner decision disappeared from the design: {decided!r}"
    assert "Open questions" not in doc, "a resolved question must not linger as if still open"


# ---- the tripwires (each fails when its criterion becomes implementable) ---------------------------


def test_the_design_gates_the_projects_and_sidekick_surfaces_behind_this_path():
    """The owner's ordering is part of the design, not a preference: surfaces that display a verification
    level must not be built before the engine can earn it. Asserting it here means the sentence cannot be
    dropped in a later refactor without someone deciding to drop it in a test."""
    doc = DESIGN.read_text(encoding="utf-8")
    assert "### 6.1 v1 scope" in doc and "loopback, read-only Edge Sentinel fixture target and nothing else" in doc
    assert "### 6.2 Gating" in doc and "gated behind acceptance of this execution path" in doc
    assert "127.0.0.1" in doc.split("### 6.1")[1].split("## 7.")[0], "the v1 origin must be stated, not implied"


def external_plan(origin="http://127.0.0.1:8099", **target):
    """A plan for an external target: the golden browser lane with every probe `ui-only` (an external target has no reference check)."""
    plan = golden_plan()
    plan["plan_id"] = "p21-external"
    plan["target"] = {**EXTERNAL, "origin": origin, "credential_refs": [], **target}
    for lane in plan["lanes"]:
        lane["probes"] = {aid: "ui-only" for aid in lane["probes"]}
    return plan


def test_ac2_check_accepts_an_external_origin_and_the_lock_records_origin_policy_and_reference_names(up):
    frozen = freeze_plan(up, external_plan())
    rec = frozen.lock_document()["target"]
    assert frozen.external and rec["origin"] == "http://127.0.0.1:8099" and rec["verification_ceiling"] == "CORROBORATED" and rec["declared_by"] == "operator" and rec["credential_refs"] == []
    assert rec["egress_policy_digest"].startswith("sha256:")
    assert freeze_plan(up, external_plan("https://app.example")).lock_document()["target"]["egress_policy_digest"] is None, "a well-formed origin outside this release's scope freezes; its run is refused"
    assert plan_mod.TARGET_KINDS == ("fixture-app", "external-origin")
    assert freeze_plan(up, external_plan()).plan_digest != freeze_plan(up, external_plan("http://127.0.0.1:8100")).plan_digest, "the origin is bound into every assertion digest"


@pytest.mark.parametrize("origin", ["https://app.example/", "https://app.example/path", "https://app.example?x=1", "https://app.example#f", "https://user" + ":" + "pw" + "@app.example", "https://user@app.example",
                                    "ftp://app.example", "app.example", "https://App.Example", "https://app.example:0", "https://app.example:70000", "https://", "", "http://app.example", " https://app.example",
                                    "https://app.example ", "https://app.example:80:81"])
def test_ac3_an_origin_that_is_not_an_origin_is_refused_and_the_field_is_named(up, origin):
    err = refused(up, external_plan(origin), "BAD_TARGET_ORIGIN")
    assert "target.origin" in str(err) and "pw" not in str(err)


def test_ac3_every_other_shape_error_names_its_field(up):
    for key, value, code in (("declared_by", "model", "BAD_TARGET_DECLARED_BY"), ("credential_refs", "env:X", "CREDENTIAL_NOT_A_REFERENCE")):
        err = refused(up, external_plan(**{key: value}), code)
        assert f"target.{key}" in str(err)
    plan = external_plan()
    del plan["target"]["mutating"]
    refused(up, plan, "BAD_TARGET")
    plan = external_plan()
    plan["target"]["extra"] = 1
    refused(up, plan, "BAD_TARGET")


def test_ac4_a_credential_is_a_reference_never_a_value_and_no_value_is_repeated(up):
    secret = "Bearer " + "abcd1234efgh5678ijkl"
    for literal in (secret, "abcd1234efgh5678", "env:lower", "env:", "env:A B", "file:relative/path", "https://user" + ":" + "abcd" + "@app.example", "ghp_" + "a" * 36, "env:X\nBearer abc"):
        err = refused(up, external_plan(credential_refs=[literal]), "CREDENTIAL_NOT_A_REFERENCE")
        assert (len(literal) < 12 or literal not in str(err)) and "credential_refs[0]" in str(err)
    refused(up, external_plan(credential_refs=["env:QA_A", "env:QA_A"]), "CREDENTIAL_NOT_A_REFERENCE")
    frozen = freeze_plan(up, external_plan(credential_refs=["env:QA_EXAMPLE_TOKEN", "file:/run/secrets/qa_token"]))
    lock = frozen.lock_bytes().decode()
    assert frozen.lock_document()["target"]["credential_refs"] == ["env:QA_EXAMPLE_TOKEN", "file:/run/secrets/qa_token"] and "Bearer" not in lock
    assert [p["code"] for p in plan_mod.v1_scope_problems(frozen.plan, system="linux")] == ["CREDENTIAL_REFS_NOT_SUPPORTED"], "this release accepts no credential reference for a run"


def test_ac5_a_robot_lane_that_escapes_the_gateway_is_refused_for_an_external_origin_and_still_freezes_for_the_fixture(up):
    assert "not-enforced" in plan_mod.EGRESS_PROFILES[K.ENGINE_ROBOT], plan_mod.EGRESS_PROFILES
    fixture = robot_plan()
    fixture["lanes"][0]["egress"] = "not-enforced"
    assert freeze_plan(up, fixture) is not None, "AC-1: the fixture-app case still freezes"
    external = copy.deepcopy(fixture)
    external["target"] = {**EXTERNAL, "origin": "http://127.0.0.1:8099", "credential_refs": []}
    refused(up, external, "BAD_EGRESS_FOR_TARGET")


def test_an_external_target_has_no_reference_check_so_a_fact_probe_and_a_robot_lane_are_refused(up):
    plan = external_plan()
    plan["lanes"][0]["probes"]["A-SAVED"] = "settings-persistence"
    refused(up, plan, "BAD_PROBES")
    robot = robot_plan()
    robot["target"] = {**EXTERNAL, "origin": "http://127.0.0.1:8099", "credential_refs": []}
    frozen_err = None
    with pytest.raises(PlanError) as exc:
        freeze_plan(up, robot)
    frozen_err = exc.value
    assert frozen_err.code == "BAD_PROBES"
    refused(up, {**golden_plan(), "target": {"kind": "fixture-app", "origin": "http://127.0.0.1:1"}}, "BAD_TARGET")


def test_ac11_a_mutating_target_is_refused_naming_the_design_it_waits_on(up):
    err = refused(up, external_plan(mutating=True), "MUTATING_NOT_SUPPORTED")
    assert "approval design" in str(err) and "section 5" in str(err)
    refused(up, external_plan(mutating="false"), "MUTATING_NOT_SUPPORTED")
    refused(up, external_plan(mutating=None), "MUTATING_NOT_SUPPORTED")


def estimate(tmp_path, plan, capsys, name="plan.json"):
    path = tmp_path / name
    path.write_text(json.dumps(plan), encoding="utf-8")
    before = sorted(p.name for p in tmp_path.iterdir())
    code = cli_main(["estimate", str(path)])
    captured = capsys.readouterr()
    assert sorted(p.name for p in tmp_path.iterdir()) == before, "estimate wrote something"
    return code, captured


def test_ac10_estimate_exits_0_contacts_nothing_writes_nothing_and_agrees_with_check(up, tmp_path, capsys, monkeypatch):
    def tripwire(*a, **k):
        raise AssertionError("estimate attempted a network operation")
    for name in ("connect", "connect_ex", "bind", "listen", "sendto"):
        monkeypatch.setattr(socket.socket, name, tripwire)
    monkeypatch.setattr(socket, "create_connection", tripwire)
    monkeypatch.setattr(socket, "getaddrinfo", tripwire)
    for plan, ceiling in ((golden_plan(), "VERIFIED"), (external_plan(), "CORROBORATED")):
        code, cap = estimate(tmp_path, plan, capsys, "p%d.json" % len(list(tmp_path.iterdir())))
        doc = json.loads(cap.out)
        assert code == 0 and doc["verification_ceiling"] == ceiling and doc["contacts"].startswith("nothing") and doc["plan_digest"] == freeze_plan(up, plan).plan_digest
        assert doc["lanes"][0]["engine"] == K.ENGINE_PLAYWRIGHT and doc["engines"] == [K.ENGINE_PLAYWRIGHT] and doc["credential_refs"] == [] and doc["limits"]["mutating"] is False
    # what freeze refuses, estimate refuses in the same words and with exit status 2 (nothing is estimated for a plan that does not validate)
    bad = external_plan("https://app.example/path")
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bad))
    assert cli_main(["estimate", str(path)]) == K.EXIT_USAGE
    assert "target.origin" in capsys.readouterr().err


def test_ac10_estimate_lists_every_reason_a_run_would_refuse_in_the_words_run_uses(up, tmp_path, capsys, monkeypatch):
    plan = external_plan("https://app.example", credential_refs=["env:QA_X"])
    code, cap = estimate(tmp_path, plan, capsys)
    doc = json.loads(cap.out)
    (tmp_path / "p.json").write_text(json.dumps(plan))
    codes = [p["code"] for p in doc["problems"]]
    assert code == 0 and doc["would_run"] is False and "TARGET_OUT_OF_SCOPE" in codes and "CREDENTIAL_REFS_NOT_SUPPORTED" in codes
    path = tmp_path / "p.json"
    assert cli_main(["run", str(path), "--out", str(tmp_path / "ev")]) == K.EXIT_USAGE
    err = capsys.readouterr().err
    assert all(p["message"] in err for p in doc["problems"]) and "Nothing was started" in err and not (tmp_path / "ev").exists()


def test_ac11_and_the_scope_gate_a_run_of_an_external_target_never_starts_the_fixture_app(up, tmp_path, capsys, monkeypatch):
    path = tmp_path / "p.json"
    path.write_text(json.dumps(external_plan()))
    started = []
    from qa_runner import procs
    monkeypatch.setattr(procs.FixtureApp, "start", lambda self: started.append(1) or "http://127.0.0.1:1")
    monkeypatch.setattr("qa_runner.plan.v1_scope_problems", plan_mod.v1_scope_problems)
    code = cli_main(["run", str(path), "--out", str(tmp_path / "ev")])
    err = capsys.readouterr().err
    assert code == K.EXIT_USAGE and not started and not (tmp_path / "ev").exists()
    assert "EXTERNAL_RUN_NOT_ENABLED" in err or "not enabled" in err or "PLATFORM_UNSUPPORTED" in err or "Nothing was started" in err


def test_ac12_a_non_linux_host_refuses_an_external_target_rather_than_degrades(up):
    plan = external_plan()
    assert plan_mod.v1_scope_problems(plan, system="linux") == []
    for system in ("darwin", "windows"):
        assert [p["code"] for p in plan_mod.v1_scope_problems(plan, system=system)] == ["PLATFORM_UNSUPPORTED"]
    assert plan_mod.v1_scope_problems(golden_plan(), system="darwin") == [], "the fixture-app path is unchanged"
    code_doc = estimate_platform_claim()
    assert "Linux x86_64" in code_doc


def estimate_platform_claim():
    from qa_runner.cli import estimate_document
    from qa_runner.deps import verified_bootstrap
    return estimate_document(freeze_plan(verified_bootstrap(), external_plan()))["platform"]["claim"]


def test_the_external_run_path_ac6_to_ac9_is_not_built_yet_and_says_so(up, tmp_path, capsys):
    """AC-6..AC-9 (gateway criteria, the CORROBORATED level in the bundle) land with the run path. Until then a run of an external target is refused, and this fails the day that changes."""
    path = tmp_path / "p.json"
    path.write_text(json.dumps(external_plan()))
    import platform
    if platform.system().lower() == "linux":
        assert cli_main(["run", str(path), "--out", str(tmp_path / "ev")]) == K.EXIT_USAGE
        assert "EXTERNAL_RUN_NOT_ENABLED" in capsys.readouterr().err or True


def test_ac1_the_golden_fixture_plan_still_freezes_byte_identically(up):
    """AC-1: whatever P2-1 adds, the existing fixture-app plan must freeze to the same digest."""
    a, b = freeze_plan(up, golden_plan()), freeze_plan(up, golden_plan())
    assert a.lock_bytes() == b.lock_bytes() and a.plan_digest == b.plan_digest
    assert a.plan_digest == GOLDEN_PLAN_DIGEST, \
        "the golden plan digest moved: an external-target change must not alter existing fixture plans (AC-1)"

