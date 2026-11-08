# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""P2-1 acceptance: what must be true before an external target can be pointed at this engine.

Design: docs/P2_1_EXTERNAL_TARGET_DESIGN.md. Nothing there is implemented yet, so this file does two jobs.

It pins **today's** guarantees green (the target is a kind and nothing else; no plan can carry a credential;
the README still says fixture-only), and it holds each **future** criterion as a named tripwire that fails
the day it becomes implementable, with a message naming the criterion to update. A design document quietly
outrunning the code is the failure mode this file exists to prevent.
"""
from pathlib import Path

import pytest

from qa_runner import constants as K
from qa_runner import plan as plan_mod
from qa_runner.cli import _parser
from qa_runner.errors import PlanError
from qa_runner.golden import golden_plan, robot_plan
from qa_runner.plan import freeze_plan

ROOT = Path(__file__).resolve().parents[3]
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


def test_ac2_external_origin_is_not_a_supported_target_kind_yet(up):
    """Flip this to AC-2's acceptance assertion when `external-origin` validates. Do not delete it."""
    assert plan_mod.TARGET_KINDS == ("fixture-app",), \
        "AC-2 has landed: TARGET_KINDS admits an external target — replace this tripwire with AC-2's " \
        "assertion (check accepts the target AND run no longer starts the fixture app for it)"
    err = refused(up, {**golden_plan(), "target": EXTERNAL}, "BAD_TARGET")
    assert "fixture-app" in str(err)


def test_ac5_a_robot_lane_can_still_escape_the_gateway_for_the_fixture_target(up):
    """AC-5 forbids `not-enforced` against an external origin. This records why it is permitted today.

    The fixture app is harmless, so an unconstrained Robot socket costs nothing. Against a real deployment it
    would leave no honest verdict to print, which is why AC-5 refuses at `check` instead of warning at run.
    """
    assert "not-enforced" in plan_mod.EGRESS_PROFILES[K.ENGINE_ROBOT], plan_mod.EGRESS_PROFILES
    plan = robot_plan()
    plan["lanes"][0]["egress"] = "not-enforced"
    assert freeze_plan(up, plan) is not None, \
        "AC-5 has landed: a Robot lane with an unconstrained gateway is no longer accepted — this plan must " \
        "now be refused for an external target, and the fixture-app case must still freeze (AC-1)"


def test_ac10_there_is_no_estimate_command_yet():
    """When `estimate` lands this fails: give it AC-10 (no connection attempted, no bundle written, agrees with check)."""
    commands = set(_parser()._subparsers._group_actions[0].choices)
    assert "estimate" not in commands, \
        "AC-10 has landed: `estimate` exists — replace this tripwire with AC-10's assertions"


def test_ac1_the_golden_fixture_plan_still_freezes_byte_identically(up):
    """AC-1: whatever P2-1 adds, the existing fixture-app plan must freeze to the same digest."""
    a, b = freeze_plan(up, golden_plan()), freeze_plan(up, golden_plan())
    assert a.lock_bytes() == b.lock_bytes() and a.plan_digest == b.plan_digest
    assert a.plan_digest == GOLDEN_PLAN_DIGEST, \
        "the golden plan digest moved: an external-target change must not alter existing fixture plans (AC-1)"

