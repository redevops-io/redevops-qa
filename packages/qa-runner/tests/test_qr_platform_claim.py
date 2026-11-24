# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The platform sentence of an external-target run names the machine the run was made on, and ``verify`` requires the sentence of the machine the report records. The x86_64 sentence is
the one every earlier release wrote, byte for byte, so a bundle made before this change still verifies."""
import hashlib

import pytest

from qa_runner import constants as K
from qa_runner.bundle import extra_limitations

ORIGIN = "http://127.0.0.1:8203"
#: sha256 of ``no_restatement_text("http://127.0.0.1:8203")`` as released in 0.6.2 to 0.6.5
X86_TEXT_SHA256 = hashlib.sha256((
    "This run's target is an external origin (http://127.0.0.1:8203). Nothing in this bundle restates, independently of the engines, what its assertions expect: the target's own request log and a reference check "
    "exist only for the bundled fixture app. The assertions are corroborated by the browser engine's own record, the harness run record and the egress gateway's decisions, so the run level is capped at "
    "CORROBORATED and is never VERIFIED. The platform claim is Linux x86_64 with CPython 3.12 (3.11 for the fixture-app CI); no other host is claimed.").encode()).hexdigest()


def test_the_x86_64_sentence_is_unchanged_and_is_the_default():
    for text in (K.no_restatement_text(ORIGIN), K.no_restatement_text(ORIGIN, "x86_64")):
        assert hashlib.sha256(text.encode()).hexdigest() == X86_TEXT_SHA256


def test_an_arm64_run_names_arm64_and_claims_nothing_else():
    arm = K.no_restatement_text(ORIGIN, "aarch64")
    assert "The platform claim is Linux arm64 with CPython 3.12; no other host is claimed." in arm and "x86_64" not in arm and "3.11" not in arm
    assert arm.split("The platform claim")[0] == K.no_restatement_text(ORIGIN).split("The platform claim")[0], "only the platform sentence differs"


@pytest.mark.parametrize("arch, want", [("aarch64", "aarch64"), ("arm64", "aarch64"), ("ARM64", "aarch64"), ("x86_64", "x86_64"), ("amd64", "x86_64"), ("unknown", "x86_64"), (None, "x86_64"), ("", "x86_64")])
def test_a_claim_is_made_for_arm64_only_when_the_machine_is_arm64(arch, want):
    assert K.claim_arch(arch) == want


def test_the_limitations_of_a_plan_follow_the_machine_given_and_default_to_x86_64():
    class Frozen:
        external = True
        lanes = ()
        plan = {"target": {"origin": ORIGIN}}
    default, arm = extra_limitations(Frozen()), extra_limitations(Frozen(), "aarch64")
    assert [x["id"] for x in default] == [x["id"] for x in arm] == [K.NO_RESTATEMENT_ID]
    assert default[0]["text"] == K.no_restatement_text(ORIGIN) and arm[0]["text"] == K.no_restatement_text(ORIGIN, "aarch64") and default != arm
