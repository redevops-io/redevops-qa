# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The product-level tamper suite over bundles written by the run under test: two real engines, real runs for the clean target and the discount defect, then every case of
``qr_tamper_cases`` with ``verify``. The same cases run offline over the golden bundles."""
import pytest

from qa_evidence.build import read_files
from qa_runner.golden import demo_plan
from qa_runner.orchestrate import RunOptions, run_plan
from qa_runner.plan import freeze_plan
from qr_tamper import codes, verify_files_in
from qr_tamper_cases import CLAIMS, CONSISTENT, REJECTED, check_claim, check_consistent_forgery, check_dropped_and_weakened, check_rejected, check_the_strongest_forger

pytestmark = pytest.mark.e2e


@pytest.fixture(scope="module")
def fresh(up, tmp_path_factory):
    frozen = freeze_plan(up, demo_plan())
    out = {}
    for defect in ("none", "discount"):
        s = run_plan(up, frozen, RunOptions(defect=defect))
        out[defect] = dict(s.bundle.files)
    return lambda defect: out[defect]


def test_the_bundles_this_run_wrote_are_accepted(up, tmp_path, fresh):
    none, discount = verify_files_in(tmp_path, fresh("none")), verify_files_in(tmp_path, fresh("discount"))
    assert none.accepted and none.exit_code == 0 and discount.accepted and discount.exit_code == 1, (codes(none), codes(discount))


@pytest.mark.parametrize("case", REJECTED, ids=[c.name for c in REJECTED])
def test_every_change_is_rejected(up, tmp_path, fresh, case):
    check_rejected(up, tmp_path, case, fresh)


@pytest.mark.parametrize("case", CONSISTENT, ids=[c.name for c in CONSISTENT])
def test_a_consistent_forgery_needs_the_anchor(up, tmp_path, fresh, case):
    check_consistent_forgery(up, tmp_path, case, fresh)


def test_the_dropped_lane_and_the_weakened_assertion(up, tmp_path, fresh):
    check_dropped_and_weakened(up, tmp_path, fresh)


@pytest.mark.parametrize("case", CLAIMS, ids=[c.name for c in CLAIMS])
def test_an_adapter_claim_is_never_a_verdict(up, tmp_path, fresh, case):
    check_claim(up, tmp_path, case, fresh)


def test_the_strongest_forger_needs_the_anchor(up, tmp_path, fresh):
    check_the_strongest_forger(up, tmp_path, fresh)
