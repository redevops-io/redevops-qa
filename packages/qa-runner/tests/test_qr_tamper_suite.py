# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Every case of ``qr_tamper_cases`` over the golden bundles (written by a real ``redevops-qa demo``), with the product's ``verify``. A clean bundle is accepted; every changed one is
rejected with the finding that names what changed; the cases that no content can reveal are accepted as internally consistent and rejected by an external anchor or plan digest.
The end-to-end job runs the same cases over bundles written by the run under test (``tests/e2e/test_qr_e2e_tamper.py``)."""
import pytest

from qr_tamper import golden, verify_files_in
from qr_tamper_cases import CASES, CLAIMS, CONSISTENT, REJECTED, check_claim, check_consistent_forgery, check_dropped_and_weakened, check_rejected, check_the_strongest_forger


@pytest.mark.parametrize("case", REJECTED, ids=[c.name for c in REJECTED])
def test_every_change_is_rejected_with_the_finding_that_names_it(up, tmp_path, case):
    check_rejected(up, tmp_path, case, golden)


@pytest.mark.parametrize("defect", ["none", "discount"])
def test_the_clean_bundle_is_accepted_and_every_case_started_from_one_that_was(up, tmp_path, defect):
    v = verify_files_in(tmp_path, golden(defect))
    assert v.accepted and v.findings == []


@pytest.mark.parametrize("case", CONSISTENT, ids=[c.name for c in CONSISTENT])
def test_a_bundle_forged_consistently_is_accepted_only_as_internally_consistent_and_rejected_with_what_comes_from_outside(up, tmp_path, case):
    check_consistent_forgery(up, tmp_path, case, golden)


def test_the_dropped_lane_looks_clean_and_the_weakened_assertion_is_stopped_by_the_engines_own_failure_not_by_the_bundle(up, tmp_path):
    check_dropped_and_weakened(up, tmp_path, golden)


@pytest.mark.parametrize("case", CLAIMS, ids=[c.name for c in CLAIMS])
def test_a_claim_of_verification_that_an_adapter_wrote_is_never_a_verdict(up, tmp_path, case):
    check_claim(up, tmp_path, case, golden)


def test_the_forger_who_rewrites_the_engines_own_files_consistently_is_not_detectable_from_the_bundle_and_is_caught_by_the_anchor(up, tmp_path):
    check_the_strongest_forger(up, tmp_path, golden)


def test_every_case_names_a_distinct_change():
    assert len({c.name for c in CASES}) == len(CASES) >= 35 and len(REJECTED) + len(CONSISTENT) + len(CLAIMS) == len(CASES)
