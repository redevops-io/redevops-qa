# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The receipt verifier: tamper test, stale-pin test, and the consistency rules."""
import copy
import dataclasses
import json
import shutil

import pytest

from redevops_qa_bridge.conformance import receipt as R
from redevops_qa_bridge.conformance import verify as V
from receipt_helpers import evidence, git, make_repo, summary

AVAILABLE = {"contracts": True, "harness_qa": True}


@pytest.fixture()
def repo(tmp_path):
    return make_repo(tmp_path / "repo")


def make(pins, repo, **kw):
    return R.build_receipt(pins, kw.pop("summary", summary()), evidence(), AVAILABLE, repo, timestamp="2026-10-30T12:00:00Z")


def write(tmp_path, receipt, name="receipt.json"):
    path = tmp_path / name
    path.write_text(json.dumps(receipt), encoding="utf-8")
    return path


def reseal(receipt):
    return R.seal(receipt)


def test_a_current_passing_receipt_is_valid(pins, repo, tmp_path):
    status, reasons = V.verify_receipt(write(tmp_path, make(pins, repo)), pins, redevops_root=repo)
    assert (status, reasons) == ("VALID", [])


# -- tamper ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("edit", [
    lambda r: r.__setitem__("result", "PASS" if r["result"] == "FAIL" else "FAIL"),
    lambda r: r.__setitem__("collected_tests", r["collected_tests"] + 1),
    lambda r: r["checks"][0].__setitem__("status", "FAIL"),
    lambda r: r["subjects"]["contracts"].__setitem__("commit", "0" * 40),
    lambda r: r["vectors"]["items"][0].__setitem__("equal", False),
    lambda r: r.__setitem__("timestamp_utc", "2030-01-01T00:00:00Z"),
    lambda r: r["runner"].__setitem__("run_id", "forged"),
    lambda r: r.__setitem__("extra_field", 1),
    lambda r: r.pop("environment"),
], ids=["result", "totals", "check-status", "commit", "vector-flag", "timestamp", "runner", "added-field", "removed-field"])
def test_any_edit_to_a_receipt_is_detected_as_tampering(pins, repo, tmp_path, edit):
    r = make(pins, repo)
    edit(r)
    status, reasons = V.verify_receipt(write(tmp_path, r), pins, redevops_root=repo)
    assert status == "TAMPERED" and "receipt_hash" in reasons[0]


def test_a_removed_hash_is_not_a_receipt(pins, repo, tmp_path):
    r = make(pins, repo)
    del r["receipt_hash"]
    assert V.verify_receipt(write(tmp_path, r), pins, redevops_root=repo)[0] == "INVALID"


def test_unreadable_files_are_invalid(pins, tmp_path):
    assert V.verify_receipt(tmp_path / "missing.json", pins)[0] == "INVALID"
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert V.verify_receipt(bad, pins)[0] == "INVALID"
    assert V.verify_receipt(write(tmp_path, [1, 2]), pins)[0] == "INVALID"


# -- consistency (hash re-sealed, so only the content rules can catch these) ------------------------------------------------

def test_a_forged_pass_with_a_failing_check_is_invalid_even_if_resealed(pins, repo, tmp_path):
    r = make(pins, repo, summary=summary(failed=("CHK1",)))
    assert r["result"] == "FAIL"
    forged = copy.deepcopy(r)
    forged["result"] = "PASS"
    status, reasons = V.verify_receipt(write(tmp_path, reseal(forged)), pins, redevops_root=repo)
    assert status == "INVALID" and any("result is PASS" in x for x in reasons)


@pytest.mark.parametrize("edit", [
    lambda r: r["checks"].pop(),
    lambda r: r["checks"].reverse(),
    lambda r: r["checks"][0].__setitem__("passed", r["checks"][0]["passed"] + 1),
    lambda r: r.__setitem__("skipped_tests", 0) or r["checks"][1].update(skipped=1, passed=2),
    lambda r: r["vectors"]["items"][0].__setitem__("rcv1_hash", "rcv1:" + "b" * 64),
    lambda r: r.__setitem__("failed_tests", 0) or r["checks"][2].update(failed=1, passed=2, status="FAIL"),
    lambda r: r["checks"][4].update(status="FAIL"),
    lambda r: r.__setitem__("result", "MAYBE"),
    lambda r: r.__setitem__("receipt_version", "2"),
], ids=["six-checks", "order", "counts", "skips-vs-total", "vector-flag", "failures-vs-total", "status-vs-counts", "result", "version"])
def test_inconsistent_receipts_are_invalid_even_if_resealed(pins, repo, tmp_path, edit):
    r = make(pins, repo)
    edit(r)
    status, _ = V.verify_receipt(write(tmp_path, reseal(r)), pins, redevops_root=repo)
    assert status == "INVALID"


def test_a_receipt_containing_a_float_is_invalid(pins, repo, tmp_path):
    r = make(pins, repo)
    r["environment"]["pythonhashseed"] = 1.5
    status, reasons = V.verify_receipt(write(tmp_path, r), pins, redevops_root=repo)
    assert status == "INVALID" and "floats" in reasons[0]


def test_a_failing_but_current_receipt_is_reported_as_failed(pins, repo, tmp_path):
    r = make(pins, repo, summary=summary(failed=("CHK3",)))
    status, reasons = V.verify_receipt(write(tmp_path, r), pins, redevops_root=repo)
    assert status == "FAILED" and any("CHK3" in x for x in reasons)


# -- stale pins --------------------------------------------------------------------------------------------------------------

def _pins_with(pins, which, **changes):
    dep = dataclasses.replace(getattr(pins, which), **changes)
    return dataclasses.replace(pins, **{which: dep})


@pytest.mark.parametrize("which,changes,fragment", [
    ("contracts", {"commit": "1" * 40}, "contracts.commit"),
    ("contracts", {"version": "9.9.9"}, "contracts.version"),
    ("contracts", {"tag": "v9.9.9", "temp_pin": False}, "contracts.tag"),
    ("harness_qa", {"commit": "2" * 40}, "harness_qa.commit"),
    ("harness_qa", {"base_pin": "3" * 40}, "harness_qa.base_pin"),
    ("harness_qa", {"tag": "v0.2.0", "temp_pin": False}, "harness_qa.tag"),
    ("contracts", {"distribution_sha256": "4" * 64}, "contracts"),
    ("harness_qa", {"distribution_sha256": "5" * 64}, "harness_qa"),
], ids=["c-commit", "c-version", "c-tag", "h-commit", "h-base", "h-tag", "c-digest", "h-digest"])
def test_a_changed_pin_makes_the_receipt_stale(pins, repo, tmp_path, which, changes, fragment):
    path = write(tmp_path, make(pins, repo))
    assert V.verify_receipt(path, pins, redevops_root=repo)[0] == "VALID"
    status, reasons = V.verify_receipt(path, _pins_with(pins, which, **changes), redevops_root=repo)
    assert status == "STALE" and any(fragment in x for x in reasons), reasons


def test_a_changed_vector_file_pin_makes_the_receipt_stale(pins, repo, tmp_path):
    path = write(tmp_path, make(pins, repo))
    files = dict(pins.contracts.vector_files)
    files["golden/qa.json"] = "6" * 64
    status, reasons = V.verify_receipt(path, _pins_with(pins, "contracts", vector_files=files), redevops_root=repo)
    assert status == "STALE" and any("golden/qa.json" in x for x in reasons)


def test_an_added_vector_file_pin_makes_the_receipt_stale(pins, repo, tmp_path):
    path = write(tmp_path, make(pins, repo))
    files = dict(pins.harness_qa.vector_files)
    files["tests/qa/golden/new_vectors.json"] = "7" * 64
    status, reasons = V.verify_receipt(path, _pins_with(pins, "harness_qa", vector_files=files), redevops_root=repo)
    assert status == "STALE" and any("new_vectors.json" in x for x in reasons)


def test_a_changed_installed_tree_makes_the_receipt_stale(pins, repo, tmp_path):
    """The receipt was made against one tree; the same pins now resolve to a tree whose content differs."""
    path = write(tmp_path, make(pins, repo))
    copy_root = tmp_path / "tree"
    shutil.copytree(pins.harness_qa.resolved_path / "agent_harness", copy_root / "agent_harness",
                    ignore=shutil.ignore_patterns("__pycache__"), copy_function=shutil.copyfile)
    for rel in pins.harness_qa.vector_files:
        (copy_root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(pins.harness_qa.resolved_path / rel, copy_root / rel)
    (copy_root / "agent_harness" / "qa" / "canon.py").write_text("# edited\n", encoding="utf-8")
    status, reasons = V.verify_receipt(path, _pins_with(pins, "harness_qa", resolved_path=copy_root), redevops_root=repo)
    assert status == "STALE" and any("distribution" in x for x in reasons)


def test_a_new_redevops_qa_commit_makes_the_receipt_stale_unless_skipped(pins, repo, tmp_path):
    path = write(tmp_path, make(pins, repo))
    (repo / "f.txt").write_text("next\n")
    git(repo, "commit", "-q", "-am", "next")
    status, reasons = V.verify_receipt(path, pins, redevops_root=repo)
    assert status == "STALE" and any("redevops_qa.commit" in x for x in reasons)
    assert V.verify_receipt(path, pins, redevops_root=None)[0] == "VALID"


def test_a_different_pin_set_makes_the_receipt_stale(pins, repo, tmp_path):
    path = write(tmp_path, make(pins, repo))
    other = dataclasses.replace(pins, pin_set="other")
    status, reasons = V.verify_receipt(path, other, redevops_root=repo)
    assert status == "STALE" and any("pin set" in x for x in reasons)


def test_tamper_outranks_stale(pins, repo, tmp_path):
    r = make(pins, repo)
    r["collected_tests"] += 1
    status, _ = V.verify_receipt(write(tmp_path, r), _pins_with(pins, "contracts", commit="1" * 40), redevops_root=repo)
    assert status == "TAMPERED"


def test_exit_codes():
    assert V.EXIT == {"VALID": 0, "FAILED": 1, "INVALID": 1, "TAMPERED": 1, "STALE": 2}
