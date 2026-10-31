# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The not-applicable category (an item that cannot apply at a pin set), the completeness item, and the refusal classifier."""
import dataclasses
import json
from pathlib import Path

import pytest

from redevops_qa_bridge import deps, pins as pins_mod
from redevops_qa_bridge.conformance import checks, data as D, items as items_mod
from redevops_qa_bridge.conformance import receipt as R
from redevops_qa_bridge.conformance import verify as V
from redevops_qa_bridge.conformance.context import get_context, set_pins
from redevops_qa_bridge.conformance.items import Item, enumerate_items
from redevops_qa_bridge.conformance.model import ConformanceFailure
from redevops_qa_bridge.errors import PinsInvalid
from receipt_helpers import evidence, make_repo, summary

C4 = "15a6f6cf79f22d27a920f59969dfeb2732a2d1cb"
NA_ITEMS = {("CHK2", "inventory:qa.inventory.json"), ("CHK3", "fields:FaultRecovery"),
            ("CHK4", "enum-presence:IntegrityRefusalCode"), ("CHK4", "enum-presence:RecoveryReason"),
            ("CHK6", "error-vocabulary")}


@pytest.fixture(scope="module")
def items(pins):
    set_pins(pins)
    get_context()
    return enumerate_items()


def _fails(item, code):
    with pytest.raises(ConformanceFailure) as info:
        checks.run_item(item)
    assert info.value.code == code, info.value.message
    return info.value


# -- what the repository pins declare ------------------------------------------------------------------------------------------

def test_c4_declares_no_not_applicable_item_and_c3_declares_exactly_the_five_c4_only_ones():
    c4 = pins_mod.load_pins(pin_set="c4")
    c3 = pins_mod.load_pins(pin_set="c3")
    assert c4.not_applicable == ()
    assert {(n.check, n.item) for n in c3.not_applicable} == NA_ITEMS
    for n in c3.not_applicable:
        assert n.introduced_in == C4 == c4.contracts.commit and n.introduced_in != c3.contracts.commit
        assert n.reason.strip() and n.probe.split(":")[0] in checks.NA_PROBES


def test_both_pin_sets_declare_the_exact_item_counts():
    for name in ("c3", "c4"):
        assert set(pins_mod.load_pins(pin_set=name).expected_items) == {f"CHK{i}" for i in range(1, 8)}


# -- pin validation ----------------------------------------------------------------------------------------------------------------

def _pins_text(extra="", expected=""):
    h = "a" * 40
    text = f'''schema = "redevops-qa/pins"
version = 2
default_set = "a"
[sets.a.contracts]
repo = "r/c"
version = "1"
tag = ""
temp_pin = true
commit = "{h}"
package = "p"
source_path = "c"
distribution_paths = ["p"]
distribution_sha256 = "{"b" * 64}"
[sets.a.contracts.vector_files]
"v.json" = "{"b" * 64}"
[sets.a.harness_qa]
repo = "r/h"
version = "1"
tag = ""
temp_pin = true
commit = "{h}"
base_pin = "{h}"
package = "q"
source_path = "h"
distribution_paths = ["q"]
distribution_sha256 = "{"b" * 64}"
[sets.a.harness_qa.vector_files]
"v.json" = "{"b" * 64}"
'''
    return text + extra + expected


def _na(**kw):
    base = {"check": "CHK4", "item": "enum-presence:X", "introduced_in": "c" * 40, "probe": "contracts_lacks_enum:X",
            "reason": "introduced later"}
    base.update(kw)
    return "[[sets.a.not_applicable]]\n" + "\n".join(f'{k} = "{v}"' for k, v in base.items()) + "\n"


def _load(tmp_path, text):
    path = tmp_path / "pins.toml"
    path.write_text(text)
    return pins_mod.load_pins(path, "a")


def test_a_well_formed_declaration_loads(tmp_path):
    loaded = _load(tmp_path, _pins_text(_na()))
    assert [(n.check, n.item, n.introduced_in) for n in loaded.not_applicable] == [("CHK4", "enum-presence:X", "c" * 40)]


@pytest.mark.parametrize("kw", [{"check": "CHK9"}, {"check": "chk4"}, {"item": ""}, {"introduced_in": "abc"},
                                {"introduced_in": "a" * 40}, {"reason": "  "}, {"probe": ""}])
def test_a_malformed_declaration_is_refused(tmp_path, kw):
    with pytest.raises(PinsInvalid):
        _load(tmp_path, _pins_text(_na(**kw)))


def test_a_declaration_cannot_name_the_commit_that_introduces_the_feature(tmp_path):
    with pytest.raises(PinsInvalid, match="introduces"):
        _load(tmp_path, _pins_text(_na(introduced_in="a" * 40)))


def test_a_duplicate_or_unknown_key_is_refused(tmp_path):
    with pytest.raises(PinsInvalid):
        _load(tmp_path, _pins_text(_na() + _na()))
    with pytest.raises(PinsInvalid):
        _load(tmp_path, _pins_text(_na().replace('reason = "introduced later"', 'reason = "x"\nextra = "y"')))


def test_expected_items_must_be_positive_integers_for_known_checks(tmp_path):
    ok = _load(tmp_path, _pins_text(expected="[sets.a.expected_items]\nCHK1 = 5\n"))
    assert dict(ok.expected_items) == {"CHK1": 5}
    for bad in ("CHK1 = 0", 'CHK1 = "5"', "CHK8 = 5", "CHK1 = 1.5"):
        with pytest.raises(PinsInvalid):
            _load(tmp_path, _pins_text(expected=f"[sets.a.expected_items]\n{bad}\n"))


# -- the items ---------------------------------------------------------------------------------------------------------------------

def test_declared_items_are_swapped_for_not_applicable_items_and_nothing_else(items, pins):
    marked = {(i.check, i.item_id) for lst in items.values() for i in lst if i.kind == "not_applicable"}
    assert marked == {(n.check, n.item) for n in pins.not_applicable}
    for lst in items.values():
        for i in lst:
            if i.kind == "not_applicable":
                assert i.data["real"].item_id == i.item_id and i.data["real"].kind != "not_applicable"


def test_every_check_ends_with_one_completeness_item_and_the_counts_match_the_pins(items, pins):
    for check, lst in items.items():
        assert [i.kind for i in lst].count("completeness") == 1 and lst[-1].kind == "completeness"
        assert len(lst) - 1 == pins.expected_items[check]
        checks.run_item(lst[-1])


def test_a_declared_item_passes_only_while_it_is_really_not_applicable(items, pins):
    for lst in items.values():
        for i in lst:
            if i.kind == "not_applicable":
                checks.run_item(i)


def test_an_item_declared_not_applicable_that_does_apply_fails(items):
    real = Item("CHK1", "x", "bad_file", {"side": "contracts", "rel": "r", "error": "e"})
    entry = pins_mod.NotApplicable("CHK1", "x", "c" * 40, "contracts_lacks_enum:Executor", "reason")
    err = _fails(Item("CHK1", "x", "not_applicable", {"entry": entry, "real": real}), "NOT_APPLICABLE_UNJUSTIFIED")
    assert "Executor" in err.message


def test_an_item_declared_not_applicable_that_passes_fails(items):
    real = Item("CHK4", "enum:Executor", "enum", {"key": "Executor"})
    entry = pins_mod.NotApplicable("CHK4", "enum:Executor", "c" * 40, "contracts_lacks_enum:NoSuchEnum", "reason")
    _fails(Item("CHK4", "enum:Executor", "not_applicable", {"entry": entry, "real": real}), "NOT_APPLICABLE_UNNEEDED")


def test_a_valid_declaration_passes_and_records_what_the_item_would_give(items):
    from redevops_qa_bridge.conformance.model import EVIDENCE
    real = Item("CHK1", "x", "bad_file", {"side": "contracts", "rel": "r", "error": "e"})
    entry = pins_mod.NotApplicable("CHK1", "x", "c" * 40, "contracts_lacks_enum:NoSuchEnum", "reason")
    checks.run_item(Item("CHK1", "x", "not_applicable", {"entry": entry, "real": real}))
    assert EVIDENCE.not_applicable[("CHK1", "x")] == {"real_item_result": "FAIL:VECTOR_FILE_UNUSABLE"}


@pytest.mark.parametrize("probe", ["no_such_probe:x", "contracts_lacks_field:NoSuchRecord.x"])
def test_an_unknown_probe_or_a_probe_that_cannot_establish_absence_fails(items, probe):
    real = Item("CHK1", "x", "bad_file", {"side": "contracts", "rel": "r", "error": "e"})
    entry = pins_mod.NotApplicable("CHK1", "x", "c" * 40, probe, "reason")
    _fails(Item("CHK1", "x", "not_applicable", {"entry": entry, "real": real}), "NOT_APPLICABLE_UNJUSTIFIED")


def test_a_declared_item_that_does_not_exist_is_a_failure(pins):
    entry = pins_mod.NotApplicable("CHK4", "enum-presence:Imaginary", "c" * 40, "contracts_lacks_enum:Imaginary", "reason")
    set_pins(dataclasses.replace(pins, not_applicable=(*pins.not_applicable, entry)))
    try:
        lst = enumerate_items()["CHK4"]
    finally:
        set_pins(pins)
    missing = [i for i in lst if i.kind == "na_missing"]
    assert len(missing) == 1
    _fails(missing[0], "NOT_APPLICABLE_ITEM_MISSING")


def test_a_missing_item_is_caught_by_the_completeness_item(pins, monkeypatch):
    real = items_mod.load_vector_files

    def without_a_case(p):
        files = real(p)
        out = []
        for f in files:
            if f.kind == "golden" and f.side == "contracts":
                data = json.loads(json.dumps(f.data))
                data["cases"].pop("checkpoint")
                f = dataclasses.replace(f, data=data)
            out.append(f)
        return out
    monkeypatch.setattr(items_mod, "load_vector_files", without_a_case)
    lst = enumerate_items()["CHK1"]
    err = _fails(lst[-1], "ITEMS_MISSING")
    assert err.details["expected"] - err.details["actual"] == 1


def test_an_unexpected_extra_item_or_missing_declaration_fails_completeness():
    _fails(Item("CHK1", "completeness:CHK1", "completeness", {"check": "CHK1", "actual": 11, "expected": 10, "pin_set": "x"}),
           "ITEMS_UNEXPECTED")
    _fails(Item("CHK1", "completeness:CHK1", "completeness", {"check": "CHK1", "actual": 9, "expected": 10, "pin_set": "x"}),
           "ITEMS_MISSING")
    _fails(Item("CHK1", "completeness:CHK1", "completeness", {"check": "CHK1", "actual": 9, "expected": None, "pin_set": "x"}),
           "EXPECTED_ITEMS_UNDECLARED")


def test_a_pin_set_without_expected_items_makes_every_completeness_item_fail(pins):
    set_pins(dataclasses.replace(pins, expected_items={}))
    try:
        lst = enumerate_items()
    finally:
        set_pins(pins)
    for check in lst:
        _fails(lst[check][-1], "EXPECTED_ITEMS_UNDECLARED")


# -- receipts and the verifier ------------------------------------------------------------------------------------------------------

@pytest.fixture()
def repo(tmp_path):
    return make_repo(tmp_path / "repo")


def _receipt(pins, repo, **kw):
    return R.build_receipt(pins, kw.pop("summary", None) or summary(pins=pins), kw.pop("evidence", None) or evidence(pins),
                           {"contracts": True, "harness_qa": True}, repo, timestamp="2026-10-30T12:00:00Z")


def _fake_na_pins(pins):
    if pins.not_applicable:
        return pins
    n = pins_mod.NotApplicable("CHK4", "enum-presence:X", "c" * 40, "contracts_lacks_enum:X", "introduced later")
    return dataclasses.replace(pins, not_applicable=(n,))


def test_not_applicable_items_are_counted_named_justified_and_tied_to_a_commit(pins, repo):
    p = _fake_na_pins(pins)
    r = _receipt(p, repo)
    assert r["result"] == "PASS" and r["not_applicable_tests"] == len(p.not_applicable) == len(r["not_applicable"])
    for e in r["not_applicable"]:
        assert set(e) == {"check_id", "item_id", "introduced_in", "probe", "reason", "real_item_result"}
        assert len(e["introduced_in"]) == 40 and e["reason"] and e["real_item_result"].startswith("FAIL:")
    for c in r["checks"]:
        assert c["collected"] == c["passed"] + c["failed"] + c["skipped"] + c["not_applicable"]
        assert c["status"] == "PASS"
    assert r["skipped_tests"] == 0 and r["failed_tests"] == 0


def test_a_pin_set_without_declarations_has_an_empty_not_applicable_section(pins, repo):
    r = _receipt(dataclasses.replace(pins, not_applicable=()), repo, summary=summary(), evidence=evidence())
    assert r["not_applicable"] == [] and r["not_applicable_tests"] == 0 and r["result"] == "PASS"


def test_a_not_applicable_item_without_a_failing_real_item_makes_the_result_fail(pins, repo):
    p = _fake_na_pins(pins)
    ev = evidence(p)
    for key in ev.not_applicable:
        ev.not_applicable[key] = {"real_item_result": ""}
    assert _receipt(p, repo, evidence=ev)["result"] == "FAIL"


def test_a_check_whose_tests_are_all_not_applicable_does_not_pass(pins, repo):
    s = summary(per_check=0, pins=_fake_na_pins(pins))
    r = _receipt(_fake_na_pins(pins), repo, summary=s)
    assert r["result"] == "FAIL" and all(c["status"] == "FAIL" for c in r["checks"])


def _write(tmp_path, receipt):
    path = tmp_path / "r.json"
    path.write_text(json.dumps(receipt))
    return path


def test_the_verifier_accepts_a_consistent_receipt_and_the_strict_flag_rejects_any_not_applicable(pins, repo, tmp_path):
    p = _fake_na_pins(pins)
    path = _write(tmp_path, _receipt(p, repo))
    assert V.verify_receipt(path, p, redevops_root=repo)[0] == "VALID"
    status, reasons = V.verify_receipt(path, p, redevops_root=repo, forbid_not_applicable=True)
    assert status == "FAILED" and "none are allowed" in reasons[0]


def test_the_strict_flag_accepts_a_receipt_with_none(pins, repo, tmp_path):
    p = dataclasses.replace(pins, not_applicable=())
    path = _write(tmp_path, _receipt(p, repo, summary=summary(), evidence=evidence()))
    assert V.verify_receipt(path, p, redevops_root=repo, forbid_not_applicable=True)[0] == "VALID"


@pytest.mark.parametrize("edit", [
    lambda r: r["not_applicable"][0].__setitem__("reason", ""),
    lambda r: r["not_applicable"][0].__setitem__("introduced_in", "abc"),
    lambda r: r["not_applicable"][0].__setitem__("real_item_result", "PASS"),
    lambda r: r["not_applicable"].pop(),
    lambda r: r.__setitem__("not_applicable_tests", 0),
], ids=["no-reason", "no-commit", "real-item-passed", "dropped-entry", "count"])
def test_an_inconsistent_not_applicable_section_is_invalid_even_if_resealed(pins, repo, tmp_path, edit):
    p = _fake_na_pins(pins)
    r = _receipt(p, repo)
    edit(r)
    assert V.verify_receipt(_write(tmp_path, R.seal(r)), p, redevops_root=repo)[0] == "INVALID"


def test_changing_the_declared_not_applicable_items_makes_the_receipt_stale(pins, repo, tmp_path):
    p = _fake_na_pins(pins)
    path = _write(tmp_path, _receipt(p, repo))
    status, reasons = V.verify_receipt(path, dataclasses.replace(p, not_applicable=()), redevops_root=repo)
    assert status == "STALE" and any("not_applicable" in x for x in reasons)


def test_an_equal_tree_is_current_only_when_accepted_explicitly(pins, repo, tmp_path):
    from receipt_helpers import git
    path = _write(tmp_path, _receipt(_fake_na_pins(pins), repo))
    git(repo, "commit", "-q", "--amend", "--date=2000-01-01T00:00:00", "-m", "same tree, other commit")
    p = _fake_na_pins(pins)
    assert V.verify_receipt(path, p, redevops_root=repo)[0] == "STALE"
    assert V.verify_receipt(path, p, redevops_root=repo, accept_equal_tree=True)[0] == "VALID"
    (repo / "f.txt").write_text("a different tree\n")
    git(repo, "commit", "-q", "-am", "different tree")
    assert V.verify_receipt(path, p, redevops_root=repo, accept_equal_tree=True)[0] == "STALE"


def test_the_receipt_records_the_git_tree(pins, repo):
    from receipt_helpers import git
    assert _receipt(pins, repo)["subjects"]["redevops_qa"]["tree"] == git(repo, "rev-parse", "HEAD^{tree}")


# -- the refusal classifier (CHK6 classification) ----------------------------------------------------------------------------------

def _classification(code, expected):
    return Item("CHK6", f"classification:{code}", "classification", {"case": {"code": code, "classification": expected, "why": ""}})


INTEGRITY = ["INCONCLUSIVE", "ASSERTION_INTEGRITY"]


def test_unknown_and_empty_codes_are_classified_by_the_neutral_classifier_not_by_an_error_class_lookup(contracts):
    if not hasattr(contracts, "classify_refusal"):
        # the pinned contracts predate the classifier: the item is not enumerated at this pin set, and cannot run
        assert not any(i.item_id.startswith("classification:") for lst in enumerate_items().values() for i in lst)
        return
    for code in ("A_CODE_FROM_A_LATER_VERSION", "", "ASSERTION_PIN_MALFORMED", "ASSERTION_HASH_MISMATCH"):
        checks.run_item(_classification(code, INTEGRITY))
    for code in ("SPEC_INVALID", "CHECK_PROGRAM_REF_REQUIRED"):
        checks.run_item(_classification(code, None))


def test_a_neutral_classifier_that_does_not_fail_closed_is_caught(contracts, neutral, monkeypatch):
    if not hasattr(contracts, "classify_refusal"):
        assert not any(i.item_id.startswith("classification:") for lst in enumerate_items().values() for i in lst)
        return
    classify = deps.neutral_module("classify")
    real = classify.classify_refusal
    monkeypatch.setattr(classify, "classify_refusal", lambda code: None if code == "A_CODE_FROM_A_LATER_VERSION" else real(code))
    checks.run_item(_classification("ASSERTION_PIN_MALFORMED", INTEGRITY))
    _fails(_classification("A_CODE_FROM_A_LATER_VERSION", INTEGRITY), "REFUSAL_PARITY")


def test_a_neutral_module_without_a_classifier_fails_the_classification_items(contracts, neutral, monkeypatch):
    if not hasattr(contracts, "classify_refusal"):
        assert not any(i.item_id.startswith("classification:") for lst in enumerate_items().values() for i in lst)
        return
    monkeypatch.delattr(deps.neutral_module("classify"), "classify_refusal")
    _fails(_classification("A_CODE_FROM_A_LATER_VERSION", INTEGRITY), "INTEGRITY_CODE_VOCABULARY")


def test_a_classifier_and_an_error_class_that_disagree_are_caught(contracts, neutral, monkeypatch):
    if not hasattr(contracts, "classify_refusal"):
        assert not any(i.item_id.startswith("classification:") for lst in enumerate_items().values() for i in lst)
        return
    classify = deps.neutral_module("classify")
    real = classify.classify_refusal
    monkeypatch.setattr(classify, "classify_refusal", lambda code: real(code))
    monkeypatch.setattr(neutral.errors.AssertionHashMismatch, "run_outcome", None)
    _fails(_classification("ASSERTION_HASH_MISMATCH", INTEGRITY), "REFUSAL_PARITY")


def test_a_batch_halting_disagreement_is_caught(contracts, neutral, monkeypatch):
    if not hasattr(contracts, "classify_refusal"):
        assert not any(i.item_id.startswith("classification:") for lst in enumerate_items().values() for i in lst)
        return
    monkeypatch.setattr(deps.neutral_module("classify"), "refusal_halts_batch", lambda code: False)
    _fails(_classification("A_CODE_FROM_A_LATER_VERSION", INTEGRITY), "REFUSAL_PARITY")
