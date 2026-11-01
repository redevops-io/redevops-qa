# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``evidence.robot-observations``: a check program over the record an importer wrote from a Robot run. It observes; the harness verifier compares the observation
with the value frozen in the assertion, and the record never carries that value."""
import copy
import json

import pytest

from redevops_qa_checks.adapter import CheckAdapter
from redevops_qa_checks.engine import CheckEngine
from redevops_qa_checks.errors import ExpectedValueRefused
from redevops_qa_checks.manifests import tree_digest
from redevops_qa_checks.registry import EVIDENCE_MODULES, builtin_registry, evidence_registry

PID = "evidence.robot-observations"
PATH = "lanes/robot/observations.json"


def record(observations, **spec):
    return {"apiVersion": "qa-checks/reference-1", "kind": "RobotObservations", "metadata": {"name": "robot"},
            "spec": {"engine": "robot-framework", "run_id": "r0-x.robot", "observations": observations, **spec}}


def root_with(tmp_path, doc=None, raw=None):
    root = tmp_path / "case"
    (root / "lanes" / "robot").mkdir(parents=True)
    (root / PATH).write_bytes(raw if raw is not None else json.dumps(doc).encode())
    return root


@pytest.fixture(scope="module")
def evidence():
    return evidence_registry()


def subject(evidence, path=PATH, program_hash=None):
    return {"check_program_ref": {"id": PID, "version": "1.0.0", "program_hash": program_hash or evidence.registered_program_hash(PID, "1.0.0")},
            "inputs": [{"kind": "MANIFEST_PATH", "path": path}], "tier": "OFFLINE"}


def test_the_evidence_registry_holds_the_program_and_the_builtin_registry_is_unchanged(evidence):
    assert EVIDENCE_MODULES == ("robot_observations",) and [e.id for e in evidence.entries()] == [PID]
    assert builtin_registry().registered_program_hash(PID, "1.0.0") is None
    assert evidence.registered_program_hash(PID, "1.0.0").startswith("sha256:")


def test_it_returns_the_observed_pairs_and_how_many_records_it_was_given(tmp_path, evidence):
    root = root_with(tmp_path, record({"order_101_total_cents": 9450, "banner": "Hello"}))
    out = CheckEngine(root, evidence).run_check(subject(evidence))
    assert out.resolution == "RESOLVED" and out.value == {"documents": 1, "observations": {"banner": "Hello", "order_101_total_cents": 9450}, "input_errors": []}


def test_only_integers_and_strings_pass_through(tmp_path, evidence):
    root = root_with(tmp_path, record({"a": 1, "b": "x", "c": True, "d": None, "e": [1], "f": {"g": 1}}))
    assert CheckEngine(root, evidence).run_check(subject(evidence)).value["observations"] == {"a": 1, "b": "x"}


def test_a_missing_path_is_unresolved_never_a_value(tmp_path, evidence):
    root = root_with(tmp_path, record({"a": 1}))
    assert CheckEngine(root, evidence).run_check(subject(evidence, path="lanes/robot/other.json")).resolution == "UNRESOLVED"


def test_two_records_or_no_record_cannot_equal_a_value_written_for_one(tmp_path, evidence):
    root = tmp_path / "case"
    (root / "d").mkdir(parents=True)
    (root / "d" / "a.json").write_text(json.dumps(record({"a": 1})))
    (root / "d" / "b.json").write_text(json.dumps(record({"a": 1})))
    both = CheckEngine(root, evidence).run_check(subject(evidence, path="d")).value
    assert both["documents"] == 2 and both["observations"] == {}
    (root / "e").mkdir()
    (root / "e" / "x.json").write_text(json.dumps({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "x"}}))
    none = CheckEngine(root, evidence).run_check(subject(evidence, path="e")).value
    assert none["documents"] == 0 and none["observations"] == {}


@pytest.mark.parametrize("key", ["expected", "expected_value", "expect", "predicate", "verdict", "Expected"])
def test_a_record_that_carries_an_expected_looking_key_is_not_loaded_and_says_so(tmp_path, evidence, key):
    root = root_with(tmp_path, record({"a": 1}, **{key: 9450}))
    out = CheckEngine(root, evidence).run_check(subject(evidence)).value
    assert out["documents"] == 0 and out["observations"] == {} and out["input_errors"] == [{"source": PATH, "code": "REFERENCE_CARRIES_EXPECTED"}]


def test_an_observation_named_like_a_result_is_refused_by_the_output_check(tmp_path, evidence):
    from redevops_qa_checks.errors import OutputRefused
    root = root_with(tmp_path, record({"passed": 1}))
    with pytest.raises(OutputRefused):
        CheckEngine(root, evidence).run_check(subject(evidence))


def test_a_malformed_record_is_reported_as_a_load_error(tmp_path, evidence):
    out = CheckEngine(root_with(tmp_path, raw=b"{not json"), evidence).run_check(subject(evidence)).value
    assert out["documents"] == 0 and out["input_errors"] and out["input_errors"][0]["source"] == PATH


def test_a_subject_that_carries_an_expected_value_is_refused(tmp_path, evidence):
    root = root_with(tmp_path, record({"a": 1}))
    s = subject(evidence)
    s["expected"] = {"a": 1}
    with pytest.raises(ExpectedValueRefused):
        CheckEngine(root, evidence).run_check(s)


def test_the_program_hash_is_checked_before_anything_is_read(tmp_path, evidence):
    from redevops_qa_checks.errors import ProgramHashMismatch
    root = root_with(tmp_path, record({"a": 1}))
    with pytest.raises(ProgramHashMismatch):
        CheckEngine(root, evidence).run_check(subject(evidence, program_hash="sha256:" + "0" * 64))


def test_the_harness_verifier_compares_the_observation_with_the_frozen_value_and_the_verdict_is_its_alone(tmp_path, evidence):
    """The SCRIPT executor end to end: the record holds no expected value; the assertion does."""
    from agent_harness.qa import records, specstore, verifier
    R = records
    values = {"order_101_total_cents": 9450, "order_102_total_cents": 9999}
    root = root_with(tmp_path, record(values))
    adapter = CheckAdapter(root, registry=evidence)
    ws = adapter.open_workspace(R.CheckProfile(case_root_digest=tree_digest(root), tier=R.CheckTier("OFFLINE")))
    ref = {"id": PID, "version": "1.0.0", "program_hash": evidence.registered_program_hash(PID, "1.0.0")}

    def doc(expected):
        return {"schema_id": "runtime-contracts/qa/assertion-spec", "schema_version": "0.1", "assertion_id": "A-RULE", "executor": "SCRIPT", "check_program_ref": ref,
                "determinism": "DETERMINISTIC", "on_unresolvable": "INDETERMINATE", "predicate": {"op": "EQUALS", "expected": expected},
                "subject": {"kind": "RESOURCE_INPUTS", "inputs": [{"kind": "MANIFEST_PATH", "path": PATH}], "subject_alternates": []},
                "verifier_id": verifier.VERIFIER_ID, "verifier_version_range": ">=1.0,<2"}

    def verdict(expected):
        d = doc(expected)
        pin = verifier.assertion_set_pin((R.AssertionSpec.from_json(copy.deepcopy(d)),))
        out = verifier.DeterministicVerifier(programs=evidence, check_adapter=adapter).verify_run(specstore.InMemorySpecStore({pin: [d]}), pin,
                                                                                                   lineage=verifier.ApprovedLineage([pin]), workspace=ws)
        return out[0].check.verdict.value
    good = {"documents": 1, "input_errors": [], "observations": values}
    assert verdict(good) == "PASS"
    assert verdict({**good, "observations": {**values, "order_101_total_cents": 10500}}) == "FAIL"        # what the defect would have recorded, frozen as the expectation: it is the verifier's comparison that fails or passes
