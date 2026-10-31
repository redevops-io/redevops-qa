# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""compat-receipt/1: the field list of ADR A.2.7 and the rule for its result."""
import json

import pytest

from redevops_qa_bridge.conformance import receipt as R
from receipt_helpers import evidence, make_repo, summary

AVAILABLE = {"contracts": True, "harness_qa": True}


@pytest.fixture()
def repo(tmp_path):
    return make_repo(tmp_path / "repo")


def build(pins, repo, **kw):
    s = kw.pop("summary", summary())
    return R.build_receipt(pins, s, kw.pop("evidence", evidence()), kw.pop("availability", AVAILABLE), repo,
                           timestamp="2026-10-30T12:00:00Z")


def test_the_top_level_fields_are_exactly_the_adr_list(pins, repo):
    r = build(pins, repo)
    assert set(r) == {"receipt_schema", "receipt_version", "result", "subjects", "environment", "schema_ids",
                      "dependencies_available", "vectors", "checks", "collected_tests", "skipped_tests", "failed_tests",
                      "timestamp_utc", "runner", "receipt_hash"}
    assert (r["receipt_schema"], r["receipt_version"]) == ("redevops-qa/compat-receipt", "1")


def test_subjects_carry_repo_version_tag_commit_and_the_installed_digest(pins, repo):
    r = build(pins, repo)
    s = r["subjects"]
    for name, dep in (("contracts", pins.contracts), ("harness_qa", pins.harness_qa)):
        assert (s[name]["repo"], s[name]["version"], s[name]["tag"], s[name]["commit"]) == (dep.repo, dep.version, dep.tag, dep.commit)
        assert s[name]["distribution_digest"] == "sha256:" + dep.distribution_sha256
    assert s["harness_qa"]["base_pin"] == pins.harness_qa.base_pin
    assert s["redevops_qa"]["commit"] and s["redevops_qa"]["worktree_clean"] is True
    assert s["redevops_qa"]["repo"] == "redevops-io/redevops-qa" and s["redevops_qa"]["tag"] == ""
    assert s["pin_set"] == pins.pin_set


def test_environment_runner_and_schema_sections(pins, repo, monkeypatch):
    monkeypatch.setenv("QA_CI_WORKFLOW", "tests.yml")
    monkeypatch.setenv("QA_CI_RUN_ID", "12345")
    r = build(pins, repo)
    assert set(r["environment"]) == {"python_version", "platform", "interpreter_class", "pythonhashseed"}
    assert r["runner"] == {"workflow": "tests.yml", "run_id": "12345"}
    assert r["schema_ids"]["contract_id"] == "qa/v1" and r["schema_ids"]["neutral_api"] == "qa-neutral/1"
    assert r["schema_ids"]["hash_algorithms"] == {"contracts": "rcv1", "neutral": "canon-v1"}
    assert r["dependencies_available"] == AVAILABLE
    assert r["timestamp_utc"] == "2026-10-30T12:00:00Z"


def test_the_receipt_holds_no_credential_variable_names_or_values(pins, repo, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secretsecretsecret")
    monkeypatch.setenv("QA_CI_RUN_ID", "9")
    text = json.dumps(build(pins, repo))
    assert "ghp_secret" not in text and "GITHUB_TOKEN" not in text


def test_vectors_section(pins, repo):
    r = build(pins, repo)
    v = r["vectors"]
    assert v["items"] == [{"vector_id": "v1", "source": "contracts_golden", "canon_v1_hash": "canon-v1:" + "a" * 64,
                           "rcv1_hash": "rcv1:" + "a" * 64, "golden_hash": "rcv1:" + "a" * 64, "equal": True}]
    assert v["contracts_golden_qa_json_sha256"] == pins.contracts.vector_files["golden/qa.json"]
    assert v["contracts_vector_files_sha256"] == dict(sorted(pins.contracts.vector_files.items()))
    assert v["harness_vector_files_sha256"] == dict(sorted(pins.harness_qa.vector_files.items()))


def test_there_are_seven_checks_with_the_adr_fields(pins, repo):
    r = build(pins, repo)
    assert [c["check_id"] for c in r["checks"]] == [f"CHK{i}" for i in range(1, 8)]
    for c in r["checks"]:
        assert set(c) == {"check_id", "name", "collected", "passed", "failed", "skipped", "status", "failure_codes"}
        assert (c["collected"], c["passed"], c["failed"], c["skipped"], c["status"]) == (3, 3, 0, 0, "PASS")


def test_no_floats_and_integers_for_counts(pins, repo):
    r = build(pins, repo)
    R.canonical_json(r)                    # raises on a float
    assert all(type(r[k]) is int for k in ("collected_tests", "skipped_tests", "failed_tests"))


def test_a_clean_run_passes(pins, repo):
    r = build(pins, repo)
    assert r["result"] == "PASS" and (r["collected_tests"], r["skipped_tests"], r["failed_tests"]) == (21, 0, 0)


@pytest.mark.parametrize("kwargs,why", [
    ({"summary": summary(failed=("CHK3",))}, "a failed check"),
    ({"summary": summary(skipped=("CHK5",))}, "a skipped test"),
    ({"summary": summary(drop=("CHK2",))}, "a check with no test"),
    ({"summary": summary(unmapped=1)}, "a test outside the seven checks"),
    ({"summary": summary(collection_errors=("t.py",))}, "a collection error"),
    ({"availability": {"contracts": False, "harness_qa": True}}, "contracts unavailable"),
    ({"availability": {"contracts": True, "harness_qa": False}}, "harness unavailable"),
    ({"summary": {"collected": 0, "collection_errors": [], "tests": []}}, "zero collected tests"),
])
def test_result_is_fail_unless_everything_holds(pins, repo, kwargs, why):
    assert build(pins, repo, **kwargs)["result"] == "FAIL", why


def test_zero_collected_is_reported_per_check_and_in_the_totals(pins, repo):
    r = build(pins, repo, summary={"collected": 0, "collection_errors": [], "tests": []})
    assert r["collected_tests"] == 0 and all("NO_TESTS_COLLECTED" in c["failure_codes"] for c in r["checks"])


def test_a_skip_is_counted_and_named(pins, repo):
    r = build(pins, repo, summary=summary(skipped=("CHK5",)))
    assert r["skipped_tests"] == 1
    chk5 = r["checks"][4]
    assert chk5["status"] == "FAIL" and chk5["skipped"] == 1 and "SKIPPED_TESTS" in chk5["failure_codes"]


def test_failure_codes_are_collected_per_check(pins, repo):
    r = build(pins, repo, summary=summary(failed=("CHK1", "CHK4")))
    assert r["checks"][0]["failure_codes"] == ["HASH_DIVERGENCE"] and r["checks"][3]["failure_codes"] == ["HASH_DIVERGENCE"]
    assert r["failed_tests"] == 2


def test_a_dirty_working_tree_makes_the_result_fail(pins, repo):
    (repo / "f.txt").write_text("changed\n")
    r = build(pins, repo)
    assert r["subjects"]["redevops_qa"]["worktree_clean"] is False and r["result"] == "FAIL"


def test_a_directory_that_is_not_a_git_checkout_fails(pins, tmp_path):
    r = build(pins, tmp_path)
    assert r["subjects"]["redevops_qa"]["commit"] == "" and r["result"] == "FAIL"


def test_the_tag_at_head_is_recorded(pins, repo):
    from receipt_helpers import git
    git(repo, "tag", "-m", "t", "test-tag")
    assert build(pins, repo)["subjects"]["redevops_qa"]["tag"] == "test-tag"


def test_receipt_hash_covers_every_other_field_and_is_sorted_compact_sha256(pins, repo):
    import hashlib
    r = build(pins, repo)
    body = {k: v for k, v in r.items() if k != "receipt_hash"}
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert r["receipt_hash"] == "sha256:" + hashlib.sha256(text.encode()).hexdigest()
    assert R.receipt_hash_of(r) == r["receipt_hash"]


def test_canonical_json_refuses_floats():
    with pytest.raises(ValueError):
        R.canonical_json({"a": 1.5})
    with pytest.raises(ValueError):
        R.canonical_json({"a": [{"b": 2.0}]})
