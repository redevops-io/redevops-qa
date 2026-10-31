# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Mutation tests: removing a guard makes the suite fail. Each case names the guard, the source it lives in, and the tests that
must catch its removal; the same tests must pass on an unmodified copy."""
import pytest

from qc_mutation import baseline_result, mutant_result

CASES = [
    ("program-hash verification", "registry.py",
     "if spec.program_hash != ph:", "if False:",
     ["test_qc_registry.py::test_a_hash_mismatch_is_refused", "test_qc_registry.py::test_verification_precedes_execution_even_for_a_spy_program",
      "test_qc_adapter.py::test_a_hash_mismatch_is_refused_before_any_input_is_read"]),
    ("unregistered-program refusal", "registry.py",
     "if spec is None:\n            raise ProgramUnregistered", "if False:\n            raise ProgramUnregistered",
     ["test_qc_registry.py::test_an_unregistered_program_is_refused_before_anything_runs"]),
    ("expected-value refusal", "engine.py",
     'refuse_expected(subject, "check subject")', "pass",
     ["test_qc_adapter.py::test_an_expected_value_cannot_reach_a_check"]),
    ("verdict-shaped output refusal", "registry.py",
     "if k.lower() in FORBIDDEN_OUTPUT_KEYS:", "if False:",
     ["test_qc_registry.py::test_an_output_that_looks_like_a_verdict_is_refused"]),
    ("program purity guard", "registry.py",
     "if alias.name.split(\".\")[0] not in ALLOWED_IMPORTS:", "if False:",
     ["test_qc_registry.py::test_an_impure_program_is_refused_at_registration"]),
    ("symbolic link refusal", "manifests.py",
     ("if stat.S_ISLNK(st.st_mode):", "if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):"), ("if False:", "if False:"),
     ["test_qc_loader.py::test_symbolic_links_are_refused"]),
    ("alias refusal in the YAML loader", "manifests.py",
     "if self.check_event(yaml.events.AliasEvent):", "if False:",
     ["test_qc_loader.py::test_unsafe_or_malformed_yaml_is_an_error_entry_not_a_crash_and_not_silent"]),
    ("reference documents cannot carry an expected value", "manifests.py",
     "        if bad is not None:", "        if False:",
     ["test_qc_loader.py::test_a_reference_document_cannot_carry_an_expected_value"]),
    ("tier K needs a gate", "adapter.py",
     "if self._tier_k is None:\n                    raise ce.PolicyBlocked(\"tier K needs a configured", "if False:\n                    raise ce.PolicyBlocked(\"tier K needs a configured",
     ["test_qc_adapter.py::test_tier_k_is_blocked_without_a_gate_and_so_is_a_k_subject"]),
    ("case root digest check", "adapter.py",
     "if actual != profile.case_root_digest:", "if False:",
     ["test_qc_adapter.py::test_the_case_root_digest_in_the_profile_must_match"]),
    ("image blob digest verification", "image_store.py",
     'if "sha256:" + hashlib.sha256(data).hexdigest() != digest:', "if False:",
     ["test_qc_images.py::test_a_config_blob_that_does_not_match_its_name_is_not_trusted",
      "test_qc_images.py::test_a_manifest_blob_that_does_not_match_its_name_gives_no_document"]),
    ("image environment values are dropped", "image_store.py",
     'env_names = sorted({e.split("=", 1)[0] for e in _strs(c.get("Env"))})', 'env_names = sorted(_strs(c.get("Env")))',
     ["test_qc_images.py::test_environment_values_and_build_commands_are_never_kept"]),
    ("image ambiguity is not resolved by first-wins", "image_store.py",
     "if len(docs) > 1:", "if False:",
     ["test_qc_images.py::test_two_documents_with_one_digest_are_ambiguous_not_first_wins"]),
]


def test_the_unmodified_copy_passes_every_selected_test(tmp_path):
    tests = sorted({t for *_, ts in CASES for t in ts})
    r = baseline_result(tmp_path, tests)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]


@pytest.mark.parametrize("name,rel,old,new,tests", CASES, ids=[c[0] for c in CASES])
def test_removing_the_guard_makes_the_suite_fail(tmp_path, name, rel, old, new, tests):
    r = mutant_result(tmp_path, rel, old, new, tests)
    assert r.returncode != 0, f"removing {name!r} was not caught by {tests}"
