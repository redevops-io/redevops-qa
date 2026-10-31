# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""One named test per incompatibility found between the harness neutral module and contracts qa/v1.

K1 value digest, K2 object-set order, K3 distinct refusal codes and unknown-code fail-closed, K4 ``reason_code``;
A1 ``Check.detail``, A2 ``Check.evidence_refs`` order, A3 ``SecretRef`` without ``path``, A4 ``EvidenceRef`` defaults,
A5 ``ActionTimeout.recoverable``.

Each test pins the concrete hashes or codes as literals and drives the neutral module directly (not through the generic
parametrised vector run), so a regression names itself. Every test holds against the aligned harness and fails against the
earlier harness behaviour, which these tests were checked against (see the handoff for the table). The contracts side is
compared wherever the pinned contracts define the behaviour; the literals are the contracts' own hashes and codes.
"""
import copy

import pytest

from redevops_qa_bridge import convert, deps
from redevops_qa_bridge.conformance import data as D
from redevops_qa_bridge.conformance.variants import VARIANTS

VARIANT = {v.variant_id: v for v in VARIANTS}


def _digest(h):
    return h.split(":", 1)[1]


def _same(*hashes):
    return len({_digest(h) for h in hashes}) == 1


@pytest.fixture(scope="module")
def reg(contracts, neutral):
    return convert.registry()


def _case(golden, name):
    return D.case_input(golden["cases"][name]), golden["cases"][name]["schema_id"]


def _both(reg, golden, name, edit):
    data, sid = _case(golden, name)
    edit(data)
    c_cls, n_cls = reg.records[sid]
    return (c_cls.from_json(copy.deepcopy(data)).content_hash, n_cls.from_json(copy.deepcopy(data)).canon_hash(), data)


# -- K1: the digest of an action value ------------------------------------------------------------------------------------

K1_STRING = [("hunter2", "rcv1:4ddbb67bf993867e13253c146a339ed3b33ea5b895543569278e99d5b3c2b7d5"),
             ("café", "rcv1:28380feb8724d669bc8d4cf5b5a5bb1adbdc61b81ebd06f3fabc567b4f3b0fc5"),
             ("", "rcv1:12ae32cb1ec02d01eda3581b127c1fee3b0dc53572ed6baf239721a03d82e126")]


@pytest.mark.parametrize("value,expected", K1_STRING, ids=["plain", "nfc", "empty"])
def test_k1_a_string_action_value_digests_as_rcv1_of_the_value_alone(neutral, value, expected):
    receipts = deps.neutral_module("receipts")
    r = neutral.records
    canonical = deps.contracts_package_module("canonical")
    got = receipts.value_digest(r.Action(kind=r.ActionKind.FILL, value=value))
    assert got == expected == canonical.content_hash(value)


def test_k1_the_action_kind_does_not_enter_the_value_digest(neutral):
    receipts = deps.neutral_module("receipts")
    r = neutral.records
    digests = {receipts.value_digest(r.Action(kind=k, value="hunter2")) for k in (r.ActionKind.FILL, r.ActionKind.SELECT,
                                                                                   r.ActionKind.NAVIGATE)}
    assert digests == {K1_STRING[0][1]}


def test_k1_a_secret_reference_digests_as_the_reference_fingerprint_not_a_wrapped_form(neutral):
    receipts = deps.neutral_module("receipts")
    secrets = deps.contracts_package_module("protocol.secrets")
    r = neutral.records
    ref = {"key": "token", "namespace": "tenant-a", "path": "kv/app", "provider": "vault", "version": "3"}
    got = receipts.value_digest(r.Action(kind=r.ActionKind.FILL, secret_ref=r.SecretRef(**ref)))
    assert got == "rcv1:f5fbad10aed509d5f10c55cae64377d84f34d9ce8d3dbced91515130a0f04173" == secrets.SecretRef(**ref).fingerprint()


# -- K2: the order of object sets -------------------------------------------------------------------------------------------

def test_k2_fixtures_are_ordered_by_id_not_by_canonical_text(reg, golden):
    def edit(d):
        d["fixtures"] = [{"id": "seed-b", "content_hash": "sha256:" + "0" * 63 + "3"},
                         {"id": "seed-a", "content_hash": "sha256:" + "0" * 63 + "9"}]
    c, n, _ = _both(reg, golden, "test_spec_ui", edit)
    assert c == "rcv1:becf7e5ef392dec128afdcefcbb054893f60c2e0fcbf179cccdc7f0d822a3d96"
    assert n == "canon-v1:becf7e5ef392dec128afdcefcbb054893f60c2e0fcbf179cccdc7f0d822a3d96"


def test_k2_step_results_are_ordered_by_step_id_not_by_canonical_text(reg, golden):
    def edit(d):
        base = d["step_results"][0]
        first = dict(base, step_id="s1", receipts=["rcv1:" + "f" * 64])
        second = dict(base, step_id="s2", receipts=["rcv1:" + "0" * 64])
        d["step_results"] = [second, first]
    c, n, _ = _both(reg, golden, "run_manifest_pass", edit)
    assert c == "rcv1:b693f24b5f070b09c2d01926a31b7182e8fad34a50457142fea9fa1cff571c5e"
    assert n == "canon-v1:b693f24b5f070b09c2d01926a31b7182e8fad34a50457142fea9fa1cff571c5e"


def test_k2_assertion_results_are_ordered_by_assertion_id_not_by_canonical_text(reg, golden):
    def edit(d):
        d["assertion_results"][0]["actual"] = "zzz"
        d["assertion_results"][1]["actual"] = "aaa"
    c, n, _ = _both(reg, golden, "run_manifest_pass", edit)
    assert c == "rcv1:6cdc6ee97c3ed452c46c6e862ed9c6faa9e9def21efaa5c054aeca44e92006ff"
    assert n == "canon-v1:6cdc6ee97c3ed452c46c6e862ed9c6faa9e9def21efaa5c054aeca44e92006ff"


def test_k2_the_listed_order_of_a_set_is_not_identity(reg, golden):
    """The same record listed in either order is one record (the order is normalised, not kept)."""
    def forward(d):
        d["fixtures"] = [{"id": "seed-a", "content_hash": "sha256:" + "0" * 63 + "9"},
                         {"id": "seed-b", "content_hash": "sha256:" + "0" * 63 + "3"}]

    def backward(d):
        d["fixtures"] = list(reversed([{"id": "seed-a", "content_hash": "sha256:" + "0" * 63 + "9"},
                                       {"id": "seed-b", "content_hash": "sha256:" + "0" * 63 + "3"}]))
    assert _both(reg, golden, "test_spec_ui", forward)[1] == _both(reg, golden, "test_spec_ui", backward)[1]


# -- K3: distinct integrity refusal codes, unknown codes fail closed -----------------------------------------------------------

INTEGRITY = ("INCONCLUSIVE", "ASSERTION_INTEGRITY")


def _reference(golden):
    aset = golden["assertion_sets"]["reference"]
    return aset["hash"], copy.deepcopy(aset["assertions"])


def _load(neutral, pin, stored, programs=None):
    verifier, specstore = deps.neutral_module("verifier"), deps.neutral_module("specstore")
    sets = {pin: stored} if stored is not None and isinstance(pin, str) and neutral.canon.is_contract_ref(pin) else {}
    lineage = verifier.ApprovedLineage([pin] if isinstance(pin, str) and neutral.canon.is_contract_ref(pin) else [])
    return verifier.load_frozen_assertions(verifier_store(specstore, sets), pin, lineage=lineage,
                                           programs=specstore.InMemoryProgramRegistry(programs or {}))


def verifier_store(specstore, sets):
    return specstore.InMemorySpecStore(sets)


def _refused(neutral, fn):
    with pytest.raises(neutral.errors.QAError) as info:
        fn()
    return info.value


@pytest.mark.parametrize("pin", ["sha256:" + "a" * 64, "rcv1:" + "a" * 63, "rcv1:" + "A" * 64, None, "rcv1:xyz",
                                 "canon-v1:" + "a" * 64], ids=["wrong-prefix", "truncated", "uppercase", "not-a-string",
                                                                "garbage", "neutral-spelling"])
def test_k3_a_malformed_pin_is_assertion_pin_malformed(neutral, golden, pin):
    _, stored = _reference(golden)
    exc = _refused(neutral, lambda: _load(neutral, pin, stored))
    assert exc.code == "ASSERTION_PIN_MALFORMED"
    assert (exc.run_outcome, exc.run_reason) == INTEGRITY


def test_k3_a_pin_the_store_does_not_hold_is_assertion_pin_not_found(neutral, golden):
    exc = _refused(neutral, lambda: _load(neutral, "rcv1:" + "0" * 61 + "194", None))
    assert exc.code == "ASSERTION_PIN_NOT_FOUND" and (exc.run_outcome, exc.run_reason) == INTEGRITY


def _script(golden, program_hash=None):
    data = D.case_input(golden["cases"]["assertion_spec_script"])
    if program_hash:
        data["check_program_ref"]["program_hash"] = program_hash
    return data


def _pin_of(neutral, assertion):
    return "rcv1:" + neutral.records.assertion_set_hash([neutral.records.AssertionSpec.from_json(copy.deepcopy(assertion))]
                                                       ).removeprefix("canon-v1:")


def test_k3_an_unregistered_check_program_is_assertion_program_unregistered(neutral, golden):
    script = _script(golden)
    exc = _refused(neutral, lambda: _load(neutral, _pin_of(neutral, script), [script], {}))
    assert exc.code == "ASSERTION_PROGRAM_UNREGISTERED" and (exc.run_outcome, exc.run_reason) == INTEGRITY


def test_k3_a_check_program_registered_under_another_hash_is_assertion_program_mismatch(neutral, golden):
    script = _script(golden)
    ref = script["check_program_ref"]
    other = "sha256:" + "0" * 61 + "3e7"
    exc = _refused(neutral, lambda: _load(neutral, _pin_of(neutral, script), [script], {(ref["id"], ref["version"]): other}))
    assert exc.code == "ASSERTION_PROGRAM_MISMATCH" and (exc.run_outcome, exc.run_reason) == INTEGRITY


def test_k3_content_that_does_not_hash_to_its_pin_keeps_assertion_hash_mismatch(neutral, golden):
    pin, stored = _reference(golden)
    exc = _refused(neutral, lambda: _load(neutral, pin, stored[:1]))
    assert exc.code == "ASSERTION_HASH_MISMATCH" and (exc.run_outcome, exc.run_reason) == INTEGRITY


def test_k3_every_call_after_an_integrity_refusal_is_batch_halted(neutral, golden):
    verifier = deps.neutral_module("verifier")
    latch = verifier.HaltLatch()
    latch.trip(neutral.errors.ERRORS_BY_CODE["ASSERTION_PIN_NOT_FOUND"]("no set"))
    exc = _refused(neutral, latch.check)
    assert exc.code == "BATCH_HALTED" and (exc.run_outcome, exc.run_reason) == INTEGRITY


NEW_CODES = ("ASSERTION_PIN_MALFORMED", "ASSERTION_PIN_NOT_FOUND", "ASSERTION_PROGRAM_MISMATCH", "ASSERTION_PROGRAM_UNREGISTERED",
             "BATCH_HALTED")


@pytest.mark.parametrize("code", NEW_CODES)
def test_k3_each_distinct_code_is_a_typed_integrity_error_of_its_own(neutral, code):
    cls = neutral.errors.ERRORS_BY_CODE.get(code)
    assert cls is not None and cls.code == code
    assert (cls.run_outcome, cls.run_reason) == INTEGRITY
    assert cls is not neutral.errors.AssertionHashMismatch


@pytest.mark.parametrize("code", ["A_CODE_FROM_A_LATER_VERSION", "", None, 7, "assertion_pin_malformed", *NEW_CODES,
                                  "ASSERTION_HASH_MISMATCH"])
def test_k3_an_unknown_or_integrity_code_classifies_fail_closed_as_inconclusive_integrity(neutral, code):
    found = deps.neutral_module("classify").classify_refusal(code)
    assert found is not None and (found[0].value, found[1]) == INTEGRITY
    assert deps.neutral_module("classify").refusal_halts_batch(code) is True


@pytest.mark.parametrize("code", ["SPEC_INVALID", "CHECK_PROGRAM_REF_REQUIRED", "UNKNOWN_FIELD", "DUPLICATE_ENTRY"])
def test_k3_a_known_non_integrity_code_has_no_classification(neutral, code):
    assert deps.neutral_module("classify").classify_refusal(code) is None


def test_k3_the_neutral_integrity_vocabulary_is_the_eleven_contracts_codes(neutral):
    assert [m.value for m in neutral.records.IntegrityRefusalCode] == [
        "ASSERTION_INTEGRITY", "ASSERTION_HASH_MISMATCH", "EXECUTOR_MISMATCH", "EXPECTED_MISMATCH",
        "RECOVERY_PAYLOAD_REJECTED", "COVERAGE_VIOLATION", "ASSERTION_PROGRAM_MISMATCH", "ASSERTION_PROGRAM_UNREGISTERED",
        "ASSERTION_PIN_NOT_FOUND", "ASSERTION_PIN_MALFORMED", "BATCH_HALTED"]


# -- K4: FaultRecovery.reason_code ------------------------------------------------------------------------------------------

def _recovery(**kw):
    base = {"schema_id": "runtime-contracts/qa/fault-recovery", "schema_version": "0.1",
            "detection_ref": "rcv1:" + format(70, "064x"), "attempted": True, "strategy": "SEMANTIC_LOCATOR",
            "result": "NOT_RECOVERED", "postcondition_verified": False, "attempts": 1, "candidates_considered": 3,
            "candidates_rejected_reasons": ["NAME_MISMATCH", "NOT_UNIQUE", "ROLE_MISMATCH"]}
    base.update(kw)
    return base


def test_k4_fault_recovery_declares_reason_code_as_an_optional_identity_field(neutral):
    infos = {i.name: i for i in neutral.records.field_infos(neutral.records.FaultRecovery)}
    assert "reason_code" in infos and not infos["reason_code"].required and not infos["reason_code"].custody


def test_k4_reason_code_enters_the_hash_and_its_absence_is_the_old_hash(neutral):
    fr = neutral.records.FaultRecovery
    assert fr.from_json(_recovery()).canon_hash() == "canon-v1:e4975ca06824fc3865f1a03efa70bd02d8ff91ead07dc047e5aeeb9c2ea3d627"
    with_reason = fr.from_json(_recovery(reason_code="NO_CANDIDATE"))
    assert with_reason.canon_hash() == "canon-v1:b7468751b3c7f76f3173d729d76fc54809bc61e42b282b76040f34455ac73bc9"
    assert with_reason.reason_code == "NO_CANDIDATE" and "reason_code" not in dict(with_reason.extras)


def test_k4_the_value_survives_conversion_as_a_field_not_an_extra(neutral, reg):
    c_cls, n_cls = reg.records["runtime-contracts/qa/fault-recovery"]
    n_obj = n_cls.from_json(_recovery(reason_code="KILL_SWITCH"))
    assert dict(n_obj.extras) == {} and n_obj.reason_code == "KILL_SWITCH"


def test_k4_a_recovered_record_carries_no_reason_code(neutral):
    with pytest.raises(neutral.errors.QAError):
        neutral.records.FaultRecovery.from_json(_recovery(result="RECOVERED", postcondition_verified=True,
                                                          reason_code="NO_CANDIDATE"))


def test_k4_an_unknown_reason_code_is_refused_as_an_unknown_enum_value(neutral):
    with pytest.raises(neutral.errors.UnknownEnumValue):
        neutral.records.FaultRecovery.from_json(_recovery(reason_code="SOMETHING_FROM_A_LATER_VERSION"))


def test_k4_rejection_tokens_may_not_outnumber_candidates_considered(neutral):
    with pytest.raises(neutral.errors.QAError):
        neutral.records.FaultRecovery.from_json(_recovery(reason_code="NO_CANDIDATE", candidates_considered=1))


def test_k4_the_recovery_reason_vocabulary_is_the_eighteen_contracts_members(neutral):
    assert [m.value for m in neutral.records.RecoveryReason] == [
        "NO_UI_TARGET", "NO_ROLE_NAME_ANCHOR", "RECOVERER_ERROR", "CANDIDATE_CAP_EXCEEDED", "ELAPSED_CAP", "KILL_SWITCH",
        "NO_CANDIDATE", "AMBIGUOUS_CANDIDATES", "RECOVERY_DISABLED", "BUDGET_EXHAUSTED", "NOT_PERMITTED", "NOT_RETRYABLE",
        "ALREADY_APPLIED", "RETRY_UNSAFE", "NO_IDEMPOTENCY_OR_POSTCONDITION_GUARD", "INVALID_INPUT",
        "UNKNOWN_SIDE_EFFECT_CLASS", "POSTCONDITION_NOT_VERIFIED"]


# -- A1 to A4: the three reused repository types ----------------------------------------------------------------------------

def test_a1_check_detail_is_wording_and_does_not_enter_the_hash(reg, golden):
    c, n, data = _both(reg, golden, VARIANT["check-detail-wording"].base_case, VARIANT["check-detail-wording"].edit)
    assert c == "rcv1:97868ba9578029b73aa83202ab123f0d939fe6d4372db36299078c9689503e20"
    assert n == "canon-v1:97868ba9578029b73aa83202ab123f0d939fe6d4372db36299078c9689503e20"
    assert _same(c, golden["cases"]["assertion_result_pass"]["hash"])


def test_a1_check_detail_is_kept_on_the_object(reg, golden):
    data, sid = _case(golden, "assertion_result_pass")
    VARIANT["check-detail-wording"].edit(data)
    obj = reg.records[sid][1].from_json(data)
    assert obj.to_json()["check"]["detail"] == "free wording"


def test_a2_check_evidence_refs_are_hashed_sorted_by_value(reg, golden):
    v = VARIANT["check-evidence-refs-unsorted"]
    c, n, data = _both(reg, golden, v.base_case, v.edit)
    assert c == "rcv1:f1fec0a5e4e25010d325e18cf971d7250248b18a6bfc3910309002cd57189e44"
    assert n == "canon-v1:f1fec0a5e4e25010d325e18cf971d7250248b18a6bfc3910309002cd57189e44"


def test_a2_the_listed_order_of_check_evidence_refs_is_kept_on_the_object(reg, golden):
    v = VARIANT["check-evidence-refs-unsorted"]
    data, sid = _case(golden, v.base_case)
    v.edit(data)
    assert reg.records[sid][1].from_json(data).to_json()["check"]["evidence_refs"] == data["check"]["evidence_refs"]


def test_a3_a_secret_reference_without_a_path_hashes_the_path_as_empty(reg, golden):
    v = VARIANT["secret-ref-without-path"]
    c, n, _ = _both(reg, golden, v.base_case, v.edit)
    assert c == "rcv1:ac84d59ea653879c2d95b8c5b68b8de3412cdb6ee348f19c4cf8ff926b127f75"
    assert n == "canon-v1:ac84d59ea653879c2d95b8c5b68b8de3412cdb6ee348f19c4cf8ff926b127f75"


def test_a3_an_explicit_empty_path_is_the_same_secret_reference(neutral):
    r = neutral.records
    assert r.SecretRef(provider="vault", key="k", path="").canon_hash() == r.SecretRef(provider="vault", key="k").canon_hash()


def test_a4_an_evidence_ref_without_modality_and_ref_type_hashes_the_defaults(reg, golden):
    v = VARIANT["evidence-ref-defaults-omitted"]
    c, n, _ = _both(reg, golden, v.base_case, v.edit)
    assert c == "rcv1:4a6691e122c3e1a46c3ebc3f605c51ef536b0d7b7d687b16e7d34ddd159133ec"
    assert n == "canon-v1:4a6691e122c3e1a46c3ebc3f605c51ef536b0d7b7d687b16e7d34ddd159133ec"


def test_a4_the_defaults_are_hashed_but_not_written_back(neutral):
    r = neutral.records
    bare = r.EvidenceRef(ref="x")
    assert bare.canonical_form()["modality"] == "text" and bare.canonical_form()["ref_type"] == "evidence"
    assert "modality" not in bare.to_json() and "ref_type" not in bare.to_json()


# -- A5: ActionTimeout.recoverable --------------------------------------------------------------------------------------------

def test_a5_action_timeout_is_recoverable_on_both_sides(contracts, neutral):
    c = contracts.ADAPTER_ERRORS[contracts.ResultCode("ACTION_TIMEOUT")]("m")
    n = neutral.errors.ActionTimeout("m")
    expected = ("ACTION", True, True, "BENIGN_DRIFT_OR_ENVIRONMENT")
    assert (c.category.value, c.retryable, c.recoverable, c.class_hint.value) == expected
    assert (n.category.value, n.retryable, n.recoverable, n.class_hint.value) == expected
