# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import pytest

from redevops_qa_bridge import errormap
from redevops_qa_bridge.errors import BlobStoreFault, ErrorCodeUnmapped


def test_every_neutral_adapter_error_maps_to_the_contracts_class_with_the_same_code(contracts, neutral):
    assert set(neutral.errors.ADAPTER_ERRORS) == {rc.value for rc in contracts.ADAPTER_ERRORS}
    for code, n_cls in neutral.errors.ADAPTER_ERRORS.items():
        mapped = errormap.contracts_error_for_neutral(n_cls("boom"))
        assert type(mapped) is contracts.ADAPTER_ERRORS[contracts.ResultCode(code)]
        assert mapped.code.value == code
        back = errormap.neutral_error_for_contracts(mapped)
        assert type(back) is n_cls and back.code == code


def test_a_crossed_error_takes_its_attributes_from_the_destination_class_never_from_the_source(contracts, neutral):
    """Only the code and message cross. Whatever retry/recovery attributes the destination class declares are the ones
    callers see (the conformance suite, not the bridge, decides whether the two sides declare the same ones)."""
    for code, n_cls in neutral.errors.ADAPTER_ERRORS.items():
        c_cls = contracts.ADAPTER_ERRORS[contracts.ResultCode(code)]
        crossed = errormap.contracts_error_for_neutral(n_cls("m"))
        own = c_cls("m")
        assert (crossed.category, crossed.retryable, crossed.recoverable, crossed.class_hint) == \
               (own.category, own.retryable, own.recoverable, own.class_hint), code
        back = errormap.neutral_error_for_contracts(c_cls("m"))
        assert (back.category, back.retryable, back.recoverable, back.class_hint) == \
               (n_cls.category, n_cls.retryable, n_cls.recoverable, n_cls.class_hint), code


@pytest.mark.parametrize("code", ["ASSERTION_HASH_MISMATCH", "EXECUTOR_MISMATCH", "EXPECTED_MISMATCH",
                                  "RECOVERY_PAYLOAD_REJECTED", "COVERAGE_VIOLATION"])
def test_integrity_errors_cross_as_integrity_errors_on_both_sides(contracts, neutral, code):
    n_exc = neutral.errors.ERRORS_BY_CODE[code]("x")
    c_exc = errormap.contracts_error_for_neutral(n_exc)
    assert isinstance(c_exc, contracts.AssertionIntegrityError) and c_exc.code == code
    assert (c_exc.run_outcome, c_exc.run_reason) == (n_exc.run_outcome, n_exc.run_reason) == ("INCONCLUSIVE", "ASSERTION_INTEGRITY")
    back = errormap.neutral_error_for_contracts(c_exc)
    assert type(back) is type(n_exc)


@pytest.mark.parametrize("code", ["SPEC_INVALID", "HASH_MISMATCH", "UNKNOWN_FIELD", "SCHEMA_VERSION_UNSUPPORTED",
                                  "CHECK_PROGRAM_REF_REQUIRED", "FAULT_BINDING_MISMATCH", "UNSUPPORTED_COVERAGE_CONTRACT",
                                  "UNKNOWN_ENUM_VALUE"])
def test_shared_codes_keep_their_spelling(contracts, neutral, code):
    n_exc = neutral.errors.ERRORS_BY_CODE[code]("x")
    c_exc = errormap.contracts_error_for_neutral(n_exc)
    assert c_exc.code == code
    assert errormap.neutral_error_for_contracts(c_exc).code == code


def test_a_neutral_only_code_crosses_as_a_contracts_contract_error_with_that_code(contracts, neutral):
    c_exc = errormap.contracts_error_for_neutral(neutral.errors.CanonicalizationRefused("float"))
    assert isinstance(c_exc, contracts.QAContractError) and c_exc.code == "CANON_REFUSED"


def test_contracts_only_structural_codes_degrade_to_spec_invalid_not_to_a_guess(contracts, neutral):
    for code in ("INVALID_FIELD", "MISSING_FIELD", "DUPLICATE_ENTRY", "FLOAT_REFUSED", "SCHEMA_MISMATCH", "PLAN_INVALID",
                 "RECORD_INCONSISTENT"):
        n_exc = errormap.neutral_error_for_contracts(contracts.QAContractError(code, "m"))
        assert n_exc.code == "SPEC_INVALID" and n_exc.details["contracts_code"] == code


def test_the_generic_integrity_code_degrades_to_an_integrity_class(contracts, neutral):
    n_exc = errormap.neutral_error_for_contracts(contracts.AssertionIntegrityError("ASSERTION_INTEGRITY", "m"))
    assert n_exc.run_outcome == "INCONCLUSIVE" and n_exc.run_reason == "ASSERTION_INTEGRITY"


def test_blob_errors_have_no_neutral_class_and_cross_as_a_bridge_fault(contracts):
    fault = errormap.neutral_error_for_contracts(contracts.BlobNotFound("gone"))
    assert isinstance(fault, BlobStoreFault) and fault.code == "BLOB_NOT_FOUND"


def test_an_exception_without_a_code_is_not_mapped(contracts):
    class NoCode(contracts.QAContractError):
        def __init__(self):
            ValueError.__init__(self, "x")
            self.code = None
    with pytest.raises(ErrorCodeUnmapped):
        errormap.neutral_error_for_contracts(NoCode())


def test_context_managers_leave_foreign_exceptions_alone(neutral):
    with pytest.raises(KeyError):
        with errormap.contracts_to_neutral():
            raise KeyError("not a qa error")
    with pytest.raises(ValueError):
        with errormap.neutral_to_contracts():
            raise ValueError("not a qa error")


def test_context_managers_translate(contracts, neutral):
    with pytest.raises(neutral.errors.LocatorNotFound):
        with errormap.contracts_to_neutral():
            raise contracts.LocatorNotFound("x")
    with pytest.raises(contracts.LocatorNotFound):
        with errormap.neutral_to_contracts():
            raise neutral.errors.LocatorNotFound("x")
