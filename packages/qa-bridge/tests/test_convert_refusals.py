# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""What the bridge refuses, and the invariant it never breaks: a converted object carries the digest of its source."""
import copy
import enum

import pytest

from redevops_qa_bridge import convert, hashing
from redevops_qa_bridge.convert import assert_data_only
from redevops_qa_bridge.errors import (BridgeError, ConversionRefused, DataOnlyViolation, HashDisagreement,
                                       UnknownSchema, UnknownType)


class _Str(str):
    pass


class _Color(enum.Enum):
    RED = "red"


@pytest.mark.parametrize("value", [1.5, 1.0, _Str("x"), _Color.RED, {1: 2}, {"a": {1, 2}}, [object()], b"bytes",
                                   {"a": float("nan")}, (1, 2.0)])
def test_assert_data_only_refuses_non_json_data(value):
    with pytest.raises(DataOnlyViolation) as info:
        assert_data_only(value)
    assert info.value.code == "DATA_ONLY_VIOLATION"


@pytest.mark.parametrize("value", [None, True, 7, "s", [1, "a", None], (1, 2), {"a": [1, {"b": None}]}])
def test_assert_data_only_accepts_plain_data(value):
    assert_data_only(value)


def test_assert_data_only_has_a_depth_bound():
    deep = []
    for _ in range(80):
        deep = [deep]
    with pytest.raises(DataOnlyViolation):
        assert_data_only(deep)


def test_data_functions_refuse_instances(gi, contracts):
    spec = contracts.AssertionSpec.from_json(gi("assertion_spec_playwright"))
    with pytest.raises(DataOnlyViolation):
        convert.contracts_data_to_neutral(spec)        # an object, not its data
    with pytest.raises(DataOnlyViolation):
        convert.neutral_data_to_contracts({"schema_id": "runtime-contracts/qa/checkpoint", "x": _Str("y")})


def test_unknown_schema_and_type_are_refused(gi):
    with pytest.raises(UnknownSchema):
        convert.contracts_data_to_neutral({"schema_id": "runtime-contracts/qa/nope"})
    with pytest.raises(UnknownSchema):
        convert.contracts_data_to_neutral({"no": "schema"})
    with pytest.raises(UnknownType):
        convert.contracts_data_to_neutral({"x": 1}, type_name="NoSuchType")


def test_a_foreign_object_is_refused(neutral):
    with pytest.raises(UnknownType):
        convert.from_contracts(object())
    with pytest.raises(UnknownType):
        convert.to_contracts(object())


def test_a_stored_hash_that_does_not_match_is_refused_by_both_sides(gi):
    data = gi("checkpoint")
    data["content_hash"] = "rcv1:" + "0" * 64
    c_cls = convert.registry().records["runtime-contracts/qa/checkpoint"][0]
    with pytest.raises(Exception) as info:
        c_cls.from_json(data)                          # contracts itself refuses first
    assert info.value.code == "HASH_MISMATCH"
    neutral_data = convert.contracts_data_to_neutral(c_cls.from_json(gi("checkpoint")).to_json())
    neutral_data["content_hash"] = "canon-v1:" + "0" * 64
    contracts_data = convert.neutral_data_to_contracts(neutral_data)
    with pytest.raises(Exception) as info2:
        c_cls.from_json(contracts_data)
    assert info2.value.code == "HASH_MISMATCH"


def test_extras_the_contracts_side_does_not_know_are_refused(gi, neutral):
    n_cls = convert.registry().records["runtime-contracts/qa/checkpoint"][1]
    obj = n_cls.from_json({
        "schema_id": "runtime-contracts/qa/checkpoint", "schema_version": "0.1", "checkpoint_id": "cp-1",
        "run_id": "run-1", "step_index": 0, "state_hash": "rcv1:" + "1" * 64, "future_field": "x"})
    assert dict(obj.extras) == {"future_field": "x"}
    with pytest.raises(ConversionRefused) as info:
        convert.to_contracts(obj)
    assert info.value.details["cause_code"] == "UNKNOWN_FIELD"


# -- verify on convert: known places where the two implementations disagree --------------------------------------------

def _check_detail(d):
    d["check"]["detail"] = "free wording"


def _unsorted_evidence_refs(d):
    d["check"]["evidence_refs"] = ["zz@1#sha256:" + "0" * 63 + "7", "aa@1#sha256:" + "0" * 63 + "6"]


def _two_fixtures(d):
    d["fixtures"] = [{"id": "a-fix", "content_hash": "rcv1:" + "f" * 64}, {"id": "z-fix", "content_hash": "rcv1:" + "0" * 64}]


def _secret_without_path(d):
    a = d["steps"][0]["action"]
    a.pop("value", None)
    a["kind"] = "fill"
    a["secret_ref"] = {"provider": "vault", "key": "k"}


DIVERGENT = [("assertion_result_pass", _check_detail), ("assertion_result_pass", _unsorted_evidence_refs),
             ("test_spec_ui", _two_fixtures), ("test_spec_ui", _secret_without_path)]


@pytest.mark.parametrize("case,mutate", DIVERGENT, ids=["check-detail", "evidence-ref-order", "fixture-order", "secret-path"])
@pytest.mark.parametrize("side", ["contracts", "neutral"])
def test_conversion_never_returns_an_object_whose_hash_differs(case, mutate, side, golden, gi):
    """For payloads on which the two implementations may disagree, the bridge either converts with equal digests or
    refuses with HashDisagreement. It never returns a converted object carrying a different digest."""
    reg = convert.registry()
    sid = golden["cases"][case]["schema_id"]
    data = copy.deepcopy(gi(case))
    mutate(data)
    c_cls, n_cls = reg.records[sid]
    try:
        if side == "contracts":
            source = c_cls.from_json(data)
            result = convert.from_contracts(source)
            assert hashing.digest_of(convert.neutral_digest(result)) == hashing.digest_of(convert.contracts_digest(source))
        else:
            source = n_cls.from_json(data)
            result = convert.to_contracts(source)
            assert hashing.digest_of(convert.contracts_digest(result)) == hashing.digest_of(convert.neutral_digest(source))
    except HashDisagreement as exc:
        assert exc.code == "HASH_DISAGREEMENT"
    except BridgeError as exc:      # the destination may also refuse the shape outright, with its own stable code
        assert exc.code in {"CONVERSION_REFUSED", "UNKNOWN_SCHEMA"}


def test_a_broken_prefix_mapping_cannot_pass_unnoticed(gi, monkeypatch):
    """Verify-on-convert catches a bridge whose hash mapping was broken: the conversion refuses instead of returning."""
    c_cls = convert.registry().records["runtime-contracts/qa/checkpoint"][0]
    original = c_cls.from_json(gi("checkpoint"))
    monkeypatch.setattr(hashing, "to_neutral_hash", lambda h: "canon-v1:" + "0" * 64)
    with pytest.raises(BridgeError):
        convert.from_contracts(original)
