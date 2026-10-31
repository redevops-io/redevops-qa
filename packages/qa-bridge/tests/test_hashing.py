# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import pytest

from redevops_qa_bridge import hashing
from redevops_qa_bridge.errors import HashFormatError

HEX = "ab" * 32


def test_prefix_mapping_both_ways():
    assert hashing.to_contracts_hash("canon-v1:" + HEX) == "rcv1:" + HEX
    assert hashing.to_neutral_hash("rcv1:" + HEX) == "canon-v1:" + HEX


@pytest.mark.parametrize("bad", ["rcv1:" + HEX, "canon-v1:" + HEX[:-1], "canon-v1:" + HEX.upper(), "", "sha256:" + HEX,
                                 "canon-v1:" + HEX + "0", 7, None])
def test_to_contracts_refuses_anything_but_a_full_neutral_hash(bad):
    with pytest.raises(HashFormatError) as info:
        hashing.to_contracts_hash(bad)
    assert info.value.code == "HASH_FORMAT"


@pytest.mark.parametrize("bad", ["canon-v1:" + HEX, "rcv1:" + HEX[:-1], "rcv1:" + HEX.upper(), "rcv1:", 3])
def test_to_neutral_refuses_anything_but_a_full_contracts_hash(bad):
    with pytest.raises(HashFormatError):
        hashing.to_neutral_hash(bad)


def test_same_digest_ignores_the_prefix_only():
    assert hashing.same_digest("canon-v1:" + HEX, "rcv1:" + HEX)
    assert not hashing.same_digest("canon-v1:" + HEX, "rcv1:" + "cd" * 32)
    with pytest.raises(HashFormatError):
        hashing.same_digest("canon-v1:" + HEX, "rcv1:short")


def test_round_trip_is_identity():
    h = "canon-v1:" + HEX
    assert hashing.to_neutral_hash(hashing.to_contracts_hash(h)) == h
