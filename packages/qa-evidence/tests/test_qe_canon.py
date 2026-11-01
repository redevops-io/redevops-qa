# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Strict JSON loading, canonical bytes, digests and text sanitising."""
import json

import pytest

from qa_evidence.canon import CanonError, digest_of, dumps_canonical, is_canonical, loads_strict, safe_text, sha256_bytes
from qa_evidence.constants import Limits


@pytest.mark.parametrize("data,code", [
    (b'{"a": 1, "a": 2}', "DUPLICATE_KEY"), (b'{"a": 1.5}', "FLOAT_REFUSED"), (b'{"a": 1e3}', "FLOAT_REFUSED"), (b'{"a": NaN}', "CONSTANT_REFUSED"),
    (b'{"a": Infinity}', "CONSTANT_REFUSED"), (b'{"a": -Infinity}', "CONSTANT_REFUSED"), (b"\xef\xbb\xbf{}", "BOM_REFUSED"), (b"\xff\xfe", "NOT_UTF8"),
    (b"{", "NOT_JSON"), (b"", "NOT_JSON"), (b'{"a": "\\ud800"}', "BAD_UNICODE"), (b'{"\\ud800": 1}', "BAD_UNICODE"),
    (b"[" * 50 + b"]" * 50, "TOO_DEEP"), (b"[" * 5000 + b"]" * 5000, "TOO_DEEP"),
])
def test_what_cannot_be_read_strictly_is_refused_with_a_stable_code(data, code):
    with pytest.raises(CanonError) as exc:
        loads_strict(data)
    assert exc.value.code == code


def test_caps_on_size_strings_and_item_counts():
    with pytest.raises(CanonError) as exc:
        loads_strict(b'{"a": "' + b"x" * 100 + b'"}', Limits(max_json_bytes=50))
    assert exc.value.code == "JSON_TOO_LARGE"
    with pytest.raises(CanonError) as exc:
        loads_strict(b'{"a": "' + b"x" * 100 + b'"}', Limits(max_string_chars=50))
    assert exc.value.code == "STRING_TOO_LONG"
    with pytest.raises(CanonError) as exc:
        loads_strict(b"[1,2,3,4]", Limits(max_items=3))
    assert exc.value.code == "TOO_MANY_ITEMS"


def test_canonical_form_is_one_byte_sequence_per_document():
    doc = {"b": [1, {"z": None, "a": True}], "a": "caf\u00e9 \U0001f600"}
    data = dumps_canonical(doc)
    assert data.endswith(b"\n") and data.isascii() and b"\\u00e9" in data and b"\\ud83d\\ude00" in data
    assert data.index(b'"a"') < data.index(b'"b"')
    assert loads_strict(data) == doc and is_canonical(data, doc)
    assert not is_canonical(json.dumps(doc).encode(), doc)
    assert dumps_canonical(loads_strict(data)) == data


def test_floats_and_nan_cannot_be_written():
    with pytest.raises(ValueError):
        dumps_canonical({"a": float("nan")})


def test_digests_are_sha256_of_the_exact_bytes():
    assert sha256_bytes(b"abc") == "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert digest_of({"a": 1}) == sha256_bytes(dumps_canonical({"a": 1}))


@pytest.mark.parametrize("hostile,bad", [("a\x1b[2Jb", "\x1b"), ("a\u202eb", "\u202e"), ("a\u200bb", "\u200b"), ("a\x00b", "\x00"), ("a\nb", "\n"),
                                         ("a\u2028b", "\u2028"), ("a\u0085b", "\u0085"), ("a\ud800b", "\ud800"), ("a\U000e0001b", "\U000e0001")])
def test_safe_text_leaves_no_control_or_format_character(hostile, bad):
    out = safe_text(hostile)
    assert bad not in out and out.isprintable() and out.startswith("a")


def test_safe_text_keeps_ordinary_text_and_bounds_length():
    assert safe_text("caf\u00e9 ok") == "caf\u00e9 ok"
    assert safe_text("x" * 50, limit=10) == "x" * 10 + "..."
    assert safe_text({"k": 1}) == '{"k": 1}' and safe_text(None) == "null"
