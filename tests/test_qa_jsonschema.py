# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The strict schema validator: every supported keyword, and a refusal of anything it does not support."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("qa_jsonschema", ROOT / "tools" / "qa_jsonschema.py")
qj = importlib.util.module_from_spec(SPEC)
sys.modules["qa_jsonschema"] = qj
SPEC.loader.exec_module(qj)


def bad(instance, schema):
    return qj.validate(instance, schema)


@pytest.mark.parametrize("schema,good,wrong", [
    ({"type": "string"}, "a", 1),
    ({"type": "integer"}, 3, True),                 # a boolean is not an integer
    ({"type": "integer"}, 3, 3.5),
    ({"type": "boolean"}, False, 0),
    ({"type": ["string", "null"]}, None, 5),
    ({"type": "array"}, [], {}),
    ({"type": "object"}, {}, []),
    ({"const": 1}, 1, True),                         # True is not 1
    ({"const": False}, False, 0),
    ({"enum": ["a", 2]}, 2, "b"),
    ({"enum": [1]}, 1, True),
    ({"minLength": 2}, "ab", "a"),
    ({"maxLength": 2}, "ab", "abc"),
    ({"pattern": "^a+$"}, "aaa", "b"),
    ({"pattern": "b"}, "abc", "xyz"),                # unanchored search, as in JSON Schema
    ({"minimum": 1}, 1, 0),
    ({"maximum": 1}, 1, 2),
    ({"minItems": 1}, [1], []),
    ({"maxItems": 1}, [1], [1, 2]),
    ({"uniqueItems": True}, [1, 2], [1, 1]),
    ({"uniqueItems": True}, [1, True], [{"a": 1}, {"a": 1}]),
    ({"items": {"type": "integer"}}, [1, 2], [1, "x"]),
    ({"required": ["a"]}, {"a": 1}, {}),
    ({"properties": {"a": {"type": "integer"}}}, {"a": 1, "z": "free"}, {"a": "x"}),
    ({"properties": {"a": {}}, "additionalProperties": False}, {"a": 1}, {"a": 1, "b": 2}),
    ({"additionalProperties": {"type": "integer"}}, {"a": 1}, {"a": "x"}),
    ({"allOf": [{"type": "integer"}, {"minimum": 2}]}, 3, 1),
    ({"anyOf": [{"type": "integer"}, {"type": "null"}]}, None, "x"),
    ({"if": {"type": "integer"}, "then": {"minimum": 5}}, 7, 3),
    ({"if": {"type": "integer"}, "else": {"minLength": 3}}, 3, "ab"),
    ({"$defs": {"n": {"type": "integer"}}, "properties": {"a": {"$ref": "#/$defs/n"}}}, {"a": 1}, {"a": "x"}),
    (False, None, 1),
])
def test_each_supported_rule_accepts_and_refuses(schema, good, wrong):
    if schema is False:
        assert bad(wrong, schema)
        return
    assert bad(good, schema) == []
    assert bad(wrong, schema), f"{schema} accepted {wrong!r}"


def test_a_condition_whose_if_fails_applies_no_then():
    schema = {"if": {"properties": {"k": {"const": "x"}}, "required": ["k"]}, "then": {"required": ["extra"]}}
    assert bad({"k": "y"}, schema) == []
    assert bad({"k": "x"}, schema) == ["/: missing required property 'extra'"]


def test_violations_name_the_json_pointer():
    schema = {"properties": {"a": {"items": {"properties": {"b": {"type": "integer"}}}}}}
    assert bad({"a": [{"b": 1}, {"b": "x"}]}, schema) == ["/a/1/b: expected integer, got str"]


@pytest.mark.parametrize("keyword", ["format", "oneOf", "not", "dependentRequired", "patternProperties", "minProperties", "contains", "prefixItems",
                                      "multipleOf", "exclusiveMinimum", "$dynamicRef", "unevaluatedProperties"])
def test_an_unsupported_keyword_is_an_error_never_a_silent_pass(keyword):
    with pytest.raises(qj.SchemaError):
        bad("x", {keyword: 1})


def test_an_unsupported_keyword_is_found_even_in_a_subschema_no_instance_reaches():
    schema = {"properties": {"never": {"oneOf": []}}, "$defs": {"d": {"format": "date"}}}
    with pytest.raises(qj.SchemaError):
        bad({}, schema)


def test_a_ref_that_does_not_resolve_or_is_not_local_is_an_error():
    for ref in ("#/$defs/missing", "http://example.invalid/x", "#/properties/a"):
        with pytest.raises(qj.SchemaError):
            bad(1, {"$ref": ref})


def test_annotations_are_accepted_and_ignored():
    schema = {"$schema": "x", "$id": "y", "title": "t", "description": "d", "$comment": "c", "examples": [1], "default": 1, "type": "integer"}
    assert bad(1, schema) == []


def test_mutations_cover_deletions_and_type_changes_and_are_independent_copies():
    doc = {"a": {"b": [1, 2]}, "c": "x"}
    found = list(qj.mutations(doc))
    labels = [d for d, _ in found]
    assert "delete /a/b/0" in labels and "delete /c" in labels and "replace /a/b by string" in labels
    assert doc == {"a": {"b": [1, 2]}, "c": "x"}
    assert all(m != doc for _, m in found)


def test_the_mutation_limit_is_respected():
    assert len(list(qj.mutations({"a": list(range(50))}, limit=7))) == 7


def test_additional_properties_false_names_the_unexpected_property():
    assert bad({"a": 1, "b": 2}, {"properties": {"a": {}}, "additionalProperties": False}) == ["/: unexpected property 'b'"]


def test_a_broken_ref_in_a_subschema_no_instance_reaches_is_an_error():
    with pytest.raises(qj.SchemaError):
        bad({}, {"properties": {"x": {"$ref": "#/$defs/missing"}}})
    with pytest.raises(qj.SchemaError):
        qj.check_schema({"$defs": {"a": {"$ref": "#/$defs/nope"}}})
