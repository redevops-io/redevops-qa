# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The validator: every supported keyword, refusal of anything unsupported, the informational extension, and the checked-in schemas."""
import json
import re
from pathlib import Path

import pytest

from qa_evidence import constants
from qa_evidence.minischema import KEYWORDS, SchemaError, Validator, check_schema
from qa_evidence.schemas import FILES, SCHEMA_DIR, load_schema

STR = {"type": "string"}


def issues(schema, value):
    return {i.code for i in Validator(schema).validate(value)[0]}


@pytest.mark.parametrize("schema,good,bad,code", [
    ({"type": "string"}, "a", 1, "TYPE"), ({"type": "integer"}, 3, True, "TYPE"), ({"type": "integer"}, 3, "3", "TYPE"),
    ({"type": ["integer", "null"]}, None, "x", "TYPE"), ({"type": "boolean"}, False, 0, "TYPE"), ({"type": "array"}, [], {}, "TYPE"),
    ({"type": "object", "additionalProperties": False}, {}, [], "TYPE"),
    ({"const": "a"}, "a", "b", "CONST"), ({"const": False}, False, 0, "CONST"), ({"const": 1}, 1, True, "CONST"),
    ({"enum": ["a", None]}, None, "b", "ENUM"), ({"enum": [1]}, 1, True, "ENUM"),
    ({"type": "string", "minLength": 2}, "ab", "a", "LENGTH"), ({"type": "string", "maxLength": 2}, "ab", "abc", "LENGTH"),
    ({"type": "string", "pattern": "^a+$"}, "aa", "ab", "PATTERN"),
    ({"type": "integer", "minimum": 1}, 1, 0, "RANGE"), ({"type": "integer", "maximum": 1}, 1, 2, "RANGE"),
    ({"type": "array", "minItems": 1}, [1], [], "ITEMS"), ({"type": "array", "maxItems": 1}, [1], [1, 2], "ITEMS"),
    ({"type": "array", "uniqueItems": True}, [1, 2], [1, 1], "UNIQUE"), ({"type": "array", "items": STR}, ["a"], [1], "TYPE"),
    ({"type": "object", "properties": {"a": STR}, "required": ["a"], "additionalProperties": False}, {"a": "x"}, {}, "REQUIRED"),
    ({"type": "object", "properties": {"a": STR}, "additionalProperties": False}, {"a": "x"}, {"a": "x", "b": 1}, "UNKNOWN_FIELD"),
    ({"type": "object", "additionalProperties": STR}, {"k": "v"}, {"k": 1}, "TYPE"),
    ({"type": "object", "additionalProperties": STR, "propertyNames": {"pattern": "^k"}}, {"k1": "v"}, {"x": "v"}, "PATTERN"),
    ({"type": "object", "additionalProperties": STR, "propertyNames": {"maxLength": 2}}, {"k": "v"}, {"kkk": "v"}, "LENGTH"),
    ({"$ref": "#/$defs/s", "$defs": {"s": {"type": "string"}}}, "a", 1, "TYPE"),
])
def test_each_keyword_accepts_good_values_and_rejects_bad_ones(schema, good, bad, code):
    assert issues(schema, good) == set()
    assert code in issues(schema, bad)


@pytest.mark.parametrize("keyword", ["allOf", "anyOf", "oneOf", "not", "if", "patternProperties", "format", "multipleOf", "dependentRequired",
                                     "contains", "$dynamicRef", "unevaluatedProperties", "exclusiveMinimum"])
def test_a_keyword_the_validator_does_not_implement_makes_the_schema_unusable(keyword):
    with pytest.raises(SchemaError):
        Validator({"type": "string", keyword: []})
    with pytest.raises(SchemaError):
        Validator({"type": "object", "additionalProperties": False, "properties": {"a": {"type": "string", keyword: []}}})


@pytest.mark.parametrize("schema", [
    {"type": "object"}, {"type": ["object", "null"]}, {"type": "object", "properties": {}}, {"type": "object", "additionalProperties": True},
    {"type": "object", "properties": {}, "additionalProperties": True}, {"type": "object", "x-qa-informational": True, "properties": {}},
    {"type": "object", "x-qa-informational": True, "additionalProperties": False, "properties": {}}, {"$ref": "#/$defs/missing"},
    {"$ref": "http://example.invalid/x"}, {"type": "array", "items": {"type": "object"}}, {"type": "string", "pattern": "("},
    {"type": "object", "additionalProperties": False, "propertyNames": {"format": "x"}}, {"type": "object", "additionalProperties": 3},
])
def test_an_object_schema_must_say_what_happens_to_unknown_properties_and_refs_must_resolve(schema):
    with pytest.raises((SchemaError, re.error)):
        Validator(schema)


INFO = {"type": "object", "x-qa-informational": True, "additionalProperties": True, "properties": {"os": STR}}


def test_informational_objects_tolerate_and_list_short_scalar_extras():
    iss, info = Validator(INFO).validate({"os": "linux", "kernel": "6", "n": 3, "f": True, "z": None})
    assert iss == [] and sorted(info) == ["/f", "/kernel", "/n", "/z"]


@pytest.mark.parametrize("extra", [{"Bad": "x"}, {"k": {"a": 1}}, {"k": [1]}, {"k": "x" * 1025}, {"9k": "x"}, {"k": 1.5}])
def test_informational_extras_of_the_wrong_form_are_refused(extra):
    assert "INFORMATIONAL_FORM" in issues(INFO, extra)


def test_declared_properties_of_an_informational_object_are_still_validated():
    assert "TYPE" in issues(INFO, {"os": 3})


def test_pointers_escape_slashes_and_tildes():
    iss, _ = Validator({"type": "object", "properties": {}, "additionalProperties": False}).validate({"a/b~c": 1})
    assert iss[0].pointer == "/a~1b~0c"


def test_a_very_deep_value_is_refused_not_crashed():
    deep = []
    cursor = deep
    for _ in range(200):
        cursor.append([])
        cursor = cursor[0]
    nested = {"$defs": {"n": {"type": "array", "items": {"$ref": "#/$defs/n"}}}, "type": "array", "items": {"$ref": "#/$defs/n"}}
    assert "TOO_DEEP" in issues(nested, deep)


# ---- the checked-in schemas -----------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("schema_id", sorted(FILES))
def test_the_checked_in_schemas_use_only_supported_keywords_and_close_every_object(schema_id):
    schema = load_schema(schema_id)
    check_schema(schema)

    def walk(node, where):
        if isinstance(node, dict):
            if node.get("type") == "object" or (isinstance(node.get("type"), list) and "object" in node["type"]):
                ap = node.get("additionalProperties")
                assert ap is False or isinstance(ap, dict) or node.get("x-qa-informational") is True, where
            for k, v in node.items():
                walk(v, f"{where}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{where}/{i}")
    walk(schema, schema_id)


def test_the_only_open_objects_are_the_documented_informational_ones():
    opened = []

    def walk(node, where):
        if isinstance(node, dict):
            if node.get("x-qa-informational") is True:
                opened.append(where)
            for k, v in node.items():
                walk(v, f"{where}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{where}/{i}")
    for sid in sorted(FILES):
        walk(load_schema(sid), sid.split("/")[1])
    names = sorted({o.split("/")[-1] for o in opened if "$defs" in o} | {o.split("/")[-1] for o in opened if "$defs" not in o})
    assert names == ["environment", "extensions", "producer"]


def test_the_schema_enums_match_the_constants():
    man = load_schema(constants.MANIFEST_SCHEMA)
    rep = load_schema(constants.REPORT_SCHEMA)
    assert tuple(man["properties"]["files"]["items"]["properties"]["role"]["enum"]) == constants.ROLES
    assert tuple(man["properties"]["anchor"]["properties"]["accepted_types"]["items"]["enum"]) == constants.ANCHOR_TYPES
    assert tuple(rep["properties"]["lanes"]["items"]["properties"]["native"]["properties"]["status"]["enum"]) == constants.LANE_STATUSES
    res = rep["properties"]["accounting"]["properties"]["results"]["items"]["properties"]
    assert tuple(res["verdict"]["properties"]["state"]["enum"]) == constants.VERDICT_STATES
    assert tuple(rep["properties"]["verdict"]["properties"]["outcome"]["enum"]) == constants.OUTCOMES
    assert set(constants.LANE_STATUSES).isdisjoint(constants.VERDICT_STATES) and all(s.startswith("NATIVE_") for s in constants.LANE_STATUSES)
    assert res["native_status"]["enum"][:-1] == list(constants.LANE_STATUSES) and res["native_status"]["enum"][-1] is None
    for doc in (man, rep):
        assert doc["$defs"]["digest"]["pattern"] == constants.DIGEST_RE.pattern
        assert doc["$defs"]["id"]["pattern"] == constants.ID_RE.pattern
        assert doc["properties"]["schema_version"] == {"$ref": "#/$defs/schema_version"}


def test_the_schema_files_are_ordinary_json_with_stable_ids():
    for sid, name in FILES.items():
        text = (SCHEMA_DIR / name).read_text(encoding="utf-8")
        doc = json.loads(text)
        assert doc["$schema"] == "https://json-schema.org/draft/2020-12/schema" and doc["$id"] == sid + "/1" and doc["properties"]["schema"]["const"] == sid
        assert text.endswith("\n") and "\t" not in text


def test_every_schema_file_in_the_directory_is_known():
    assert sorted(p.name for p in Path(SCHEMA_DIR).glob("*.json")) == sorted(FILES.values())


def test_keywords_are_the_documented_set():
    assert KEYWORDS == frozenset({"type", "enum", "const", "required", "properties", "additionalProperties", "propertyNames", "items", "minItems",
                                  "maxItems", "uniqueItems", "minLength", "maxLength", "pattern", "minimum", "maximum", "$ref", "x-qa-informational"})
