# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A small, strict JSON Schema validator (standard library only) for the checked-in schemas of this package.

It supports only the keywords below and FAILS when a schema uses any other keyword, so a rule can never be silently ignored:
``type`` (name or list), ``enum``, ``const``, ``required``, ``properties``, ``additionalProperties`` (``false`` or a schema),
``propertyNames`` (``pattern``, ``maxLength``), ``items``, ``minItems``, ``maxItems``, ``uniqueItems``, ``minLength``, ``maxLength``,
``pattern`` (``re.search``), ``minimum``, ``maximum`` and a local ``$ref`` of the form ``#/$defs/<name>``. Annotation keywords
(``$schema``, ``$id``, ``$defs``, ``title``, ``description``, ``$comment``) are accepted.

One extension, ``x-qa-informational: true`` on an object schema, marks that object as INFORMATIONAL: properties it does not declare are
tolerated and reported (as JSON pointers) instead of refused, provided their names are short lowercase identifiers and their values are
scalars. Every other object refuses unknown properties. Standard validators ignore the extension keyword, and treat the object as open.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, NamedTuple

ANNOTATIONS = frozenset({"$schema", "$id", "$defs", "title", "description", "$comment"})
KEYWORDS = frozenset({"type", "enum", "const", "required", "properties", "additionalProperties", "propertyNames", "items", "minItems", "maxItems",
                      "uniqueItems", "minLength", "maxLength", "pattern", "minimum", "maximum", "$ref", "x-qa-informational"})
INFO_KEY_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
INFO_VALUE_MAX = 1024
MAX_REF_DEPTH = 32


class SchemaError(ValueError):
    """The schema uses something this validator does not support."""


class SchemaIssue(NamedTuple):
    code: str
    pointer: str
    message: str


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def check_schema(schema: Any, root: Any = None, where: str = "#") -> None:
    """Fail on any keyword this validator does not implement (recursively), on a dangling ``$ref`` and on a malformed keyword value."""
    root = schema if root is None else root
    if not isinstance(schema, dict):
        raise SchemaError(f"{where}: a schema must be an object")
    for key in schema:
        if key not in KEYWORDS and key not in ANNOTATIONS:
            raise SchemaError(f"{where}: unsupported keyword {key!r}")
    ref = schema.get("$ref")
    if ref is not None:
        if not isinstance(ref, str) or not ref.startswith("#/$defs/") or ref[8:] not in root.get("$defs", {}):
            raise SchemaError(f"{where}: unresolvable $ref {ref!r}")
    for name, sub in schema.get("$defs", {}).items():
        check_schema(sub, root, f"{where}/$defs/{name}")
    for name, sub in schema.get("properties", {}).items():
        check_schema(sub, root, f"{where}/properties/{name}")
    if isinstance(schema.get("additionalProperties"), dict):
        check_schema(schema["additionalProperties"], root, f"{where}/additionalProperties")
    elif "additionalProperties" in schema and not isinstance(schema["additionalProperties"], bool):
        raise SchemaError(f"{where}: additionalProperties must be a boolean or a schema")
    types = schema.get("type") if isinstance(schema.get("type"), list) else [schema.get("type")]
    if ("properties" in schema or "object" in types) and "additionalProperties" not in schema:
        raise SchemaError(f"{where}: an object schema must say what happens to unknown properties")
    if schema.get("additionalProperties") is True and schema.get("x-qa-informational") is not True:
        raise SchemaError(f"{where}: open objects must be marked x-qa-informational")
    if schema.get("x-qa-informational") is True and schema.get("additionalProperties") is not True:
        raise SchemaError(f"{where}: an informational object must set additionalProperties to true")
    if "items" in schema:
        check_schema(schema["items"], root, f"{where}/items")
    if "pattern" in schema:
        re.compile(schema["pattern"])
    if "propertyNames" in schema:
        extra = set(schema["propertyNames"]) - {"pattern", "maxLength"}
        if extra:
            raise SchemaError(f"{where}: propertyNames supports only pattern and maxLength, got {sorted(extra)}")


def _type_ok(value: Any, name: str) -> bool:
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "string":
        return isinstance(value, str)
    if name == "array":
        return isinstance(value, list)
    if name == "object":
        return isinstance(value, dict)
    raise SchemaError(f"unsupported type {name!r}")


class Validator:
    """``Validator(schema).validate(value)`` returns ``(issues, informational)``; an empty issue list means the value conforms."""

    def __init__(self, schema: Dict[str, Any]):
        check_schema(schema)
        self.schema = schema

    def validate(self, value: Any):
        issues: List[SchemaIssue] = []
        info: List[str] = []
        self._walk(self.schema, value, "", issues, info, 0)
        return issues, info

    def _walk(self, schema, value, pointer, issues, info, depth):
        if depth > MAX_REF_DEPTH + 64:
            issues.append(SchemaIssue("TOO_DEEP", pointer, "value is nested too deeply"))
            return
        if "$ref" in schema:
            schema = self.schema["$defs"][schema["$ref"][8:]]
        add = lambda code, msg: issues.append(SchemaIssue(code, pointer or "/", msg))      # noqa: E731
        if "type" in schema:
            names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(_type_ok(value, n) for n in names):
                add("TYPE", f"expected {' or '.join(names)}")
                return
        if "const" in schema and (value != schema["const"] or type(value) is not type(schema["const"])):
            add("CONST", f"must be {schema['const']!r}")
        if "enum" in schema and not any(value == e and type(value) is type(e) for e in schema["enum"]):
            add("ENUM", "not one of the allowed values")
        if isinstance(value, str):
            if "minLength" in schema and len(value) < schema["minLength"]:
                add("LENGTH", f"shorter than {schema['minLength']}")
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                add("LENGTH", f"longer than {schema['maxLength']}")
            if "pattern" in schema and not re.search(schema["pattern"], value):
                add("PATTERN", "does not match the required pattern")
        if isinstance(value, int) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                add("RANGE", f"below {schema['minimum']}")
            if "maximum" in schema and value > schema["maximum"]:
                add("RANGE", f"above {schema['maximum']}")
        if isinstance(value, list):
            if "minItems" in schema and len(value) < schema["minItems"]:
                add("ITEMS", f"fewer than {schema['minItems']} items")
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                add("ITEMS", f"more than {schema['maxItems']} items")
            if schema.get("uniqueItems") and len({repr(v) for v in value}) != len(value):
                add("UNIQUE", "items are not unique")
            if "items" in schema:
                for i, item in enumerate(value):
                    self._walk(schema["items"], item, f"{pointer}/{i}", issues, info, depth + 1)
        if isinstance(value, dict):
            props = schema.get("properties", {})
            for name in schema.get("required", []):
                if name not in value:
                    issues.append(SchemaIssue("REQUIRED", f"{pointer}/{_escape(name)}", "required property is missing"))
            additional = schema.get("additionalProperties", True)
            informational = schema.get("x-qa-informational") is True
            names = schema.get("propertyNames")
            for key in sorted(value):
                sub = f"{pointer}/{_escape(key)}"
                if names is not None:
                    if "pattern" in names and not re.search(names["pattern"], key):
                        issues.append(SchemaIssue("PATTERN", sub, "property name does not match the required pattern"))
                    if "maxLength" in names and len(key) > names["maxLength"]:
                        issues.append(SchemaIssue("LENGTH", sub, "property name is too long"))
                if key in props:
                    self._walk(props[key], value[key], sub, issues, info, depth + 1)
                elif informational:
                    item = value[key]
                    ok = INFO_KEY_RE.match(key) is not None and (item is None or isinstance(item, (bool, int)) or (
                        isinstance(item, str) and len(item) <= INFO_VALUE_MAX))
                    if ok:
                        info.append(sub)
                    else:
                        issues.append(SchemaIssue("INFORMATIONAL_FORM", sub, "informational fields must have a short lowercase name and a scalar value"))
                elif isinstance(additional, dict):
                    self._walk(additional, value[key], sub, issues, info, depth + 1)
                elif additional is False:
                    issues.append(SchemaIssue("UNKNOWN_FIELD", sub, "unknown field"))
