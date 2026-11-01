#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A small, strict JSON Schema validator (standard library only) for the schemas in ``schemas/``.

Why it exists: the offline CI jobs install only pytest and PyYAML, and the capability manifest and install profiles must be checked there. The
schemas stay ordinary JSON Schema (draft 2020-12 vocabulary), so any full validator accepts them; ``tools/check_capabilities.py --cross-check``
runs the real ``jsonschema`` package over the same files in a dedicated CI step to prove the two agree.

It supports only the keywords below and FAILS on any other keyword (an unsupported keyword would otherwise be silently ignored, which would turn
a schema rule into a no-op): ``type`` (a name or a list of names), ``enum``, ``const``, ``required``, ``properties``, ``additionalProperties``
(``false`` or a schema), ``items``, ``minItems``, ``maxItems``, ``uniqueItems``, ``minLength``, ``maxLength``, ``pattern`` (``re.search``),
``minimum``, ``maximum``, ``allOf``, ``anyOf``, ``if`` / ``then`` / ``else`` and a local ``$ref`` of the form ``#/$defs/<name>``. Annotation keywords
(``$schema``, ``$id``, ``$defs``, ``title``, ``description``, ``$comment``, ``examples``, ``default``) are accepted and ignored.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

ANNOTATIONS = frozenset({"$schema", "$id", "$defs", "title", "description", "$comment", "examples", "default"})
KEYWORDS = frozenset({"type", "enum", "const", "required", "properties", "additionalProperties", "items", "minItems", "maxItems", "uniqueItems",
                      "minLength", "maxLength", "pattern", "minimum", "maximum", "allOf", "anyOf", "if", "then", "else", "$ref"})


class SchemaError(ValueError):
    """The schema uses something this validator does not support (never silently ignored)."""


def _type_ok(value: Any, name: str) -> bool:
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "string":
        return isinstance(value, str)
    if name == "array":
        return isinstance(value, list)
    if name == "object":
        return isinstance(value, dict)
    raise SchemaError(f"unknown type {name!r}")


def _resolve(ref: str, root: Dict[str, Any]) -> Dict[str, Any]:
    prefix = "#/$defs/"
    if not ref.startswith(prefix):
        raise SchemaError(f"unsupported $ref {ref!r} (only {prefix}<name>)")
    defs = root.get("$defs", {})
    name = ref[len(prefix):]
    if name not in defs:
        raise SchemaError(f"$ref {ref!r} does not resolve")
    return defs[name]


def _equal(a: Any, b: Any) -> bool:
    # JSON equality: True is not 1 and False is not 0
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_equal(a[k], b[k]) for k in a)
    return a == b


def _check(value: Any, schema: Any, root: Dict[str, Any], path: str, out: List[str]) -> None:
    if schema is True:
        return
    if schema is False:
        out.append(f"{path or '/'}: not allowed")
        return
    if not isinstance(schema, dict):
        raise SchemaError(f"a schema must be an object or a boolean at {path or '/'}")
    unknown = sorted(set(schema) - KEYWORDS - ANNOTATIONS)
    if unknown:
        raise SchemaError(f"unsupported keyword(s) {unknown} at {path or '/'}")
    here = path or "/"
    if "$ref" in schema:
        _check(value, _resolve(schema["$ref"], root), root, path, out)
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(value, n) for n in names):
            out.append(f"{here}: expected {'/'.join(names)}, got {type(value).__name__}")
            return
    if "const" in schema and not _equal(value, schema["const"]):
        out.append(f"{here}: must equal {schema['const']!r}")
    if "enum" in schema and not any(_equal(value, option) for option in schema["enum"]):
        out.append(f"{here}: {value!r} is not one of {schema['enum']!r}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            out.append(f"{here}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            out.append(f"{here}: longer than {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            out.append(f"{here}: does not match pattern {schema['pattern']!r}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            out.append(f"{here}: below {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            out.append(f"{here}: above {schema['maximum']}")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            out.append(f"{here}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            out.append(f"{here}: more than {schema['maxItems']} items")
        if schema.get("uniqueItems"):
            for i, item in enumerate(value):
                if any(_equal(item, other) for other in value[:i]):
                    out.append(f"{here}: item {i} repeats an earlier item")
                    break
        if "items" in schema:
            for i, item in enumerate(value):
                _check(item, schema["items"], root, f"{path}/{i}", out)
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                out.append(f"{here}: missing required property {name!r}")
        for name, sub in value.items():
            if name in props:
                _check(sub, props[name], root, f"{path}/{name}", out)
            elif "additionalProperties" in schema:
                extra = schema["additionalProperties"]
                if extra is False:
                    out.append(f"{here}: unexpected property {name!r}")
                elif extra is not True:
                    _check(sub, extra, root, f"{path}/{name}", out)
    for sub in schema.get("allOf", []):
        _check(value, sub, root, path, out)
    if "anyOf" in schema:
        trials = []
        for sub in schema["anyOf"]:
            errs: List[str] = []
            _check(value, sub, root, path, errs)
            if not errs:
                break
            trials.append(errs)
        else:
            out.append(f"{here}: matches none of the alternatives ({'; '.join(e[0] for e in trials)})")
    if "if" in schema:
        probe: List[str] = []
        _check(value, schema["if"], root, path, probe)
        branch = "then" if not probe else "else"
        if branch in schema:
            _check(value, schema[branch], root, path, out)


def check_schema(schema: Any, root: Optional[Dict[str, Any]] = None, path: str = "") -> None:
    """Walk every subschema (also the ones no instance reaches) and raise ``SchemaError`` for an unsupported keyword or a broken ``$ref``."""
    root = schema if root is None else root
    if isinstance(schema, bool):
        return
    if not isinstance(schema, dict):
        raise SchemaError(f"a schema must be an object or a boolean at {path or '/'}")
    unknown = sorted(set(schema) - KEYWORDS - ANNOTATIONS)
    if unknown:
        raise SchemaError(f"unsupported keyword(s) {unknown} at {path or '/'}")
    if "$ref" in schema:
        _resolve(schema["$ref"], root)
    for name, sub in schema.get("properties", {}).items():
        check_schema(sub, root, f"{path}/properties/{name}")
    for name, sub in schema.get("$defs", {}).items():
        check_schema(sub, root, f"{path}/$defs/{name}")
    for key in ("items", "additionalProperties", "if", "then", "else"):
        if key in schema:
            check_schema(schema[key], root, f"{path}/{key}")
    for key in ("allOf", "anyOf"):
        for i, sub in enumerate(schema.get(key, [])):
            check_schema(sub, root, f"{path}/{key}/{i}")


def validate(instance: Any, schema: Dict[str, Any], *, root: Optional[Dict[str, Any]] = None) -> List[str]:
    """Every violation as ``<json pointer>: <reason>``; an empty list means valid. Raises ``SchemaError`` for an unsupported schema."""
    check_schema(schema, root)
    out: List[str] = []
    _check(instance, schema, root if root is not None else schema, "", out)
    return out


def mutations(instance: Any, *, limit: int = 4000):
    """Yield ``(description, mutated copy)`` for systematic single edits of ``instance``: delete each object member, replace each value by one of
    another type, empty each string and drop each array item. Used by the differential check that compares this validator with the full
    ``jsonschema`` package (strings, integers, booleans, null, lists and objects only; no floats)."""
    import copy

    count = 0

    def walk(node: Any, path: tuple):
        if isinstance(node, dict):
            for key in list(node):
                yield path + (key,), "delete"
                yield from walk(node[key], path + (key,))
        elif isinstance(node, list):
            for i in range(len(node)):
                yield path + (i,), "delete"
                yield from walk(node[i], path + (i,))

    def edit(root: Any, path: tuple, action: str, replacement: Any = None):
        clone = copy.deepcopy(root)
        parent = clone
        for step in path[:-1]:
            parent = parent[step]
        if action == "delete":
            del parent[path[-1]]
        else:
            parent[path[-1]] = replacement
        return clone

    points = list(walk(instance, ()))
    for path, action in points:
        for repl_name, repl in (("string", "x"), ("integer", 12345), ("null", None), ("true", True), ("empty string", ""), ("empty list", []), ("empty object", {})):
            if count >= limit:
                return
            changed = edit(instance, path, "set", repl)
            if changed == instance:
                continue
            yield f"replace /{'/'.join(map(str, path))} by {repl_name}", changed
            count += 1
        if action == "delete":
            if count >= limit:
                return
            yield f"delete /{'/'.join(map(str, path))}", edit(instance, path, "delete")
            count += 1
