# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Conversion between contracts ``qa/v1`` objects and harness neutral records.

Only plain JSON data crosses. A conversion is always ``object.to_json()`` on the source side, a pure dictionary
transformation here (hash prefix mapping, normalisation of the three reused repository types), and ``from_json`` on the
destination side. No class instance of one side is ever handed to the other.

**Verify on convert.** After the destination object exists, the digest it computes for itself is compared with the digest
the source computed. A difference raises :class:`HashDisagreement` and the converted object is not returned: the bridge
never papers over two implementations that disagree about the same payload.

Public API
----------
data level   ``contracts_data_to_neutral`` / ``neutral_data_to_contracts``  (dict -> dict, no instances)
object level ``from_contracts`` / ``to_contracts``  (contracts object -> neutral object and back)
"""
from __future__ import annotations

import copy
import dataclasses
import enum
import typing
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from . import deps, hashing
from .errors import (Codes, ConversionRefused, DataOnlyViolation, HashDisagreement, UnknownSchema, UnknownType)
from .registry import Registry, build_registry

SCHEMA_PREFIX = "runtime-contracts/qa/"
_registry_cache: Dict[Tuple[int, int], Registry] = {}
_DATA_TYPES = (type(None), bool, int, str)
_MAX_DEPTH = 64


def registry() -> Registry:
    """The type pairs of the currently imported dependencies (rebuilt if either module object changes)."""
    key = (id(deps.contracts_qa()), id(deps.neutral_qa()))
    reg = _registry_cache.get(key)
    if reg is None:
        _registry_cache.clear()
        reg = _registry_cache[key] = build_registry()
    return reg


# -- data-only guard ------------------------------------------------------------------------------------------------

def assert_data_only(value: Any, path: str = "value", _depth: int = 0) -> None:
    """Refuse anything that is not plain JSON data: exact ``None``/``bool``/``int``/``str``, ``list``, ``tuple`` and
    ``dict`` with ``str`` keys. Class instances (including subclasses of ``str``/``int``, enums and mappings that are
    not ``dict``) and floats are refused with :class:`DataOnlyViolation`."""
    if _depth > _MAX_DEPTH:
        raise DataOnlyViolation(f"{path}: nested deeper than {_MAX_DEPTH}")
    t = type(value)
    if t in _DATA_TYPES:
        return
    if t is list or t is tuple:
        for i, item in enumerate(value):
            assert_data_only(item, f"{path}[{i}]", _depth + 1)
        return
    if t is dict:
        for k, item in value.items():
            if type(k) is not str:
                raise DataOnlyViolation(f"{path}: object keys must be str, got {type(k).__name__}")
            assert_data_only(item, f"{path}.{k}", _depth + 1)
        return
    raise DataOnlyViolation(f"{path}: {t.__module__}.{t.__qualname__} is not plain data (class instances never cross "
                            "the boundary)")


# -- hash prefix mapping inside a payload --------------------------------------------------------------------------

def _is_record_dict(node: Mapping) -> bool:
    sid = node.get("schema_id")
    return isinstance(sid, str) and sid.startswith(SCHEMA_PREFIX)


def _map_content_hashes(node: Any, mapper) -> Any:
    if isinstance(node, dict):
        out = {k: _map_content_hashes(v, mapper) for k, v in node.items()}
        if _is_record_dict(node) and isinstance(node.get("content_hash"), str):
            out["content_hash"] = mapper(node["content_hash"])
        return out
    if isinstance(node, (list, tuple)):
        return [_map_content_hashes(v, mapper) for v in node]
    return node


# -- reused repository types (Check, EvidenceRef, SecretRef) ---------------------------------------------------------

def _strip_empty_optionals(node: Any, spec: Any, neutral_records) -> Any:
    """Contracts spells an unset optional string of a reused type as ``""``; the neutral records spell it as absent and
    refuse ``""``. Drop exactly those empty strings, walking the neutral class structure so nothing else is touched."""
    kind = spec.kind
    if kind == "tuple" and isinstance(node, list):
        return [_strip_empty_optionals(v, spec.elem, neutral_records) for v in node]
    if kind == "record" and isinstance(node, dict):
        return _strip_record(node, spec.cls, neutral_records)
    return node


def _strip_record(data: Dict[str, Any], ncls: type, neutral_records) -> Dict[str, Any]:
    infos = {i.name: i for i in neutral_records.field_infos(ncls)}
    reused = ncls.__name__ in registry().reused
    out: Dict[str, Any] = {}
    for key, value in data.items():
        if key == "custody" and isinstance(value, dict):
            out[key] = {ck: _strip_empty_optionals(cv, infos[ck].spec, neutral_records) if ck in infos else cv
                        for ck, cv in value.items()}
            continue
        info = infos.get(key)
        if info is None:
            out[key] = value
        elif reused and not info.required and info.spec.kind == "str" and value == "":
            continue
        else:
            out[key] = _strip_empty_optionals(value, info.spec, neutral_records)
    return out


def _constructed_reused_from_json(cls: type, data: Mapping[str, Any]) -> Any:
    hints = typing.get_type_hints(cls, include_extras=False)
    kwargs: Dict[str, Any] = {}
    for f in dataclasses.fields(cls):
        if f.name not in data:
            continue
        value = data[f.name]
        hint = hints[f.name]
        if isinstance(hint, type) and issubclass(hint, enum.Enum):
            value = hint(value)
        elif isinstance(value, list):
            value = tuple(value)
        kwargs[f.name] = value
    unknown = sorted(set(data) - {f.name for f in dataclasses.fields(cls)})
    if unknown:
        raise ConversionRefused(f"{cls.__name__}: unknown field(s) {unknown}", cause_code="UNKNOWN_FIELD")
    return cls(**kwargs)


def _reused_to_json(obj: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for f in dataclasses.fields(obj):
        value = getattr(obj, f.name)
        if isinstance(value, enum.Enum):
            value = value.value
        elif isinstance(value, (tuple, list)):
            value = [v.value if isinstance(v, enum.Enum) else v for v in value]
        out[f.name] = value
    return out


# -- classification ---------------------------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class _Kind:
    kind: str               # record | value | reused | enum
    key: str                # schema id for records, class name otherwise
    contracts_cls: Optional[type] = None
    neutral_cls: Optional[type] = None


def _kind_from_schema_id(schema_id: str) -> _Kind:
    pair = registry().records.get(schema_id)
    if pair is None:
        reg = registry()
        if schema_id in reg.contracts_only_records:
            raise UnknownSchema(f"{schema_id} exists only on the contracts side and never crosses to the harness "
                                "(the harness receives no plan record)", schema_id=schema_id)
        raise UnknownSchema(f"no qa/v1 record has schema id {schema_id!r}", schema_id=schema_id)
    return _Kind("record", schema_id, pair[0], pair[1])


def _kind_from_name(name: str) -> _Kind:
    reg = registry()
    for kind, table in (("value", reg.values), ("reused", reg.reused), ("enum", reg.enums)):
        if name in table:
            return _Kind(kind, name, *table[name])
    if name in reg.contracts_only_values or name in reg.contracts_only_enums:
        raise UnknownType(f"{name} exists only on the contracts side and never crosses to the harness", type=name)
    raise UnknownType(f"no qa/v1 value, reused type or enum is named {name!r}", type=name)


def _contracts_digest(obj: Any) -> str:
    c = deps.contracts_qa()
    base = deps.contracts_module("base")
    if isinstance(obj, base.QARecord):
        return obj.content_hash
    if isinstance(obj, base.QAValue):
        return obj.value_hash()
    canonical = deps.contracts_package_module("canonical")
    return canonical.content_hash(obj.canonical_form())


def _neutral_digest(obj: Any) -> str:
    return obj.canon_hash()


def contracts_digest(obj: Any) -> str:
    """The ``rcv1:`` hash the contracts side computes for one of its objects."""
    return _contracts_digest(obj)


def neutral_digest(obj: Any) -> str:
    """The ``canon-v1:`` hash the neutral side computes for one of its objects."""
    return _neutral_digest(obj)


# -- data level -------------------------------------------------------------------------------------------------------

def contracts_data_to_neutral(data: Any, *, type_name: Optional[str] = None) -> Dict[str, Any]:
    """Contracts JSON (``to_json()`` form) -> neutral JSON. Records are recognised by ``schema_id``; a value or reused
    type needs ``type_name``. The result is data only; ``canon-v1:`` replaces ``rcv1:`` on every ``content_hash``."""
    assert_data_only(data)
    kind = _kind_for(data, type_name)
    mapped = _map_content_hashes(copy.deepcopy(data), hashing.to_neutral_hash)
    n = deps.neutral_qa()
    return _strip_record(mapped, kind.neutral_cls, n.records)


def neutral_data_to_contracts(data: Any, *, type_name: Optional[str] = None) -> Dict[str, Any]:
    """Neutral JSON (``to_json(with_hash=True)`` form) -> contracts JSON."""
    assert_data_only(data)
    _kind_for(data, type_name)
    return _map_content_hashes(copy.deepcopy(data), hashing.to_contracts_hash)


def _kind_for(data: Any, type_name: Optional[str]) -> _Kind:
    if not isinstance(data, dict):
        raise DataOnlyViolation("expected a JSON object")
    if type_name is not None:
        return _kind_from_name(type_name)
    sid = data.get("schema_id")
    if not isinstance(sid, str):
        raise UnknownSchema("a record needs a schema_id; pass type_name= for a value type")
    return _kind_from_schema_id(sid)


# -- object level -----------------------------------------------------------------------------------------------------

def _refused(side: str, exc: Exception) -> Exception:
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code:
        if code == "HASH_MISMATCH":
            return HashDisagreement(f"{side} refused the payload: its stored content_hash does not match its own "
                                    f"recomputation ({exc})", cause_code=code, side=side)
        return ConversionRefused(f"{side} refused the payload: {exc}", cause_code=code, side=side)
    return exc


def _same_digest_or_raise(source_hash: str, dest_hash: str, what: str) -> None:
    if hashing.digest_of(source_hash) != hashing.digest_of(dest_hash):
        raise HashDisagreement(f"{what}: the two sides compute different digests for the same payload "
                               f"({source_hash} != {dest_hash})", source_hash=source_hash, destination_hash=dest_hash)


def from_contracts(obj: Any) -> Any:
    """A contracts object (record, value, reused type or enum member) -> the neutral object with the same identity."""
    c = deps.contracts_qa()
    base = deps.contracts_module("base")
    if isinstance(obj, enum.Enum):
        kind = _kind_from_name(type(obj).__name__)
        if kind.kind != "enum":
            raise UnknownType(f"{type(obj).__name__} is not an enum", type=type(obj).__name__)
        return kind.neutral_cls(obj.value)
    if isinstance(obj, base.QARecord):
        kind = _kind_from_schema_id(obj.SCHEMA_ID)
        data = obj.to_json()
        type_name = None
    elif isinstance(obj, base.QAValue):
        kind = _kind_from_name(type(obj).__name__)
        data = obj.to_json()
        type_name = type(obj).__name__
    elif dataclasses.is_dataclass(obj) and type(obj).__name__ in registry().reused:
        kind = _kind_from_name(type(obj).__name__)
        data = _reused_to_json(obj)
        type_name = type(obj).__name__
    else:
        raise UnknownType(f"{type(obj).__module__}.{type(obj).__qualname__} is not a contracts qa/v1 type")
    neutral_data = contracts_data_to_neutral(data, type_name=type_name)
    try:
        out = kind.neutral_cls.from_json(neutral_data)
    except Exception as exc:
        raise _refused("neutral", exc) from exc
    _same_digest_or_raise(_contracts_digest(obj), _neutral_digest(out), type(obj).__name__)
    return out


def to_contracts(obj: Any) -> Any:
    """A neutral object (record, value, reused type or enum member) -> the contracts object with the same identity."""
    n = deps.neutral_qa()
    base = n.records._Value
    if isinstance(obj, enum.Enum):
        kind = _kind_from_name(type(obj).__name__)
        if kind.kind != "enum":
            raise UnknownType(f"{type(obj).__name__} is not an enum", type=type(obj).__name__)
        return kind.contracts_cls(obj.value)
    if not isinstance(obj, base):
        raise UnknownType(f"{type(obj).__module__}.{type(obj).__qualname__} is not a neutral qa/v1 type")
    if obj.IS_RECORD:
        kind = _kind_from_schema_id(obj.SCHEMA_ID)
        data = obj.to_json(with_hash=True)
        type_name = None
    else:
        kind = _kind_from_name(type(obj).__name__)
        data = obj.to_json()
        type_name = type(obj).__name__
    contracts_data = neutral_data_to_contracts(data, type_name=type_name)
    try:
        if kind.kind == "reused":
            out = _constructed_reused_from_json(kind.contracts_cls, contracts_data)
        else:
            out = kind.contracts_cls.from_json(contracts_data)
    except Exception as exc:
        raise _refused("contracts", exc) from exc
    _same_digest_or_raise(_neutral_digest(obj), _contracts_digest(out), type(obj).__name__)
    return out


def from_contracts_sequence(items: Sequence[Any]) -> Tuple[Any, ...]:
    return tuple(from_contracts(i) for i in items)


def to_contracts_sequence(items: Sequence[Any]) -> Tuple[Any, ...]:
    return tuple(to_contracts(i) for i in items)
