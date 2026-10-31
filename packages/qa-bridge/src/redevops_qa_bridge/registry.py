# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Pairs of corresponding types on the two sides, discovered from the pinned packages (nothing is listed by hand).

Records pair by ``schema_id``; values, reused repository types and enums pair by class name. A type that exists on one
side only is reported, never silently skipped: ``qa-plan`` is contracts-only by design (the harness receives no plan,
ADR A.2.4 item 7).
"""
from __future__ import annotations

import dataclasses
import enum
import typing
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from . import deps


@dataclass(frozen=True)
class Registry:
    records: Dict[str, Tuple[type, type]]       # schema_id -> (contracts class, neutral class)
    values: Dict[str, Tuple[type, type]]        # class name -> pair (qa/v1 value types)
    reused: Dict[str, Tuple[type, type]]        # repository types reused by qa/v1 (Check, EvidenceRef, SecretRef)
    enums: Dict[str, Tuple[type, type]]         # enum name -> pair
    contracts_only_records: Dict[str, type]
    neutral_only_records: Dict[str, type]
    contracts_only_values: Dict[str, type]
    neutral_only_values: Dict[str, type]
    contracts_only_enums: Dict[str, type]
    neutral_only_enums: Dict[str, type]


def _walk_dataclass_hints(roots, qa_value_base) -> Dict[str, type]:
    """Dataclasses reachable from the qa/v1 schemas that are not themselves qa/v1 values (the reused types)."""
    found: Dict[str, type] = {}
    stack = list(roots)
    seen = set()
    while stack:
        cls = stack.pop()
        if cls in seen:
            continue
        seen.add(cls)
        try:
            hints = typing.get_type_hints(cls, include_extras=True)
        except Exception:
            continue
        pending = list(hints.values())
        while pending:
            t = pending.pop()
            pending.extend(typing.get_args(t))
            if isinstance(t, type) and dataclasses.is_dataclass(t):
                if not issubclass(t, qa_value_base):
                    found[t.__name__] = t
                stack.append(t)
    return found


def build_registry() -> Registry:
    c = deps.contracts_qa()
    n = deps.neutral_qa()
    c_reg = deps.contracts_module("registry")
    c_base = deps.contracts_module("base")
    n_rec = n.records
    n_err = n.errors

    c_records = {cls.SCHEMA_ID: cls for cls in c_reg.RECORDS}
    n_records = dict(n_rec.RECORDS_BY_SCHEMA_ID)
    c_values = {cls.__name__: cls for cls in c_reg.VALUES}
    n_values = {cls.__name__: cls for cls in n_rec.VALUE_TYPES}

    c_reused = _walk_dataclass_hints([*c_reg.RECORDS, *c_reg.VALUES], c_base.QAValue)
    reused_names = set(c_reused) & {cls.__name__ for cls in n_rec.VALUE_TYPES}
    # the neutral side lists a reused type among its values; keep it out of the plain value pairs
    c_enums = dict(c_reg.ALL_ENUMS)
    n_enums: Dict[str, type] = dict(n_rec.ENUMS)
    n_enums["ErrorCategory"] = n_err.ErrorCategory
    n_enums["ClassHint"] = n_err.ClassHint

    def pair(cmap: Dict[str, Any], nmap: Dict[str, Any]):
        both = {k: (cmap[k], nmap[k]) for k in sorted(set(cmap) & set(nmap))}
        return both, {k: cmap[k] for k in sorted(set(cmap) - set(nmap))}, {k: nmap[k] for k in sorted(set(nmap) - set(cmap))}

    rec, c_only_rec, n_only_rec = pair(c_records, n_records)
    c_values_plain = {k: v for k, v in c_values.items() if k not in reused_names}
    n_values_plain = {k: v for k, v in n_values.items() if k not in reused_names}
    val, c_only_val, n_only_val = pair(c_values_plain, n_values_plain)
    reused = {k: (c_reused[k], next(cls for cls in n_rec.VALUE_TYPES if cls.__name__ == k)) for k in sorted(reused_names)}
    en, c_only_en, n_only_en = pair(c_enums, n_enums)
    return Registry(records=rec, values=val, reused=reused, enums=en, contracts_only_records=c_only_rec,
                    neutral_only_records=n_only_rec, contracts_only_values=c_only_val, neutral_only_values=n_only_val,
                    contracts_only_enums=c_only_en, neutral_only_enums=n_only_en)


def is_enum_type(t: Any) -> bool:
    return isinstance(t, type) and issubclass(t, enum.Enum)
