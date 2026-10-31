# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Reading the pinned vector files. No dependency is imported here: only the files named by ``pins.toml``."""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Dict, List

from ..deps import addendum_files
from ..pins import DependencyPin, Pins

KINDS = ("golden", "canon", "clarifications", "inventory", "schema", "unrecognized")


@dataclass(frozen=True)
class VectorFile:
    side: str               # "contracts" or "harness"
    rel: str                # path relative to the pinned tree
    kind: str               # one of KINDS
    data: Any
    error: str = ""

    @property
    def name(self) -> str:
        return PurePosixPath(self.rel).name

    @property
    def vector_id_prefix(self) -> str:
        return self.name


def classify(rel: str, data: Any) -> str:
    name = PurePosixPath(rel).name
    if name.endswith(".inventory.json"):
        return "inventory"
    if name.endswith(".schema.json"):
        return "schema"
    if isinstance(data, dict):
        if isinstance(data.get("vectors"), list) and "canonicalization" in data:
            return "canon"
        if isinstance(data.get("cases"), dict) and isinstance(data.get("values"), dict):
            return "golden"
        if "clarifications_version" in data:
            return "clarifications"
    return "unrecognized"


def _load_dependency(side: str, dep: DependencyPin) -> List[VectorFile]:
    out = []
    for rel in sorted(set(dep.vector_files) | set(addendum_files(dep))):
        path = dep.vector_path(rel)
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as exc:
            out.append(VectorFile(side, rel, "unrecognized", None, f"{type(exc).__name__}: {exc}"))
            continue
        out.append(VectorFile(side, rel, classify(rel, data), data))
    return out


def load_vector_files(pins: Pins) -> List[VectorFile]:
    return _load_dependency("contracts", pins.contracts) + _load_dependency("harness", pins.harness_qa)


def only(files: List[VectorFile], side: str, kind: str) -> List[VectorFile]:
    return [f for f in files if f.side == side and f.kind == kind]


def deep(value: Any) -> Any:
    return copy.deepcopy(value)


def case_input(case: Dict[str, Any]) -> Dict[str, Any]:
    """A golden case as contracts ``from_json`` expects it: the input with its custody fields merged back."""
    data = deep(case["input"])
    if case.get("custody"):
        data["custody"] = deep(case["custody"])
    return data
