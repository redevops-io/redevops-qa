# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""What a check program receives: parsed, frozen, read-only data and nothing else.

There is no field for an expected value, no clock, no environment and no handle to the file system, a network or a cluster.
A program is a pure function ``run(data) -> observed value``.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Tuple

from .manifests import LoadError, Manifest, Reference


@dataclass(frozen=True)
class ProgramInput:
    manifests: Tuple[Manifest, ...] = ()
    references: Tuple[Reference, ...] = ()
    load_errors: Tuple[LoadError, ...] = ()
    files: Tuple[Tuple[str, str], ...] = ()
    #: parsed image-configuration documents (``image_metadata``), frozen; empty for manifest checks
    images: Tuple[Mapping[str, Any], ...] = ()
    #: observations from a disposable cluster (a frozen document), empty for offline checks
    cluster: Tuple[Mapping[str, Any], ...] = ()

    def by_kind(self, kind: str) -> Tuple[Manifest, ...]:
        return tuple(m for m in self.manifests if m.kind == kind)

    def reference(self, kind: str):
        found = [r for r in self.references if r.kind == kind]
        return found[0] if len(found) == 1 else None
