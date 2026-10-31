# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Shared pure helpers for tier K programs: they read observation documents the collector gathered."""
from __future__ import annotations

from ._common import as_list, as_map, text


def section(data, name):
    return [as_map(d) for d in data.cluster if as_map(d).get("section") == name]


def lane(data):
    docs = section(data, "lane")
    d = docs[0] if len(docs) == 1 else {}
    return {"id": text(d.get("lane")), "kubernetes_version": text(d.get("kubernetes_version")), "disposable_proof": text(d.get("disposable_proof"))}


def strs(v):
    return [text(x) for x in as_list(v)]
