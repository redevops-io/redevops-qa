# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The check engine: resolves resource references inside a case root and runs one registered check program over them.

This is the library entry point. The adapter (``adapter.py``) and the command line (``cli.py``) both wrap it, so a scripted
executor and the adapter run the identical code. Everything here works on plain JSON mappings in the ``qa-check-adapter/1``
shape (``{"check_program_ref": {...}, "inputs": [{"kind": ..., ...}], "tier": "OFFLINE"}``), reads the case root and writes
nothing. Resolution:

* ``MANIFEST_PATH``: a file or a directory inside the case root; manifests are loaded with the safe loader.
* ``NAMESPACE_OBJECT``: one object (``api_version``, ``object_kind``, optional ``namespace``, ``name``) found among the
  manifests under the case root; zero matches is ``UNRESOLVED``, more than one is ``AMBIGUOUS``.
* ``IMAGE_DIGEST``: an image configuration found by digest in the configured image store (``image_metadata``); without a
  store it is not expressible here and raises ``Unsupported``.

A subject that does not resolve is reported as ``UNRESOLVED`` or ``AMBIGUOUS`` with no value; it is never a pass.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .canonical import canonical_bytes, json_digest, sha256_ref
from .errors import CheckError, LimitExceeded, ResourceAmbiguous, ResourceNotFound, Unsupported
from .manifests import Manifest, ManifestSet, freeze, load_tree, thaw, tree_digest
from .program_input import ProgramInput
from .registry import ProgramRegistry, refuse_expected

MAX_VALUE_BYTES = 16000        # the neutral ObservedValue carries at most 16384 bytes of canonical JSON; keep a margin
TIERS = ("OFFLINE", "K")
KINDS = ("MANIFEST_PATH", "IMAGE_DIGEST", "NAMESPACE_OBJECT")
_SUBJECT_FIELDS = {"check_program_ref", "inputs", "tier"}


@dataclass(frozen=True)
class Outcome:
    resolution: str                       # RESOLVED | UNRESOLVED | AMBIGUOUS
    match_count: int
    value: Any = None                     # plain JSON, observed values only
    value_sha256: str = ""
    inputs: Tuple[Tuple[str, str], ...] = ()      # (description, content digest) of each resolved input


def _ref_fields(ref: Mapping) -> Dict[str, Any]:
    kind = ref.get("kind")
    if kind not in KINDS:
        raise Unsupported(f"unknown resource kind {kind!r}")
    allowed = {"MANIFEST_PATH": {"path"}, "IMAGE_DIGEST": {"digest"},
               "NAMESPACE_OBJECT": {"api_version", "object_kind", "name", "namespace"}}[kind]
    present = {k for k, v in ref.items() if k != "kind" and v is not None}
    if present - allowed:
        raise Unsupported(f"fields {sorted(present - allowed)} do not belong to {kind}")
    return {k: ref.get(k) for k in allowed}


class CheckEngine:
    def __init__(self, case_root: Path, registry: ProgramRegistry, *, image_store: Any = None) -> None:
        self._root = Path(case_root)
        self._registry = registry
        self._images = image_store
        self._all: Optional[ManifestSet] = None

    @property
    def case_root(self) -> Path:
        return self._root

    @property
    def registry(self) -> ProgramRegistry:
        return self._registry

    def case_root_digest(self) -> str:
        return tree_digest(self._root)

    def _manifests_under_root(self) -> ManifestSet:
        if self._all is None:
            self._all = load_tree(self._root)
        return self._all

    # -- resolution -------------------------------------------------------------------------------------------------------
    def _find_objects(self, f: Mapping) -> List[Manifest]:
        ns = f.get("namespace") or ""
        return [m for m in self._manifests_under_root().manifests
                if m.api_version == f["api_version"] and m.kind == f["object_kind"] and m.name == f["name"]
                and m.namespace == ns]

    def resolve(self, ref: Mapping) -> Dict[str, Any]:
        """``{"content_digest", "ref"}`` for a resource reference; raises ``ResourceNotFound`` when absent."""
        f = _ref_fields(ref)
        kind = ref["kind"]
        if kind == "MANIFEST_PATH":
            try:
                digest = tree_digest(self._root, f["path"])
            except FileNotFoundError:
                raise ResourceNotFound(f"no such path in the case root: {f['path']}", path=f["path"]) from None
        elif kind == "NAMESPACE_OBJECT":
            found = self._find_objects(f)
            if not found:
                raise ResourceNotFound("no such object in the case root", object_kind=f["object_kind"], name=f["name"])
            if len(found) > 1:
                raise ResourceAmbiguous("more than one object has that identity", object_kind=f["object_kind"], name=f["name"])
            digest = json_digest(thaw(found[0].doc))
        else:
            if self._images is None:
                raise Unsupported("image metadata checks are not configured in this adapter")
            doc = self._images.get(f["digest"])
            if doc is None:
                raise ResourceNotFound("no image configuration with that digest in the image store", digest=f["digest"])
            digest = json_digest(thaw(doc))
        return {"content_digest": digest, "ref": dict(ref)}

    # -- running a check ----------------------------------------------------------------------------------------------------
    def load_inputs(self, inputs: List[Mapping]) -> Tuple[Optional[ProgramInput], str, int, Tuple[Tuple[str, str], ...]]:
        """(ProgramInput or None, resolution, match_count, resolved input digests)."""
        if not inputs:
            return None, "UNRESOLVED", 0, ()
        merged = ManifestSet()
        images: List[Any] = []
        digests: List[Tuple[str, str]] = []
        for ref in inputs:
            f = _ref_fields(ref)
            kind = ref["kind"]
            if kind == "MANIFEST_PATH":
                try:
                    part = load_tree(self._root, f["path"])
                    digests.append((f"path:{f['path']}", tree_digest(self._root, f["path"])))
                except FileNotFoundError:
                    return None, "UNRESOLVED", 0, tuple(digests)
                merged = merged.merged(part)
            elif kind == "NAMESPACE_OBJECT":
                found = self._find_objects(f)
                if not found:
                    return None, "UNRESOLVED", 0, tuple(digests)
                if len(found) > 1:
                    return None, "AMBIGUOUS", len(found), tuple(digests)
                merged = merged.merged(ManifestSet(manifests=(found[0],)))
                digests.append((f"object:{f['object_kind']}/{f['name']}", json_digest(thaw(found[0].doc))))
            else:
                if self._images is None:
                    raise Unsupported("image metadata checks are not configured in this adapter")
                doc = self._images.get(f["digest"])
                if doc is None:
                    return None, "UNRESOLVED", 0, tuple(digests)
                images.append(freeze(doc))
                digests.append((f"image:{f['digest']}", json_digest(thaw(doc))))
        data = ProgramInput(manifests=merged.manifests, references=merged.references, load_errors=merged.errors,
                            files=merged.files, images=tuple(images))
        return data, "RESOLVED", 1, tuple(digests)

    def run_check(self, subject: Mapping) -> Outcome:
        """Run the program the subject names (hash verified first) over its inputs; returns observed values only."""
        refuse_expected(subject, "check subject")
        if set(subject) - _SUBJECT_FIELDS:
            raise Unsupported(f"unknown subject fields {sorted(set(subject) - _SUBJECT_FIELDS)}")
        if subject.get("tier") not in TIERS:
            raise Unsupported(f"unknown tier {subject.get('tier')!r}")
        if subject["tier"] != "OFFLINE":
            raise Unsupported("this engine runs offline checks; tier K checks go through the disposable-cluster gate")
        self._registry.resolve(subject["check_program_ref"])           # verified before anything is read or executed
        data, resolution, count, digests = self.load_inputs(list(subject.get("inputs") or ()))
        if data is None:
            return Outcome(resolution=resolution, match_count=count, inputs=digests)
        value = self._registry.run(subject["check_program_ref"], data)
        raw = canonical_bytes(value)
        if len(raw) > MAX_VALUE_BYTES:
            raise LimitExceeded(f"the observed value is {len(raw)} bytes, over the {MAX_VALUE_BYTES} byte bound; "
                                "scope the inputs to fewer files", size=len(raw))
        return Outcome(resolution="RESOLVED", match_count=1, value=value, value_sha256=sha256_ref(raw), inputs=digests)
