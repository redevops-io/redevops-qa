# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Read-only inspection of image metadata that is already on disk, as files inside the case root.

Accepted inputs (nothing else, and nothing is fetched):

* an OCI image layout directory (``oci-layout``, ``index.json``, ``blobs/sha256/<hex>``). Manifest, index and configuration
  blobs are read and each one is verified against the digest in its file name; a blob that does not hash to its name is an
  error entry and no document is produced from it. Layer blobs are never read (only their descriptors are reported).
* loose JSON files: an image manifest, an image index, an image configuration or ``image inspect`` output, classified by
  content. A manifest finds its configuration among the loose configurations by digest.

There is no registry access, no daemon call and no network. Symbolic links are refused. The environment of an image is
reduced to the *names* of its variables and the build history to counts: values and build commands can carry secrets.

Each document is plain JSON, frozen, and keyed by digest. ``ImageStore.get`` returns the document for a ``sha256:<hex>``
digest, ``None`` when there is none, and raises ``ResourceAmbiguous`` when more than one distinct document answers to it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from .canonical import sha256_ref
from .errors import PathRefused, ResourceAmbiguous
from .manifests import (MAX_FILE_BYTES, LoadProblem, _lstat_regular_or_dir, freeze, iter_tree_files, parse_documents, resolve_in_root,
                        safe_relative)

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
MAX_INDEX_DEPTH = 3
MAX_ATTESTATION_BLOB = 1024 * 1024
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
SBOM_WORDS = ("spdx", "cyclonedx")
PROVENANCE_WORDS = ("slsa", "provenance")


def _read_file(path: Path, rel: str, cap: Optional[int] = None) -> bytes:
    cap = MAX_FILE_BYTES if cap is None else cap
    _lstat_regular_or_dir(path, rel)
    try:
        with open(path, "rb") as fh:
            data = fh.read(cap + 1)
    except OSError as exc:
        raise PathRefused(f"cannot read {rel}: {type(exc).__name__}", path=rel) from None
    if len(data) > cap:
        raise PathRefused(f"{rel} is larger than {cap} bytes", path=rel)
    return data


def _json(data: bytes) -> Any:
    try:
        docs = parse_documents(data.decode("utf-8"), as_json=True)
    except (UnicodeDecodeError, LoadProblem):
        return None
    return docs[0] if docs else None


def _m(v: Any) -> Mapping:
    return v if isinstance(v, Mapping) else {}


def _l(v: Any) -> list:
    return v if isinstance(v, list) else []


def _s(v: Any) -> str:
    return v if type(v) is str else ""


def _strs(v: Any) -> List[str]:
    return [x for x in _l(v) if type(x) is str] if isinstance(v, list) else []


def _int(v: Any) -> Optional[int]:
    return v if type(v) is int else None


def _pairs(v: Any) -> List[List[str]]:
    return sorted([k, x] for k, x in _m(v).items() if type(k) is str and type(x) is str)


def classify_attestation(texts: Iterable[str]) -> str:
    blob = " ".join(t.lower() for t in texts)
    if any(w in blob for w in SBOM_WORDS):
        return "sbom"
    if any(w in blob for w in PROVENANCE_WORDS):
        return "provenance"
    return "other"


# -- configuration to fields --------------------------------------------------------------------------------------------

def _config_fields(cfg: Mapping, *, inspect: bool = False) -> Dict[str, Any]:
    """Fields from an image configuration blob (or the ``Config`` of an ``image inspect`` document)."""
    c = _m(cfg) if inspect else _m(_m(cfg).get("config"))
    hc = c.get("Healthcheck")
    health = None
    if isinstance(hc, Mapping):
        health = {"test": _strs(hc.get("Test")), "interval": _int(hc.get("Interval")), "timeout": _int(hc.get("Timeout")),
                  "start_period": _int(hc.get("StartPeriod")), "retries": _int(hc.get("Retries"))}
    env_names = sorted({e.split("=", 1)[0] for e in _strs(c.get("Env"))})
    ports = sorted(k for k in _m(c.get("ExposedPorts")) if type(k) is str)
    return {
        "user": _s(c.get("User")),
        "entrypoint": _strs(c.get("Entrypoint")) if isinstance(c.get("Entrypoint"), list) else (None if c.get("Entrypoint") is None else [_s(c.get("Entrypoint"))]),
        "cmd": _strs(c.get("Cmd")) if isinstance(c.get("Cmd"), list) else (None if c.get("Cmd") is None else [_s(c.get("Cmd"))]),
        "working_dir": _s(c.get("WorkingDir")),
        "exposed_ports": ports,
        "volumes": sorted(k for k in _m(c.get("Volumes")) if type(k) is str),
        "env_names": env_names,
        "stop_signal": _s(c.get("StopSignal")),
        "healthcheck": health,
        "labels": _pairs(c.get("Labels")),
    }


def _base_from(labels: List[List[str]], annotations: List[List[str]]) -> Tuple[str, str]:
    lookup = {k: v for k, v in annotations}
    lookup.update({k: v for k, v in labels})
    return (_s(lookup.get("org.opencontainers.image.base.digest")), _s(lookup.get("org.opencontainers.image.base.name")))


def _empty_doc(digest: str, source: str, kind: str) -> Dict[str, Any]:
    return {"digest": digest, "source": source, "kind": kind, "media_type": "", "config_digest": "", "config_present": False,
            "layers": [], "layer_count": 0, "architecture": "", "os": "", "variant": "", "user": "", "entrypoint": None, "cmd": None,
            "working_dir": "", "exposed_ports": [], "volumes": [], "env_names": [], "stop_signal": "", "healthcheck": None,
            "labels": [], "annotations": [], "base_digest": "", "base_name": "", "diff_id_count": 0, "history_count": 0,
            "history_empty_layers": 0, "created": "", "ref_names": [], "attestations": [], "manifests": [], "problems": []}


def _build_image(digest: str, source: str, manifest: Mapping, config: Optional[Mapping], *, config_digest: str,
                 layer_present: Optional[Dict[str, bool]] = None, ref_names: Sequence[str] = (),
                 attestations: Sequence[Mapping] = (), problems: Sequence[str] = ()) -> Dict[str, Any]:
    d = _empty_doc(digest, source, "image")
    d["media_type"] = _s(manifest.get("mediaType"))
    d["config_digest"] = config_digest
    d["config_present"] = config is not None
    layers = []
    for l in _l(manifest.get("layers")):
        lm = _m(l)
        ld = _s(lm.get("digest"))
        layers.append({"media_type": _s(lm.get("mediaType")), "digest": ld, "size": _int(lm.get("size")),
                       "present": (layer_present or {}).get(ld)})
    d["layers"] = layers
    d["layer_count"] = len(layers)
    d["annotations"] = _pairs(manifest.get("annotations"))
    if config is not None:
        d.update(_config_fields(config))
        d["architecture"] = _s(config.get("architecture"))
        d["os"] = _s(config.get("os"))
        d["variant"] = _s(config.get("variant"))
        d["created"] = _s(config.get("created"))
        d["diff_id_count"] = len(_l(_m(config.get("rootfs")).get("diff_ids")))
        hist = _l(config.get("history"))
        d["history_count"] = len(hist)
        d["history_empty_layers"] = sum(1 for h in hist if _m(h).get("empty_layer") is True)
    d["base_digest"], d["base_name"] = _base_from(d["labels"], d["annotations"])
    d["ref_names"] = sorted(set(ref_names))
    d["attestations"] = sorted((dict(a) for a in attestations), key=lambda a: (a["kind"], a["predicate_type"], a["via"]))
    d["problems"] = sorted(set(problems))
    return d


def _build_inspect(item: Mapping, source: str, index: int) -> Optional[Dict[str, Any]]:
    cfg = item.get("Config")
    if not isinstance(cfg, Mapping):
        return None
    repo_digests = [x.split("@", 1)[1] for x in _strs(item.get("RepoDigests")) if "@" in x and DIGEST.fullmatch(x.split("@", 1)[1])]
    ident = _s(item.get("Id"))
    digest = repo_digests[0] if repo_digests else (ident if DIGEST.fullmatch(ident) else "")
    d = _empty_doc(digest, f"{source}#{index}", "inspect")
    d.update(_config_fields(cfg, inspect=True))
    d["config_digest"] = ident if DIGEST.fullmatch(ident) else ""
    d["config_present"] = True
    d["architecture"] = _s(item.get("Architecture"))
    d["os"] = _s(item.get("Os"))
    d["variant"] = _s(item.get("Variant"))
    d["created"] = _s(item.get("Created"))
    layers = _l(_m(item.get("RootFS")).get("Layers"))
    d["layer_count"] = len(layers)
    d["diff_id_count"] = len(layers)
    d["layers"] = [{"media_type": "", "digest": _s(x), "size": None, "present": None} for x in layers]
    d["ref_names"] = sorted(_strs(item.get("RepoTags")))
    d["base_digest"], d["base_name"] = _base_from(d["labels"], [])
    d["_keys"] = sorted(set(repo_digests + ([ident] if DIGEST.fullmatch(ident) else [])))
    if not d["_keys"]:
        d["problems"].append("no_digest")
    return d


# -- OCI layout -----------------------------------------------------------------------------------------------------------

class _Layout:
    def __init__(self, directory: Path, rel: str) -> None:
        self.dir, self.rel = directory, rel
        self.problems: List[Tuple[str, str]] = []             # (source, code)
        self._cache: Dict[str, Optional[Tuple[bytes, Any]]] = {}

    def blob(self, digest: str, cap: Optional[int] = None) -> Optional[Tuple[bytes, Any]]:
        """(bytes, parsed json) for a verified blob, or None (and a problem entry) when absent or not what its name says."""
        if digest in self._cache:
            return self._cache[digest]
        res: Optional[Tuple[bytes, Any]] = None
        if not DIGEST.fullmatch(digest or ""):
            self.problems.append((self.rel, "BAD_DIGEST"))
        else:
            path = self.dir / "blobs" / "sha256" / digest.split(":", 1)[1]
            try:
                data = _read_file(path, f"{self.rel}/blobs/sha256/{digest.split(':', 1)[1]}", cap)
            except FileNotFoundError:
                data = None
                self.problems.append((self.rel, "BLOB_MISSING"))
            if data is not None:
                if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
                    self.problems.append((self.rel, "BLOB_DIGEST_MISMATCH"))
                else:
                    res = (data, _json(data))
        self._cache[digest] = res
        return res

    def has_blob(self, digest: str) -> Optional[bool]:
        if not DIGEST.fullmatch(digest or ""):
            return None
        try:
            _lstat_regular_or_dir(self.dir / "blobs" / "sha256" / digest.split(":", 1)[1], self.rel)
            return True
        except FileNotFoundError:
            return False


def _walk_descriptors(layout: _Layout, descriptors: List[Any], depth: int, out: List[Dict[str, Any]], ref_for: Dict[str, List[str]]) -> None:
    for desc in descriptors:
        dm = _m(desc)
        digest = _s(dm.get("digest"))
        mt = _s(dm.get("mediaType"))
        ann = _m(dm.get("annotations"))
        got = layout.blob(digest)
        if got is None or not isinstance(got[1], Mapping):
            continue
        body = got[1]
        ref = _s(ann.get("org.opencontainers.image.ref.name"))
        if ref:
            ref_for.setdefault(digest, []).append(ref)
        is_index = mt in INDEX_TYPES or (not mt and "manifests" in body)
        if is_index:
            out.append({"type": "index", "digest": digest, "body": body, "annotations": ann, "descriptor": dm})
            if depth < MAX_INDEX_DEPTH:
                _walk_descriptors(layout, _l(body.get("manifests")), depth + 1, out, ref_for)
        else:
            out.append({"type": "manifest", "digest": digest, "body": body, "annotations": ann, "descriptor": dm})


def _attestations_for(layout: _Layout, found: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, str]]]:
    """Attestations by subject digest: OCI referrers (``subject``) and build-tool attestation manifests (annotation)."""
    by_subject: Dict[str, List[Dict[str, str]]] = {}
    for f in found:
        if f["type"] != "manifest":
            continue
        body, ann = f["body"], f["annotations"]
        manifest_ann = _m(body.get("annotations"))
        subject = _s(_m(body.get("subject")).get("digest")) or _s(ann.get("vnd.docker.reference.digest")) \
            or _s(manifest_ann.get("vnd.docker.reference.digest"))
        is_att = bool(subject) and (_s(ann.get("vnd.docker.reference.type")) == "attestation-manifest" or "subject" in body
                                    or _s(manifest_ann.get("vnd.docker.reference.type")) == "attestation-manifest")
        if not is_att:
            continue
        texts = [_s(body.get("artifactType")), _s(_m(body.get("config")).get("mediaType"))]
        predicate = ""
        for l in _l(body.get("layers")):
            lm = _m(l)
            texts.append(_s(lm.get("mediaType")))
            p = _s(_m(lm.get("annotations")).get("in-toto.io/predicate-type"))
            if p:
                predicate = predicate or p
                texts.append(p)
            elif "in-toto" in _s(lm.get("mediaType")):
                got = layout.blob(_s(lm.get("digest")), MAX_ATTESTATION_BLOB) if layout.has_blob(_s(lm.get("digest"))) else None
                if got is not None and isinstance(got[1], Mapping):
                    pt = _s(got[1].get("predicateType"))
                    if pt:
                        predicate = predicate or pt
                        texts.append(pt)
        kind = classify_attestation(texts)
        via = "attestation-manifest" if _s(ann.get("vnd.docker.reference.type")) == "attestation-manifest" else "referrer"
        by_subject.setdefault(subject, []).append({"kind": kind, "predicate_type": predicate, "via": via})
    return by_subject


def _platform(desc: Mapping) -> str:
    p = _m(desc.get("platform"))
    return "/".join(x for x in (_s(p.get("os")), _s(p.get("architecture")), _s(p.get("variant"))) if x)


def _load_layout(directory: Path, rel: str, errors: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    layout = _Layout(directory, rel)
    try:
        marker = _json(_read_file(directory / "oci-layout", f"{rel}/oci-layout"))
        index = _json(_read_file(directory / "index.json", f"{rel}/index.json"))
    except FileNotFoundError:
        errors.append((rel, "LAYOUT_INCOMPLETE"))
        return []
    if not isinstance(marker, Mapping) or not isinstance(index, Mapping) or _s(marker.get("imageLayoutVersion")) == "":
        errors.append((rel, "LAYOUT_MALFORMED"))
        return []
    found: List[Dict[str, Any]] = []
    ref_for: Dict[str, List[str]] = {}
    _walk_descriptors(layout, _l(index.get("manifests")), 0, found, ref_for)
    atts = _attestations_for(layout, found)
    docs: List[Dict[str, Any]] = []
    seen = set()
    for f in found:
        digest, body = f["digest"], f["body"]
        if digest in seen:
            continue
        seen.add(digest)
        if f["type"] == "index":
            d = _empty_doc(digest, rel, "index")
            d["media_type"] = _s(body.get("mediaType"))
            d["annotations"] = _pairs(body.get("annotations"))
            d["ref_names"] = sorted(set(ref_for.get(digest, [])))
            d["manifests"] = sorted(({"digest": _s(_m(x).get("digest")), "media_type": _s(_m(x).get("mediaType")),
                                      "platform": _platform(_m(x)), "artifact_type": _s(_m(x).get("artifactType")),
                                      "reference_type": _s(_m(_m(x).get("annotations")).get("vnd.docker.reference.type"))}
                                     for x in _l(body.get("manifests"))), key=lambda x: (x["digest"], x["platform"]))
            docs.append(d)
            continue
        if "config" not in body or "layers" not in body:
            continue
        if _s(f["annotations"].get("vnd.docker.reference.type")) == "attestation-manifest" or "subject" in body:
            continue                                          # an attestation is reported on its subject, not as an image
        cdig = _s(_m(body.get("config")).get("digest"))
        problems: List[str] = []
        cgot = layout.blob(cdig)
        config = cgot[1] if cgot is not None and isinstance(cgot[1], Mapping) else None
        if config is None:
            problems.append("config_missing_or_unverified")
        present = {_s(_m(l).get("digest")): bool(layout.has_blob(_s(_m(l).get("digest")))) for l in _l(body.get("layers"))}
        docs.append(_build_image(digest, rel, body, config, config_digest=cdig, layer_present=present,
                                 ref_names=ref_for.get(digest, []), attestations=atts.get(digest, []), problems=problems))
    errors.extend(layout.problems)
    return docs


# -- the store ----------------------------------------------------------------------------------------------------------------

def _is_layout_dir(directory: Path) -> bool:
    return (directory / "oci-layout").is_file() and not (directory / "oci-layout").is_symlink()


class ImageStore:
    """Image documents found under ``paths`` of a case root, scanned lazily on first use and never written to."""

    def __init__(self, case_root: Path, paths: Sequence[str] = (".",)) -> None:
        self._root = Path(case_root)
        self._paths = tuple(paths)
        self._docs: Optional[Dict[str, List[Dict[str, Any]]]] = None
        self._errors: List[Tuple[str, str]] = []
        self._all: List[Dict[str, Any]] = []

    # scanning
    def _scan(self) -> None:
        if self._docs is not None:
            return
        found: List[Dict[str, Any]] = []
        errors: List[Tuple[str, str]] = []
        loose: List[Tuple[str, Any, bytes]] = []
        for rel in self._paths:
            base = self._root if rel in (".", "") else resolve_in_root(self._root, rel)
            prefix = "" if rel in (".", "") else str(safe_relative(rel))
            if base.is_file():
                data = _read_file(base, prefix)
                loose.append((prefix, _json(data), data))
                continue
            self._walk(base, prefix, found, errors, loose)
        found.extend(self._from_loose(loose, errors))
        keyed: Dict[str, List[Dict[str, Any]]] = {}
        for d in found:
            for k in d.pop("_keys", None) or ([d["digest"]] if d["digest"] else []):
                if d not in keyed.setdefault(k, []):
                    keyed[k].append(d)
        self._docs = keyed
        self._errors = sorted(set(errors))
        self._all = sorted(found, key=lambda d: (d["source"], d["digest"]))

    def _walk(self, base: Path, prefix: str, found: List[Dict[str, Any]], errors: List[Tuple[str, str]],
              loose: List[Tuple[str, Any, bytes]]) -> None:
        stack = [(base, prefix)]
        layouts: List[str] = []
        while stack:
            directory, pre = stack.pop()
            if _is_layout_dir(directory):
                layouts.append(pre)
                found.extend(_load_layout(directory, pre or ".", errors))
                continue
            try:
                names = sorted(os.listdir(directory))
            except OSError as exc:
                raise PathRefused(f"cannot list {pre or '.'}: {type(exc).__name__}", path=pre) from None
            for name in names:
                child = directory / name
                rel = f"{pre}/{name}" if pre else name
                st = _lstat_regular_or_dir(child, rel)
                if stat.S_ISDIR(st.st_mode):
                    if name != ".git":
                        stack.append((child, rel))
                elif name.lower().endswith(".json"):
                    data = _read_file(child, rel)
                    loose.append((rel, _json(data), data))

    def _from_loose(self, loose: List[Tuple[str, Any, bytes]], errors: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
        configs: Dict[str, Tuple[str, Mapping]] = {}
        manifests: List[Tuple[str, str, Mapping]] = []
        indexes: List[Tuple[str, str, Mapping]] = []
        sbom_dirs: Dict[str, List[Dict[str, str]]] = {}
        out: List[Dict[str, Any]] = []
        for rel, body, data in sorted(loose, key=lambda t: t[0]):
            digest = sha256_ref(data)
            if isinstance(body, list):
                for i, item in enumerate(body):
                    if isinstance(item, Mapping):
                        d = _build_inspect(item, rel, i)
                        if d is not None:
                            out.append(d)
                continue
            if not isinstance(body, Mapping):
                continue
            if "spdxVersion" in body or _s(body.get("bomFormat")).lower() == "cyclonedx":
                directory = rel.rsplit("/", 1)[0] if "/" in rel else ""
                sbom_dirs.setdefault(directory, []).append({"kind": "sbom", "predicate_type": "spdx" if "spdxVersion" in body else "cyclonedx",
                                                            "via": "colocated-file"})
                continue
            if isinstance(body.get("Config"), Mapping) and ("Id" in body or "RepoDigests" in body):
                d = _build_inspect(body, rel, 0)
                if d is not None:
                    out.append(d)
            elif body.get("schemaVersion") == 2 and isinstance(body.get("config"), Mapping) and isinstance(body.get("layers"), list):
                manifests.append((rel, digest, body))
            elif body.get("schemaVersion") == 2 and isinstance(body.get("manifests"), list):
                indexes.append((rel, digest, body))
            elif isinstance(body.get("rootfs"), Mapping) and (isinstance(body.get("config"), Mapping) or "architecture" in body):
                configs[digest] = (rel, body)
        used_configs = set()
        for rel, digest, body in manifests:
            cdig = _s(_m(body.get("config")).get("digest"))
            cfg = configs.get(cdig)
            problems = [] if cfg is not None else ["config_missing_or_unverified"]
            if cfg is not None:
                used_configs.add(cdig)
            directory = rel.rsplit("/", 1)[0] if "/" in rel else ""
            out.append(_build_image(digest, rel, body, cfg[1] if cfg else None, config_digest=cdig,
                                    attestations=sbom_dirs.get(directory, []), problems=problems))
        for rel, digest, body in indexes:
            d = _empty_doc(digest, rel, "index")
            d["media_type"] = _s(body.get("mediaType"))
            d["annotations"] = _pairs(body.get("annotations"))
            d["manifests"] = sorted(({"digest": _s(_m(x).get("digest")), "media_type": _s(_m(x).get("mediaType")),
                                      "platform": _platform(_m(x)), "artifact_type": _s(_m(x).get("artifactType")),
                                      "reference_type": ""} for x in _l(body.get("manifests"))), key=lambda x: (x["digest"], x["platform"]))
            out.append(d)
        for cdig, (rel, body) in sorted(configs.items()):
            if cdig in used_configs:
                continue
            d = _build_image(cdig, rel, {}, body, config_digest=cdig)
            d["kind"] = "config"
            d["layer_count"] = 0
            out.append(d)
        return out

    # access
    def get(self, digest: str) -> Optional[Mapping]:
        self._scan()
        docs = self._docs.get(digest, []) if self._docs is not None else []
        if not docs:
            return None
        if len(docs) > 1:
            raise ResourceAmbiguous("more than one image document has that digest", digest=digest, count=len(docs))
        return freeze(docs[0])

    def documents(self) -> Tuple[Mapping, ...]:
        self._scan()
        return tuple(freeze(d) for d in self._all)

    def errors(self) -> Tuple[Tuple[str, str], ...]:
        self._scan()
        return tuple(self._errors)
