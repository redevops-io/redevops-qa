# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Builders for synthetic OCI image layouts and loose image files, created at run time in a temporary directory.
Layer contents are placeholder bytes; nothing is pulled from a registry and no image is real."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
IN_TOTO = "application/vnd.in-toto+json"


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def dumps(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class Layout:
    def __init__(self, root: Path) -> None:
        self.root = root
        (root / "blobs" / "sha256").mkdir(parents=True, exist_ok=True)
        (root / "oci-layout").write_text(json.dumps({"imageLayoutVersion": "1.0.0"}), encoding="utf-8")
        self.descriptors: List[Dict[str, Any]] = []

    def put(self, data: bytes) -> str:
        d = sha(data)
        (self.root / "blobs" / "sha256" / d.split(":", 1)[1]).write_bytes(data)
        return d

    def desc(self, media_type: str, data: bytes, **extra: Any) -> Dict[str, Any]:
        return {"mediaType": media_type, "digest": self.put(data), "size": len(data), **extra}

    def write_index(self) -> None:
        (self.root / "index.json").write_text(json.dumps({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": self.descriptors}), encoding="utf-8")


def config_doc(*, user: Optional[str] = "10001", entrypoint: Optional[List[str]] = None, cmd: Optional[List[str]] = None, ports: Sequence[str] = ("8080/tcp",),
               healthcheck: Optional[Dict[str, Any]] = None, labels: Optional[Dict[str, str]] = None, env: Sequence[str] = ("PATH=/usr/bin", "MODE=prod"),
               layers: int = 2, arch: str = "amd64", workdir: str = "/app", volumes: Sequence[str] = (), history_cmds: Sequence[str] = ()) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {"Env": list(env), "WorkingDir": workdir}
    if user is not None:
        cfg["User"] = user
    if entrypoint is not None:
        cfg["Entrypoint"] = entrypoint
    if cmd is not None:
        cfg["Cmd"] = cmd
    if ports:
        cfg["ExposedPorts"] = {p: {} for p in ports}
    if healthcheck is not None:
        cfg["Healthcheck"] = healthcheck
    if labels:
        cfg["Labels"] = dict(labels)
    if volumes:
        cfg["Volumes"] = {v: {} for v in volumes}
    return {"architecture": arch, "os": "linux", "created": "2024-01-01T00:00:00Z", "config": cfg,
            "rootfs": {"type": "layers", "diff_ids": [sha(f"diff-{i}".encode()) for i in range(layers)]},
            "history": [{"created_by": c} for c in history_cmds] or [{"created_by": "placeholder"} for _ in range(layers)]}


def add_image(layout: Layout, *, layers: int = 2, annotations: Optional[Dict[str, str]] = None, ref_name: Optional[str] = None,
              write_layer_blobs: bool = True, **config_kwargs: Any) -> Dict[str, Any]:
    cfg = config_doc(layers=layers, **config_kwargs)
    cdesc = layout.desc(OCI_CONFIG, dumps(cfg))
    ldescs = []
    for i in range(layers):
        body = f"layer-{i}".encode()
        ldescs.append(layout.desc(OCI_LAYER, body) if write_layer_blobs else {"mediaType": OCI_LAYER, "digest": sha(body), "size": len(body)})
    manifest = {"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": cdesc, "layers": ldescs}
    if annotations:
        manifest["annotations"] = dict(annotations)
    mbytes = dumps(manifest)
    mdesc = layout.desc(OCI_MANIFEST, mbytes)
    ann = {"org.opencontainers.image.ref.name": ref_name} if ref_name else {}
    layout.descriptors.append({**mdesc, **({"annotations": ann} if ann else {}), "platform": {"os": "linux", "architecture": cfg["architecture"]}})
    layout.write_index()
    return {"manifest_digest": mdesc["digest"], "config_digest": cdesc["digest"], "manifest": manifest, "config": cfg}


def add_buildx_attestation(layout: Layout, subject_digest: str, predicate_type: str = "https://spdx.dev/Document") -> str:
    stmt = dumps({"_type": "https://in-toto.io/Statement/v0.1", "predicateType": predicate_type, "predicate": {}})
    sdesc = layout.desc(IN_TOTO, stmt, annotations={"in-toto.io/predicate-type": predicate_type})
    cfg = layout.desc("application/vnd.oci.empty.v1+json", b"{}")
    manifest = {"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": cfg, "layers": [sdesc]}
    mdesc = layout.desc(OCI_MANIFEST, dumps(manifest))
    layout.descriptors.append({**mdesc, "annotations": {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": subject_digest},
                               "platform": {"os": "unknown", "architecture": "unknown"}})
    layout.write_index()
    return mdesc["digest"]


def add_referrer(layout: Layout, subject_digest: str, artifact_type: str = "application/spdx+json") -> str:
    body = layout.desc(artifact_type, b'{"spdxVersion":"SPDX-2.3"}')
    cfg = layout.desc("application/vnd.oci.empty.v1+json", b"{}")
    manifest = {"schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": artifact_type, "config": cfg, "layers": [body],
                "subject": {"mediaType": OCI_MANIFEST, "digest": subject_digest, "size": 1}}
    mdesc = layout.desc(OCI_MANIFEST, dumps(manifest))
    layout.descriptors.append({**mdesc, "artifactType": artifact_type})
    layout.write_index()
    return mdesc["digest"]


def inspect_doc(*, user: str = "1000", repo_digest: Optional[str] = None, ident: Optional[str] = None, tags: Sequence[str] = ("app:1",),
                ports: Sequence[str] = ("80/tcp",), labels: Optional[Dict[str, str]] = None, layers: int = 3) -> Dict[str, Any]:
    ident = ident or sha(b"image-id-" + user.encode())
    cfg: Dict[str, Any] = {"User": user, "ExposedPorts": {p: {} for p in ports}, "Env": ["A=1"], "Labels": dict(labels or {})}
    out: Dict[str, Any] = {"Id": ident, "RepoTags": list(tags), "Architecture": "arm64", "Os": "linux", "Config": cfg,
                           "RootFS": {"Type": "layers", "Layers": [sha(f"l{i}".encode()) for i in range(layers)]}}
    if repo_digest:
        out["RepoDigests"] = [f"registry.example.test/team/app@{repo_digest}"]
    return out
