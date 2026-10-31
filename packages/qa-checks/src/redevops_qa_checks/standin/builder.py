# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Deterministic build contexts for stand-in images.

The builder takes a list of ``{name, tag, port, health_path}`` as configuration and returns, for each entry, the files of a
build context (a Dockerfile on the pinned ``python:3.12-slim`` digest, the stand-in server, a configuration file) and a hash of
that context. It runs no build, has no registry code and cannot push: images are built and loaded into the local cluster by
whoever runs bring-up, under the registry names and tags the manifests use, and their digests are recorded then. Nothing is
copied from any repository; the only inputs are the entries.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

from ..canonical import canonical_bytes, sha256_ref
from ..errors import CheckError
from ..tierk.plan import STAND_IN_BASE

MAX_ENTRIES = 32
_NAME = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*){0,3}")
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")
SERVER_SOURCE = (Path(__file__).resolve().parent / "server.py").read_bytes().replace(b"\r\n", b"\n")


class StandInRefused(CheckError):
    code = "STANDIN_REFUSED"


def _check(entry: Mapping[str, Any], seen: set) -> Dict[str, Any]:
    if set(entry) != {"name", "tag", "port", "health_path"}:
        raise StandInRefused("an entry has exactly name, tag, port and health_path")
    name, tag, port, health = entry["name"], entry["tag"], entry["port"], entry["health_path"]
    if type(name) is not str or not _NAME.fullmatch(name) or len(name) > 128:
        raise StandInRefused("the image name is not a valid repository name", name=str(name)[:60])
    if type(tag) is not str or not _TAG.fullmatch(tag) or tag == "latest":
        raise StandInRefused("the tag must be a pinned tag, never latest", tag=str(tag)[:40])
    if type(port) is not int or isinstance(port, bool) or not 1 <= port <= 65535:
        raise StandInRefused("the port is out of range")
    if type(health) is not str or not health.startswith("/") or len(health) > 100 or not re.fullmatch(r"/[A-Za-z0-9._~/%-]*", health):
        raise StandInRefused("the health path is not a plain absolute path")
    key = f"{name}:{tag}"
    if key in seen:
        raise StandInRefused("duplicate image entry", image=key)
    seen.add(key)
    return {"name": name, "tag": tag, "port": port, "health_path": health}


def dockerfile(port: int, health_path: str) -> str:
    return "\n".join([
        f"FROM {STAND_IN_BASE['image']}@{STAND_IN_BASE['digest']}",
        "RUN useradd --system --uid 10001 --no-create-home standin",
        "COPY server.py /app/server.py",
        f"ENV STANDIN_PORT={port}",
        f"ENV STANDIN_HEALTH_PATH={health_path}",
        f"EXPOSE {port}",
        "USER 10001",
        'ENTRYPOINT ["python", "/app/server.py"]', ""])


def build_contexts(entries: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """For each entry: ``{image, files: {name: bytes}, context_sha256, base}``. The order of the input is kept."""
    if not isinstance(entries, (list, tuple)) or not 1 <= len(entries) <= MAX_ENTRIES:
        raise StandInRefused(f"between 1 and {MAX_ENTRIES} entries are expected")
    seen: set = set()
    out = []
    for raw in entries:
        e = _check(raw, seen)
        config = canonical_bytes({"name": e["name"], "tag": e["tag"], "port": e["port"], "health_path": e["health_path"]})
        files = {"Dockerfile": dockerfile(e["port"], e["health_path"]).encode("utf-8"), "server.py": SERVER_SOURCE, "config.json": config}
        ctx = sha256_ref(canonical_bytes({k: sha256_ref(v) for k, v in sorted(files.items())}))
        out.append({"image": f"{e['name']}:{e['tag']}", "files": files, "context_sha256": ctx, "base": dict(STAND_IN_BASE),
                    "image_digest": None, "image_digest_note": "recorded by whoever builds and loads the image; never pushed"})
    return out


def write_contexts(entries: Sequence[Mapping[str, Any]], destination: Path) -> List[Path]:
    """Write each context to ``destination/<n>-<name>`` (a new, empty directory the caller made). Refuses anything else."""
    dest = Path(destination)
    if not dest.is_dir() or any(dest.iterdir()):
        raise StandInRefused("the destination must be an existing empty directory")
    paths = []
    for i, ctx in enumerate(build_contexts(entries)):
        d = dest / f"{i:02d}-{ctx['image'].replace('/', '_').replace(':', '_')}"
        d.mkdir()
        for name, data in ctx["files"].items():
            (d / name).write_bytes(data)
        paths.append(d)
    return paths
