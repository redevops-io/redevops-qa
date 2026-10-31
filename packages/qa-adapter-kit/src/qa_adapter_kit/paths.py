# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Path allowlist. Every path a run reads or writes is resolved against the real file system (symlinks followed) and must lie
inside one of the allowed roots; a deny list is applied on top, so that a mistaken root cannot expose credentials or the Docker
socket."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Sequence

from .errors import PathRefused

DENIED_COMPONENTS = frozenset({".ssh", ".aws", ".gnupg", ".docker", ".kube", ".azure", ".config", ".netrc", ".git-credentials",
                               ".npmrc", ".pypirc"})
DENIED_NAMES = ("docker.sock", "containerd.sock", "podman.sock", "id_rsa", "id_ed25519", "id_ecdsa", "credentials")
DENIED_PREFIXES = ("/etc", "/proc", "/sys", "/dev", "/run", "/var/run", "/root", "/boot", "/private/etc", "/private/var/run")


def is_denied(path: str) -> bool:
    """True for a path that must never be handed to an adapter, whatever the allowed roots say. The path is not resolved here."""
    norm = os.path.normpath(path)
    for prefix in DENIED_PREFIXES:
        if norm == prefix or norm.startswith(prefix + "/"):
            return True
    parts = Path(norm).parts
    if any(part in DENIED_COMPONENTS for part in parts):
        return True
    last = parts[-1] if parts else ""
    return any(last == n or last.startswith(n + ".") for n in DENIED_NAMES)


class PathPolicy:
    def __init__(self, allowed_roots: Sequence[os.PathLike | str]):
        roots: List[Path] = []
        for root in allowed_roots:
            real = Path(os.path.realpath(root))
            if not real.is_absolute() or real == Path("/") or is_denied(str(real)):
                raise PathRefused(f"{root!s} cannot be an allowed root")
            roots.append(real)
        if not roots:
            raise PathRefused("at least one allowed root is needed")
        self.roots = tuple(roots)

    def resolve(self, path: os.PathLike | str, *, base: os.PathLike | str | None = None, must_exist: bool = False) -> Path:
        """The real path of ``path`` (relative paths are taken from ``base``), or ``PathRefused``."""
        text = os.fspath(path)
        if "\x00" in text:
            raise PathRefused("a path contains a NUL byte")
        raw = Path(text) if base is None or os.path.isabs(text) else Path(base) / text
        if not raw.is_absolute():
            raise PathRefused("a relative path needs a base")
        real = Path(os.path.realpath(raw))
        if is_denied(str(raw)) or is_denied(str(real)):
            raise PathRefused("the path is on the prohibited list")
        if not any(real == root or root in real.parents for root in self.roots):
            raise PathRefused("the path is outside the allowed roots")
        if must_exist and not real.exists():
            raise PathRefused("the path does not exist")
        return real

    def resolve_all(self, paths: Iterable[os.PathLike | str], **kw) -> List[Path]:
        return [self.resolve(p, **kw) for p in paths]
