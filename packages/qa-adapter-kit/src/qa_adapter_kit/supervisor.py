# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The shared process supervisor of the suite adapters.

What it enforces, before and during a run:

* an executable allowlist (absolute paths from the manifest, compared after symlink resolution) and, in a sealed run, the
  manifest's pinned files hashed before anything starts;
* a deadline, a per-stream output limit and cancellation, each ending the whole process group (terminate, a grace period, kill);
* an environment built from nothing: the parent environment is never inherited; only the names the manifest allows pass, and
  names that look like credentials, Docker, cloud or Git hosting variables are refused;
* no host Docker socket and no container engine as an executable, and no installer or downloader as an executable in a sealed run.

What it does not enforce: network isolation. ``AdapterManifest.network`` is a declaration for the worker (a network namespace, an
egress gateway); a process started here can still open sockets if the worker allows it. POSIX only (process groups).
"""
from __future__ import annotations

import hashlib
import os
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Mapping, Optional, Sequence, Tuple

from .errors import PolicyRefused
from .models import AdapterManifest, Limits
from .paths import PathPolicy, is_denied
from .status import ErrorCode

CONTAINER_ENGINES = frozenset({"docker", "dockerd", "podman", "nerdctl", "ctr", "crictl", "buildah", "containerd", "runc"})
DOWNLOADERS = frozenset({"pip", "pip3", "pipx", "uv", "poetry", "conda", "mamba", "npm", "npx", "yarn", "pnpm", "bun", "curl", "wget", "aria2c",
                         "apt", "apt-get", "aptitude", "dnf", "yum", "apk", "brew", "gem", "cargo", "go", "git", "svn", "hg", "scp", "rsync"})
INSTALL_MODULES = frozenset({"pip", "ensurepip", "venv", "virtualenv", "pipx", "get_pip"})
_CREDENTIAL_NAME = re.compile(r"(?i)(TOKEN|SECRET|PASSW|CREDENTIAL|PRIVATE|API_?KEY|AUTH|COOKIE|SESSION)")
# never passed to a child, plain or secret: loader, shell, runtime and container variables, and cloud or code-hosting credentials
_FORBIDDEN_ENV = re.compile(r"^(DOCKER_|CONTAINER|SSH_|GPG_|LD_|DYLD_|BASH_ENV$|ENV$|IFS$|PATH$|HOME$|SHELL$|TMPDIR$|PYTHON|PIP_|NPM_CONFIG_|"
                            r"AWS_|AZURE_|GOOGLE_|GCP_|GCLOUD|GH_|GITHUB_|GITLAB_|KUBE|NPM_TOKEN)")
_MAX_ARGV = 256
_MAX_ARG = 4096


@dataclass(frozen=True)
class CommandSpec:
    argv: Tuple[str, ...]
    cwd: str
    extra_env: Mapping[str, str] = field(default_factory=dict)      # adapter-chosen names, checked like the request's


@dataclass
class CancelToken:
    """Set from any thread; the supervisor ends the process group at its next poll (50 ms)."""

    _event: threading.Event = field(default_factory=threading.Event)

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


@dataclass(frozen=True)
class ProcessOutcome:
    exit_code: Optional[int]
    signal: Optional[int]
    stdout: bytes
    stderr: bytes
    duration_s: float
    error_code: Optional[ErrorCode] = None
    error_message: str = ""
    group_terminated: bool = False


# ------------------------------------------------------------------------------------------------ checks before a start
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_command(manifest: AdapterManifest, spec: CommandSpec, policy: PathPolicy, *, sealed: bool) -> None:
    argv = spec.argv
    if not argv or len(argv) > _MAX_ARGV:
        raise PolicyRefused("the command is empty or has too many arguments", ErrorCode.INVALID_REQUEST)
    for arg in argv:
        if not isinstance(arg, str) or "\x00" in arg or len(arg) > _MAX_ARG:
            raise PolicyRefused("an argument is not a bounded string", ErrorCode.INVALID_REQUEST)
        if "docker.sock" in arg or "containerd.sock" in arg or "podman.sock" in arg:
            raise PolicyRefused("a container socket cannot be handed to an adapter", ErrorCode.DOCKER_REFUSED)
        candidate = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
        if candidate.startswith("/") and is_denied(candidate):
            raise PolicyRefused("an argument names a prohibited path", ErrorCode.PROHIBITED_PATH)
    exe = argv[0]
    if not os.path.isabs(exe):
        raise PolicyRefused("the executable must be an absolute path", ErrorCode.EXECUTABLE_NOT_ALLOWED)
    real_exe = os.path.realpath(exe)
    base = os.path.basename(real_exe).lower()
    shown = os.path.basename(exe).lower()
    if base in CONTAINER_ENGINES or shown in CONTAINER_ENGINES:
        raise PolicyRefused("a container engine cannot be started by an adapter (no host Docker socket)", ErrorCode.DOCKER_REFUSED)
    allowed = {os.path.realpath(p) for p in manifest.allowed_executables}
    if real_exe not in allowed:
        raise PolicyRefused("the executable is not in the manifest's allowlist", ErrorCode.EXECUTABLE_NOT_ALLOWED)
    if sealed:
        if manifest.downloads:
            raise PolicyRefused("an adapter that downloads at run time cannot run sealed", ErrorCode.DOWNLOAD_REFUSED)
        stem = re.sub(r"[0-9.]+$", "", base)
        if base in DOWNLOADERS or shown in DOWNLOADERS or stem in DOWNLOADERS:
            raise PolicyRefused("an installer or downloader cannot run in a sealed run", ErrorCode.DOWNLOAD_REFUSED)
        for i in range(1, len(argv) - 1):
            if argv[i] == "-m" and argv[i + 1].split(".")[0] in INSTALL_MODULES:
                raise PolicyRefused("an installer module cannot run in a sealed run", ErrorCode.DOWNLOAD_REFUSED)
        verify_pins(manifest)
    policy.resolve(spec.cwd, must_exist=True)


def verify_pins(manifest: AdapterManifest) -> None:
    """Every pinned file exists and has the recorded SHA-256; a sealed run starts nothing otherwise."""
    for pinned in manifest.pinned_files:
        try:
            got = sha256_file(pinned.path)
        except OSError:
            raise PolicyRefused(f"pinned file {pinned.path} cannot be read", ErrorCode.PIN_MISMATCH) from None
        if got != pinned.sha256:
            raise PolicyRefused(f"pinned file {pinned.path} does not match its recorded digest", ErrorCode.PIN_MISMATCH)


def build_env(manifest: AdapterManifest, *, env: Mapping[str, str], secret_env: Mapping[str, str], extra: Mapping[str, str],
              home: str, sealed: bool) -> Dict[str, str]:
    """The child environment. Nothing is inherited. A name must be allowlisted by the manifest and must not be a credential or
    container variable; a secret goes in only through ``secret_env`` and only if the manifest names it."""
    out: Dict[str, str] = {"PATH": "/usr/bin:/bin", "HOME": home, "TMPDIR": home, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
                           "NO_COLOR": "1"}
    if sealed:
        out.update({"PIP_NO_INDEX": "1", "NPM_CONFIG_OFFLINE": "true"})
    for name, value in env.items():
        if name not in manifest.env_allowlist:
            raise PolicyRefused(f"environment variable {name} is not allowed by the manifest", ErrorCode.ENV_REFUSED)
        if _FORBIDDEN_ENV.match(name) or _CREDENTIAL_NAME.search(name):
            raise PolicyRefused(f"environment variable {name} is refused (credential-like, cloud, container or loader variable); "
                                "a secret goes through secret_env", ErrorCode.ENV_REFUSED)
        out[name] = value
    for name, value in secret_env.items():
        if name not in manifest.secret_env_allowlist:
            raise PolicyRefused(f"secret variable {name} is not allowed by the manifest", ErrorCode.ENV_REFUSED)
        if _FORBIDDEN_ENV.match(name):
            raise PolicyRefused(f"secret variable {name} is refused (cloud, container or loader variable)", ErrorCode.ENV_REFUSED)
        out[name] = value
    for name, value in extra.items():
        if name not in manifest.env_allowlist or _FORBIDDEN_ENV.match(name) or _CREDENTIAL_NAME.search(name):
            raise PolicyRefused(f"the adapter asked for environment variable {name}, which the manifest does not allow", ErrorCode.ENV_REFUSED)
        out[name] = value
    return out


# ------------------------------------------------------------------------------------------------ running
def _kill_group(pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def run_supervised(argv: Sequence[str], *, cwd: str, env: Mapping[str, str], limits: Limits, cancel: Optional[CancelToken] = None,
                   clock: Callable[[], float] = time.monotonic) -> ProcessOutcome:
    """Run one command to completion or to the first limit. The child leads its own session, so every signal goes to the group
    (grandchildren included); after the leader exits, a final kill removes any survivor of the group."""
    start = clock()
    try:
        proc = subprocess.Popen(list(argv), cwd=cwd, env=dict(env), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, close_fds=True)
    except OSError as exc:
        return ProcessOutcome(None, None, b"", b"", clock() - start, ErrorCode.SPAWN_FAILED, f"could not start the process ({type(exc).__name__})")
    pgid = proc.pid
    buffers = {"out": bytearray(), "err": bytearray()}
    over = threading.Event()

    def pump(stream, key: str) -> None:
        buf = buffers[key]
        try:
            while True:
                chunk = stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536)
                if not chunk:
                    return
                room = limits.output_limit_bytes - len(buf)
                buf.extend(chunk[:max(room, 0)])
                if len(chunk) > room:
                    over.set()
                    return
        except (OSError, ValueError):
            return

    threads = [threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True)]
    for t in threads:
        t.start()
    deadline = start + limits.deadline_s
    reason: Optional[ErrorCode] = None
    terminated = False
    while True:
        try:
            proc.wait(timeout=0.05)
            break
        except subprocess.TimeoutExpired:
            pass
        if cancel is not None and cancel.cancelled:
            reason = ErrorCode.CANCELLED
        elif over.is_set():
            reason = ErrorCode.OUTPUT_LIMIT
        elif clock() >= deadline:
            reason = ErrorCode.TIMEOUT
        if reason is not None:
            terminated = True
            _kill_group(pgid, signal.SIGTERM)
            try:
                proc.wait(timeout=limits.kill_grace_s)
            except subprocess.TimeoutExpired:
                pass
            _kill_group(pgid, signal.SIGKILL)       # also reached when the leader obeyed but a child did not
            proc.wait()
            break
    if over.is_set() and reason is None:
        reason = ErrorCode.OUTPUT_LIMIT
    _kill_group(pgid, signal.SIGKILL)               # a group member that outlived the leader
    for t in threads:
        t.join(timeout=2.0)
    for stream in (proc.stdout, proc.stderr):
        try:
            stream.close()
        except OSError:
            pass
    rc = proc.returncode
    messages = {ErrorCode.TIMEOUT: f"the deadline of {limits.deadline_s:g}s passed", ErrorCode.CANCELLED: "the run was cancelled",
                ErrorCode.OUTPUT_LIMIT: f"output exceeded {limits.output_limit_bytes} bytes on a stream"}
    return ProcessOutcome(exit_code=rc if rc is not None and rc >= 0 else None, signal=-rc if rc is not None and rc < 0 else None,
                          stdout=bytes(buffers["out"]), stderr=bytes(buffers["err"]), duration_s=clock() - start, error_code=reason,
                          error_message=messages.get(reason, ""), group_terminated=terminated)
