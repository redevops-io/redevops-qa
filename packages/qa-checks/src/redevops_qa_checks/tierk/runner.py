# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The kubectl runner protocol and the real runner (disabled unless explicitly enabled on an acknowledged disposable host).

``KubectlRunner`` is what the drivers are written against; tests use a fake. ``RealKubectlRunner`` shells out to ``kubectl`` with
a fixed argument vector built from an allow-listed command, the generated kubeconfig of a lane, an empty environment and a
timeout. It cannot be constructed unless:

* the real lane is enabled in the configuration (the default is disabled),
* a disposable-host acknowledgement file inside the state directory is valid for *this* host,
* a ``LocalCluster`` produced by the guard is given (so the kubeconfig and context are the generated ones).

It is not reachable on its own: drivers only receive a ``GuardedSession`` (see ``guard``), which also re-reads the cluster's
marker object before every command.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence, Tuple, runtime_checkable

from ..errors import LimitExceeded, PolicyBlocked
from .argv import validate_argv
from .guard import LocalCluster, _SEAL, check_state_dir

ACK_FILE = "host-acknowledgement.json"
ACK_SCHEMA = "qa-checks/disposable-host-ack/1"
ACK_STATEMENT = ("This host is dedicated to disposable test clusters, has no route to non-disposable systems and holds no credentials.")
ACK_CHECKS = ("dedicated_host", "no_route_to_non_disposable_systems", "no_credentials_present", "no_shared_container_socket")
MAX_OUTPUT = 8 * 1024 * 1024


@dataclass(frozen=True)
class KubectlResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@runtime_checkable
class KubectlRunner(Protocol):
    def run(self, args: Sequence[str], *, stdin: Optional[str] = None, timeout_s: int = 60) -> KubectlResult: ...


@dataclass(frozen=True)
class TierKConfig:
    """Configuration of the real lane. ``real_lane_enabled`` is false unless somebody sets it."""
    real_lane_enabled: bool = False
    kubectl_path: Optional[str] = None
    sandbox_networks: Tuple[str, ...] = ()


def host_fingerprint() -> str:
    return hashlib.sha256(f"{platform.node()}|{platform.system()}|{platform.machine()}".encode("utf-8")).hexdigest()


def write_acknowledgement(state_dir: Path, *, acknowledged_by: str, runtime: str) -> Path:
    """Write the acknowledgement for *this* host (a person runs this on the disposable host; nothing calls it automatically)."""
    state = check_state_dir(state_dir)
    doc = {"schema": ACK_SCHEMA, "statement": ACK_STATEMENT, "acknowledged_by": acknowledged_by, "runtime": runtime,
           "host_fingerprint": host_fingerprint(), "isolation_checks": {k: True for k in ACK_CHECKS}}
    (state / ACK_FILE).write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
    return state / ACK_FILE


def check_acknowledgement(state_dir: Path) -> Dict[str, Any]:
    """The acknowledgement, if it is present, exact, complete and made on this host; ``PolicyBlocked`` otherwise."""
    state = check_state_dir(state_dir)
    path = state / ACK_FILE
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise ValueError
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise PolicyBlocked("the real lane needs a disposable-host acknowledgement and none is configured", guard_code="ACK_MISSING") from None
    except (OSError, ValueError):
        raise PolicyBlocked("the disposable-host acknowledgement is not a valid file", guard_code="ACK_INVALID") from None
    checks = doc.get("isolation_checks") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or doc.get("schema") != ACK_SCHEMA or doc.get("statement") != ACK_STATEMENT \
            or type(doc.get("acknowledged_by")) is not str or not doc["acknowledged_by"].strip() \
            or type(doc.get("runtime")) is not str or not doc["runtime"].strip() \
            or not isinstance(checks, dict) or set(checks) != set(ACK_CHECKS) or any(checks[k] is not True for k in ACK_CHECKS):
        raise PolicyBlocked("the disposable-host acknowledgement is incomplete or not the required statement", guard_code="ACK_INVALID")
    if doc.get("host_fingerprint") != host_fingerprint():
        raise PolicyBlocked("the acknowledgement was made on another host", guard_code="ACK_OTHER_HOST")
    return doc


class RealKubectlRunner:
    """Runs ``kubectl`` for one generated cluster. Disabled by default; see the module documentation."""

    def __init__(self, local: LocalCluster, config: TierKConfig) -> None:
        if not isinstance(local, LocalCluster) or local._seal is not _SEAL:
            raise PolicyBlocked("a runner needs the guard's local check result", guard_code="LOCAL_CLUSTER_FORGED")
        if config.real_lane_enabled is not True:
            raise PolicyBlocked("the real cluster lane is disabled", guard_code="REAL_LANE_DISABLED")
        check_acknowledgement(local.state_dir)
        path = config.kubectl_path
        if type(path) is not str or not os.path.isabs(path) or ".." in Path(path).parts:
            raise PolicyBlocked("the kubectl path must be an absolute path set in the configuration", guard_code="KUBECTL_PATH")
        try:
            st = os.lstat(path)
        except OSError:
            raise PolicyBlocked("the configured kubectl does not exist", guard_code="KUBECTL_PATH") from None
        if not stat.S_ISREG(st.st_mode) or not os.access(path, os.X_OK):
            raise PolicyBlocked("the configured kubectl is not an executable file", guard_code="KUBECTL_PATH")
        self._kubectl = path
        self._kubeconfig = str(local.kubeconfig_path)
        self._context = local.entry.context_name
        self._home = local.state_dir / "home"
        self._home.mkdir(mode=0o700, exist_ok=True)

    def _argv(self, args: Sequence[str]) -> List[str]:
        validate_argv(args)                                   # again: the runner does not trust its caller
        return [self._kubectl, "--kubeconfig", self._kubeconfig, "--context", self._context, "--request-timeout=30s", *args]

    def run(self, args: Sequence[str], *, stdin: Optional[str] = None, timeout_s: int = 60) -> KubectlResult:
        argv = self._argv(args)
        env = {"HOME": str(self._home), "PATH": "/usr/bin:/bin", "KUBECONFIG": self._kubeconfig, "LANG": "C"}
        try:
            proc = subprocess.run(argv, input=stdin, env=env, cwd=str(self._home), capture_output=True, text=True, timeout=timeout_s,
                                  check=False, shell=False)
        except subprocess.TimeoutExpired:
            return KubectlResult(124, "", "timed out")
        if len(proc.stdout) > MAX_OUTPUT or len(proc.stderr) > MAX_OUTPUT:
            raise LimitExceeded("kubectl output is too large")
        return KubectlResult(proc.returncode, proc.stdout, proc.stderr)
