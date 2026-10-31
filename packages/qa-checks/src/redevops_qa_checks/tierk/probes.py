# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The fixed probe workloads.

A probe is one Pod built from a single constant specification: the stand-in base image by digest (loaded into the cluster, never
pulled, never pushed), a constant command that makes one TCP connection to an IP literal and prints one JSON line, a restricted
security context, small resources and a deadline. Only an IP literal, a port and a timeout vary, and the pod name is derived from
them. ``ProbePolicy`` accepts a manifest only if it is *exactly* what ``probe_pod`` builds for the values it carries; anything else
(another image, another command, a mount, a host setting, an extra field) is refused. This module is hashed into the connectivity
programs.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Mapping
from typing import Any, Dict

from ..errors import PolicyBlocked
from .argv import PROBE_POD_PATTERN
from .plan import STAND_IN_BASE

MANAGED_BY = "redevops-qa-checks"
MAX_TIMEOUT_S = 10
IMAGE = f"{STAND_IN_BASE['image']}@{STAND_IN_BASE['digest']}"

#: the whole probe: one TCP connection to an IP literal, one JSON line on stdout
PROBE_SOURCE = (
    "import ipaddress, json, socket, sys\n"
    "res = {'result': 'error', 'errno': 0}\n"
    "try:\n"
    "    ip = str(ipaddress.ip_address(sys.argv[1]))\n"
    "    port = int(sys.argv[2])\n"
    "    if sys.argv[3] != 'tcp':\n"
    "        res['result'] = 'unsupported'\n"
    "    else:\n"
    "        s = socket.create_connection((ip, port), timeout=float(sys.argv[4]))\n"
    "        s.close()\n"
    "        res['result'] = 'connected'\n"
    "except socket.timeout:\n"
    "    res['result'] = 'timeout'\n"
    "except ConnectionRefusedError:\n"
    "    res['result'] = 'refused'\n"
    "except OSError as exc:\n"
    "    res['errno'] = exc.errno or 0\n"
    "    res['result'] = 'unreachable' if exc.errno in (101, 113) else 'error'\n"
    "except Exception:\n"
    "    res['result'] = 'error'\n"
    "print(json.dumps(res))\n"
)


def probe_name(namespace: str, ip: str, port: int, timeout_s: int, role: str) -> str:
    digest = hashlib.sha256(json.dumps([namespace, ip, port, timeout_s, role], separators=(",", ":")).encode()).hexdigest()
    return "qa-probe-" + digest[:12]


def probe_pod(namespace: str, ip: str, port: int, *, timeout_s: int = 5, role: str = "probe", labels: Mapping[str, str] = ()) -> Dict[str, Any]:
    """The one probe specification. ``labels`` are the source workload's labels, so the probe is subject to the policies that apply to it."""
    if type(ip) is not str:
        raise PolicyBlocked("a probe target is an IP literal", guard_code="PROBE_BOUNDS")
    ip = str(ipaddress.ip_address(ip))
    if not (isinstance(port, int) and 1 <= port <= 65535) or not (isinstance(timeout_s, int) and 1 <= timeout_s <= MAX_TIMEOUT_S):
        raise PolicyBlocked("probe port or timeout out of bounds", guard_code="PROBE_BOUNDS")
    lab = {str(k): str(v) for k, v in dict(labels).items()}
    lab.update({"app.kubernetes.io/managed-by": MANAGED_BY, "qa-checks/probe-role": role})
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": probe_name(namespace, ip, port, timeout_s, role), "namespace": namespace, "labels": lab},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False, "activeDeadlineSeconds": timeout_s + 25,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "probe", "image": IMAGE, "imagePullPolicy": "Never",
                                     "command": ["python", "-c", PROBE_SOURCE], "args": [ip, str(port), "tcp", str(timeout_s)],
                                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}},
                                     "resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"cpu": "100m", "memory": "64Mi"}}}]}}


class ProbePolicy:
    """Accepts exactly the probe pods ``probe_pod`` builds. Used as the session's probe policy."""

    def __call__(self, doc: Mapping[str, Any]) -> None:
        try:
            md, spec = doc["metadata"], doc["spec"]
            c = spec["containers"][0]
            ip, port, _tcp, timeout = c["args"]
            role = md["labels"]["qa-checks/probe-role"]
            labels = {k: v for k, v in md["labels"].items() if k not in ("app.kubernetes.io/managed-by", "qa-checks/probe-role")}
            rebuilt = probe_pod(md["namespace"], ip, int(port), timeout_s=int(timeout), role=role, labels=labels)
        except (KeyError, IndexError, TypeError, ValueError, AttributeError):
            raise PolicyBlocked("not a probe specification", guard_code="PROBE_SPEC_REFUSED") from None
        if json.dumps(rebuilt, sort_keys=True) != json.dumps(_plain(doc), sort_keys=True) or not PROBE_POD_PATTERN.fullmatch(md["name"]):
            raise PolicyBlocked("the manifest is not the fixed probe specification", guard_code="PROBE_SPEC_REFUSED")


def _plain(v: Any) -> Any:
    if isinstance(v, Mapping):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    return v
