# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The allow-list of kubectl argument vectors.

A command is allowed only if it has exactly the shape of one rule below. Rules are structural (fixed positions, fixed flags,
validated names); nothing is matched by prefix and no flag is passed through. In particular there is no way to select another
kubeconfig, context, server, user, token, proxy or impersonation: those are fixed by the runner. Secrets are not readable.
Server-side dry-run persists nothing. The only commands that persist anything are the probe rules, which are confined to
namespaces that start with ``qa-probe-`` and are refused unless the session was opened with probe mutation enabled.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

from ..errors import PolicyBlocked

PROBE_NAMESPACE_PREFIX = "qa-probe-"
MARKER_NAMESPACE = "qa-disposable-system"
MARKER_NAME = "qa-disposable-marker"
MAX_ARGS = 14
MAX_ARG_LEN = 200
MAX_WAIT_SECONDS = 300

READ_KINDS = frozenset({
    "configmap", "namespace", "node", "pod", "deployment", "daemonset", "service", "endpoints", "endpointslice", "resourcequota", "limitrange",
    "networkpolicy", "event", "customresourcedefinition", "gatewayclass.gateway.networking.k8s.io", "gateway.gateway.networking.k8s.io",
    "httproute.gateway.networking.k8s.io", "grpcroute.gateway.networking.k8s.io", "ciliumnetworkpolicy.cilium.io",
    "ciliumclusterwidenetworkpolicy.cilium.io", "ciliumendpoint.cilium.io", "clusterpolicy.kyverno.io", "policy.kyverno.io",
    "validatingwebhookconfiguration", "mutatingwebhookconfiguration", "ipaddresspool.metallb.io", "backendtrafficpolicy.gateway.envoyproxy.io",
    "httproutefilter.gateway.envoyproxy.io",
})
CONDITIONS = frozenset({"Ready", "Available", "Established", "Accepted", "Programmed", "ResolvedRefs", "Complete", "Initialized"})

_NAME = re.compile(r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?")
_LABEL_NS = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")
_SELECTOR = re.compile(r"[A-Za-z0-9._/-]{1,63}=[A-Za-z0-9._-]{0,63}(,[A-Za-z0-9._/-]{1,63}=[A-Za-z0-9._-]{0,63}){0,5}")
_WAIT_KIND = re.compile(r"[a-z]{2,40}(\.[a-z0-9.]{2,60})?/[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?")


@dataclass(frozen=True)
class ArgvDecision:
    rule: str
    mutating: bool
    stdin_required: bool
    namespace: Optional[str] = None


def _refuse(code: str, message: str, args: Sequence[str]) -> PolicyBlocked:
    return PolicyBlocked(message, rule_code=code, verb=(args[0] if args and isinstance(args[0], str) else ""))


def _basic(args: Sequence[str]) -> None:
    if not isinstance(args, (list, tuple)) or not args or len(args) > MAX_ARGS:
        raise _refuse("ARGV_SHAPE", "a kubectl command is a non-empty list of at most %d arguments" % MAX_ARGS, args if isinstance(args, (list, tuple)) else ())
    for a in args:
        if type(a) is not str or not a or len(a) > MAX_ARG_LEN or "\x00" in a or "\n" in a or "\r" in a:
            raise _refuse("ARGV_SHAPE", "every argument is a short non-empty single-line string", args)


def _ns(value: str, args: Sequence[str]) -> str:
    if not _LABEL_NS.fullmatch(value):
        raise _refuse("ARGV_NAMESPACE", "not a namespace name", args)
    return value


def _probe_ns(value: str, args: Sequence[str]) -> str:
    _ns(value, args)
    if not value.startswith(PROBE_NAMESPACE_PREFIX) or len(value) <= len(PROBE_NAMESPACE_PREFIX):
        raise _refuse("ARGV_NAMESPACE_NOT_PROBE", "persisting commands are confined to probe namespaces", args)
    return value


def _get(args: Sequence[str]) -> ArgvDecision:
    # get KIND [NAME] [-n NS | -A] [-l SELECTOR] -o json
    rest = list(args[1:])
    if len(rest) < 3 or rest[-2:] != ["-o", "json"]:
        raise _refuse("ARGV_GET_SHAPE", "get must end with -o json", args)
    rest = rest[:-2]
    kind = rest.pop(0)
    if kind not in READ_KINDS:
        raise _refuse("ARGV_KIND_NOT_READABLE", "this kind is not on the read allow-list", args)
    name = None
    if rest and not rest[0].startswith("-"):
        name = rest.pop(0)
        if not _NAME.fullmatch(name):
            raise _refuse("ARGV_NAME", "not a resource name", args)
    ns = None
    seen = set()
    while rest:
        flag = rest.pop(0)
        if flag in seen:
            raise _refuse("ARGV_GET_SHAPE", "a flag may appear once", args)
        seen.add(flag)
        if flag == "-n" and rest:
            ns = _ns(rest.pop(0), args)
        elif flag == "-A":
            if name is not None:
                raise _refuse("ARGV_GET_SHAPE", "-A cannot be combined with a name", args)
        elif flag == "-l" and rest:
            if not _SELECTOR.fullmatch(rest.pop(0)):
                raise _refuse("ARGV_SELECTOR", "only simple equality label selectors are allowed", args)
        else:
            raise _refuse("ARGV_FLAG", "this flag is not allowed on get", args)
    if "-n" in seen and "-A" in seen:
        raise _refuse("ARGV_GET_SHAPE", "-n and -A are exclusive", args)
    return ArgvDecision("get", False, False, ns)


def _wait(args: Sequence[str]) -> ArgvDecision:
    # wait --for=condition=COND KIND/NAME -n NS --timeout=Ns
    if len(args) != 6 or args[3] != "-n":
        raise _refuse("ARGV_WAIT_SHAPE", "wait has one fixed shape", args)
    m = re.fullmatch(r"--for=condition=([A-Za-z]{3,30})", args[1])
    t = re.fullmatch(r"--timeout=([0-9]{1,3})s", args[5])
    if not m or m.group(1) not in CONDITIONS or not t or not (1 <= int(t.group(1)) <= MAX_WAIT_SECONDS):
        raise _refuse("ARGV_WAIT_SHAPE", "wait condition or timeout is not allowed", args)
    if not _WAIT_KIND.fullmatch(args[2]) or args[2].split("/", 1)[0] not in READ_KINDS:
        raise _refuse("ARGV_KIND_NOT_READABLE", "wait target kind is not on the read allow-list", args)
    return ArgvDecision("wait", False, False, _ns(args[4], args))


def validate_argv(args: Sequence[str]) -> ArgvDecision:
    """The rule this command matches, or ``PolicyBlocked``. Everything not listed is refused."""
    _basic(args)
    verb = args[0]
    if verb == "version":
        if list(args) == ["version", "-o", "json"]:
            return ArgvDecision("version", False, False)
    elif verb == "get":
        return _get(args)
    elif verb == "wait":
        return _wait(args)
    elif verb == "apply":
        if list(args) == ["apply", "--dry-run=server", "--validate=strict", "-f", "-", "-o", "json"]:
            return ArgvDecision("apply-dry-run", False, True)
        if len(args) == 5 and args[1:3] == ["-f", "-"] and args[3] == "-n":
            return ArgvDecision("apply-probe", True, True, _probe_ns(args[4], args))
    elif verb == "create":
        if len(args) == 3 and args[1] == "namespace":
            return ArgvDecision("create-probe-namespace", True, False, _probe_ns(args[2], args))
    elif verb == "delete":
        if len(args) == 5 and args[1] == "namespace" and args[3:] == ["--wait=true", "--timeout=60s"]:
            return ArgvDecision("delete-probe-namespace", True, False, _probe_ns(args[2], args))
    elif verb == "logs":
        if len(args) == 4 and args[2] == "-n" and _NAME.fullmatch(args[1]):
            return ArgvDecision("probe-logs", False, False, _probe_ns(args[3], args))
    raise _refuse("ARGV_NOT_ALLOWED", "this kubectl command is not on the allow-list", args)
