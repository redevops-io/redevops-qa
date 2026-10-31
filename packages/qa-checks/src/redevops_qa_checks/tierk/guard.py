# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The disposable-cluster guard.

A cluster is accepted only if **this tool generated it**, and that is proven twice, locally and in the cluster:

* locally: the state directory carries the tool's sentinel, a *marker list* names the cluster (fixed cluster and context names
  per lane), and the kubeconfig the tool is given is the very file that was generated (its sha256 is in the marker list, it
  lies inside the state directory, it has exactly one cluster, one context and one user, embedded client certificate data only,
  no token, exec plugin, auth provider, proxy or file path, an https server on loopback or on a configured sandbox network);
* in the cluster: the *marker object* (a ConfigMap in a reserved namespace) carries the nonce hash, names, lane and plan hash
  that the marker list recorded, and the server reports the Kubernetes version the lane declares.

Anything else is refused with ``PolicyBlocked`` (``ActionBlockedByPolicy`` at the adapter): an ambient or user kubeconfig, a
context that is not on the allow-list, a server outside loopback or the sandbox network, a missing or different marker object,
a lane or plan mismatch. The ambient environment (``KUBECONFIG``, ``KUBECTL_*``, the current context) is never consulted.

``disposable_proof_ref`` is the sha256 of a canonical proof record; it is recomputed from the live cluster, so a stale or
foreign reference is refused.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from ..canonical import canonical_bytes, sha256_ref
from ..errors import LimitExceeded, PolicyBlocked
from ..manifests import LoadProblem, parse_documents
from .argv import MARKER_NAME, MARKER_NAMESPACE, ArgvDecision, validate_argv

STATE_SENTINEL = ".qa-checks-state"
STATE_SCHEMA = "qa-checks/tier-k-state/1"
MARKER_LIST_FILE = "disposable-clusters.json"
MARKER_LIST_SCHEMA = "qa-checks/disposable-marker-list/1"
MARKER_OBJECT_SCHEMA = "qa-checks/disposable-marker-object/1"
PROOF_SCHEMA = "qa-checks/disposable-proof/1"
CREATED_BY = "redevops-qa-checks"
CLUSTER_NAME_PREFIX = "qa-tier-k-"
FORBIDDEN_LAN = ipaddress.ip_network("192.168.0.0/16")
MAX_COMMANDS = 500


def _refuse(code: str, message: str, **details: Any) -> PolicyBlocked:
    return PolicyBlocked(message, guard_code=code, **details)


# -- state directory and marker list -----------------------------------------------------------------------------------------

def check_state_dir(state_dir: Path) -> Path:
    """The tool's own state directory: a real directory (not a link), not writable by others, with the tool's sentinel."""
    p = Path(state_dir)
    try:
        st = os.lstat(p)
    except OSError:
        raise _refuse("STATE_DIR_MISSING", "the state directory does not exist") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise _refuse("STATE_DIR_INVALID", "the state directory must be a real directory")
    if st.st_mode & 0o022:
        raise _refuse("STATE_DIR_WRITABLE_BY_OTHERS", "the state directory must not be writable by group or others")
    sentinel = _read_json(p / STATE_SENTINEL, "STATE_SENTINEL_INVALID")
    if not isinstance(sentinel, Mapping) or sentinel.get("schema") != STATE_SCHEMA:
        raise _refuse("STATE_SENTINEL_INVALID", "the directory is not a state directory created by this tool")
    return p.resolve()


def _read_bytes(path: Path, code: str, cap: int = 1 << 20) -> bytes:
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise _refuse(code, "not a regular file")
        with open(path, "rb") as fh:
            data = fh.read(cap + 1)
    except FileNotFoundError:
        raise _refuse(code, "file is missing") from None
    except OSError:
        raise _refuse(code, "file cannot be read") from None
    if len(data) > cap:
        raise _refuse(code, "file is too large")
    return data


def _read_json(path: Path, code: str) -> Any:
    try:
        return json.loads(_read_bytes(path, code).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _refuse(code, "file is not valid JSON") from None


@dataclass(frozen=True)
class MarkerEntry:
    lane: str
    cluster_name: str
    context_name: str
    kubeconfig_file: str
    kubeconfig_sha256: str
    server: str
    nonce: str
    plan_sha256: str
    kubernetes_version: str

    @property
    def nonce_sha256(self) -> str:
        return hashlib.sha256(self.nonce.encode("ascii")).hexdigest()

    def public(self) -> Dict[str, str]:
        """The entry without its nonce (what the proof and the marker object may carry)."""
        return {"lane": self.lane, "cluster_name": self.cluster_name, "context_name": self.context_name, "server": self.server,
                "kubeconfig_sha256": self.kubeconfig_sha256, "plan_sha256": self.plan_sha256, "kubernetes_version": self.kubernetes_version}


def load_marker_list(state: Path) -> Tuple[MarkerEntry, ...]:
    doc = _read_json(state / MARKER_LIST_FILE, "MARKER_LIST_MISSING")
    if not isinstance(doc, Mapping) or doc.get("schema") != MARKER_LIST_SCHEMA or doc.get("created_by") != CREATED_BY \
            or not isinstance(doc.get("clusters"), list):
        raise _refuse("MARKER_LIST_INVALID", "the marker list is not one this tool wrote")
    out = []
    for e in doc["clusters"]:
        if not isinstance(e, Mapping) or set(e) != {"lane", "cluster_name", "context_name", "kubeconfig_file", "kubeconfig_sha256", "server",
                                                    "nonce", "plan_sha256", "kubernetes_version"} \
                or any(type(v) is not str or not v for v in e.values()):
            raise _refuse("MARKER_LIST_INVALID", "a marker list entry is malformed")
        out.append(MarkerEntry(**{k: e[k] for k in e}))
    names = [x.context_name for x in out]
    if len(set(names)) != len(names) or len({x.lane for x in out}) != len(out):
        raise _refuse("MARKER_LIST_INVALID", "marker list entries must be unique per lane and context")
    for x in out:
        if not x.cluster_name.startswith(CLUSTER_NAME_PREFIX) or x.context_name != f"kind-{x.cluster_name}":
            raise _refuse("MARKER_LIST_INVALID", "cluster and context names must follow the generated naming")
    return tuple(out)


def write_state_dir(state_dir: Path) -> Path:
    """Create the tool's state directory (mode 0700) with its sentinel. Used by bring-up and by tests; never on an existing path."""
    p = Path(state_dir)
    p.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(p, 0o700)
    (p / STATE_SENTINEL).write_text(json.dumps({"schema": STATE_SCHEMA}), encoding="utf-8")
    return p


def register_cluster(state_dir: Path, entry: MarkerEntry, kubeconfig: bytes) -> None:
    """Record a generated cluster: write its kubeconfig and add it to the marker list (bring-up calls this after creating a cluster)."""
    state = check_state_dir(state_dir)
    if hashlib.sha256(kubeconfig).hexdigest() != entry.kubeconfig_sha256:
        raise _refuse("KUBECONFIG_HASH_MISMATCH", "the entry does not describe this kubeconfig")
    existing = []
    if (state / MARKER_LIST_FILE).exists():
        existing = [dict(e) for e in _read_json(state / MARKER_LIST_FILE, "MARKER_LIST_MISSING")["clusters"]]
    existing = [e for e in existing if e["lane"] != entry.lane]
    existing.append({"lane": entry.lane, "cluster_name": entry.cluster_name, "context_name": entry.context_name,
                     "kubeconfig_file": entry.kubeconfig_file, "kubeconfig_sha256": entry.kubeconfig_sha256, "server": entry.server,
                     "nonce": entry.nonce, "plan_sha256": entry.plan_sha256, "kubernetes_version": entry.kubernetes_version})
    (state / entry.kubeconfig_file).write_bytes(kubeconfig)
    os.chmod(state / entry.kubeconfig_file, 0o600)
    (state / MARKER_LIST_FILE).write_text(json.dumps({"schema": MARKER_LIST_SCHEMA, "created_by": CREATED_BY, "clusters": existing}, sort_keys=True),
                                          encoding="utf-8")


def marker_object(entry: MarkerEntry) -> Dict[str, Any]:
    """The ConfigMap bring-up applies to the new cluster. It carries the nonce hash, never the nonce."""
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": MARKER_NAME, "namespace": MARKER_NAMESPACE, "labels": {"app.kubernetes.io/managed-by": CREATED_BY}},
            "data": {"schema": MARKER_OBJECT_SCHEMA, "cluster_name": entry.cluster_name, "context_name": entry.context_name, "lane": entry.lane,
                     "nonce_sha256": entry.nonce_sha256, "plan_sha256": entry.plan_sha256, "created_by": CREATED_BY}}


# -- the kubeconfig ---------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class KubeconfigFacts:
    server: str
    cluster: str
    context: str
    user: str


_CREDENTIAL_FIELDS = ("token", "tokenFile", "exec", "auth-provider", "username", "password", "client-certificate", "client-key",
                      "as", "as-groups", "as-user-extra", "proxy-url", "certificate-authority", "insecure-skip-tls-verify",
                      "tls-server-name")


def inspect_kubeconfig(data: bytes) -> KubeconfigFacts:
    try:
        docs = parse_documents(data.decode("utf-8"))
    except (UnicodeDecodeError, LoadProblem):
        raise _refuse("KUBECONFIG_INVALID", "the kubeconfig does not parse") from None
    if len(docs) != 1 or not isinstance(docs[0], Mapping):
        raise _refuse("KUBECONFIG_INVALID", "a kubeconfig is one document")
    kc = docs[0]
    if kc.get("kind") != "Config":
        raise _refuse("KUBECONFIG_INVALID", "not a kubeconfig")
    clusters, contexts, users = kc.get("clusters"), kc.get("contexts"), kc.get("users")
    if not (isinstance(clusters, list) and len(clusters) == 1 and isinstance(contexts, list) and len(contexts) == 1
            and isinstance(users, list) and len(users) == 1):
        raise _refuse("KUBECONFIG_NOT_SINGLE", "the generated kubeconfig has exactly one cluster, one context and one user")
    c, x, u = clusters[0], contexts[0], users[0]
    if not all(isinstance(v, Mapping) for v in (c, x, u)):
        raise _refuse("KUBECONFIG_INVALID", "malformed entries")
    cl, ctx = c.get("cluster"), x.get("context")
    usr = u.get("user")
    if not (isinstance(cl, Mapping) and isinstance(ctx, Mapping) and isinstance(usr, Mapping)):
        raise _refuse("KUBECONFIG_INVALID", "malformed entries")
    if kc.get("current-context") != x.get("name") or ctx.get("cluster") != c.get("name") or ctx.get("user") != u.get("name"):
        raise _refuse("KUBECONFIG_INVALID", "context, cluster and user must refer to each other and be current")
    if ctx.get("namespace") not in (None, "default"):
        raise _refuse("KUBECONFIG_INVALID", "the context must not pin another namespace")
    for field in _CREDENTIAL_FIELDS:
        if field in usr or field in cl:
            raise _refuse("KUBECONFIG_CREDENTIAL_FORBIDDEN", f"{field} is not allowed in the generated kubeconfig", field=field)
    if set(usr) - {"client-certificate-data", "client-key-data"}:
        raise _refuse("KUBECONFIG_CREDENTIAL_FORBIDDEN", "only embedded client certificate data is allowed")
    if set(cl) - {"server", "certificate-authority-data"}:
        raise _refuse("KUBECONFIG_CREDENTIAL_FORBIDDEN", "only the server and embedded CA data are allowed on the cluster")
    server = cl.get("server")
    if type(server) is not str:
        raise _refuse("KUBECONFIG_INVALID", "no server")
    return KubeconfigFacts(server=server, cluster=str(c.get("name")), context=str(x.get("name")), user=str(u.get("name")))


def check_server(server: str, sandbox_networks: Sequence[str] = ()) -> None:
    """https, an IP literal on loopback or inside a configured sandbox network, or ``localhost``; never a hostname resolved by DNS."""
    nets = []
    for n in sandbox_networks:
        net = ipaddress.ip_network(n, strict=True)
        if net.version == 4 and net.overlaps(FORBIDDEN_LAN):
            raise _refuse("SANDBOX_NETWORK_REFUSED", "a sandbox network may not overlap the 192.168.0.0/16 range")
        nets.append(net)
    try:
        parts = urlsplit(server)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise _refuse("SERVER_NOT_LOOPBACK", "the server address does not parse") from None
    if parts.scheme != "https" or not host or port is None or not (1 <= port <= 65535) or parts.username or parts.password \
            or parts.path not in ("", "/") or parts.query or parts.fragment:
        raise _refuse("SERVER_NOT_LOOPBACK", "the server must be https://HOST:PORT")
    if host == "localhost":
        return
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise _refuse("SERVER_NOT_LOOPBACK", "a server name is refused; use a loopback or sandbox IP literal") from None
    if ip.is_loopback or any(ip in n for n in nets if n.version == ip.version):
        return
    raise _refuse("SERVER_NOT_LOOPBACK", "the server is outside loopback and the configured sandbox networks")


@dataclass(frozen=True)
class LocalCluster:
    """What the local checks established. Only ``TierKGuard.local_check`` creates one (the seal is a module-private object)."""
    entry: MarkerEntry
    kubeconfig_path: Path
    state_dir: Path
    _seal: object

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise _refuse("LOCAL_CLUSTER_FORGED", "a LocalCluster is created by the guard only")


_SEAL = object()


class TierKGuard:
    def __init__(self, state_dir: Path, *, plan_sha256: str, lanes: Mapping[str, str], sandbox_networks: Sequence[str] = ()) -> None:
        """``lanes`` maps each lane id to the Kubernetes version it declares; ``plan_sha256`` is the bring-up plan hash."""
        self._state_dir = Path(state_dir)
        self._plan = plan_sha256
        self._lanes = dict(lanes)
        self._sandbox = tuple(sandbox_networks)

    def local_check(self, lane: str, kubeconfig: Path, context: str) -> LocalCluster:
        """All checks that need no cluster. ``kubeconfig`` and ``context`` are what the caller was handed; they are only accepted
        if they are the generated ones."""
        if lane not in self._lanes:
            raise _refuse("LANE_UNKNOWN", "unknown lane", lane=lane)
        state = check_state_dir(self._state_dir)
        entries = {e.context_name: e for e in load_marker_list(state)}
        if context not in entries:
            raise _refuse("CONTEXT_NOT_ALLOWED", "the context is not on the allow-list of generated clusters", context=context)
        entry = entries[context]
        if entry.lane != lane:
            raise _refuse("LANE_MISMATCH", "the context belongs to another lane", lane=lane)
        if entry.plan_sha256 != self._plan:
            raise _refuse("PLAN_MISMATCH", "the cluster was generated from a different bring-up plan")
        if entry.kubernetes_version != self._lanes[lane]:
            raise _refuse("LANE_MISMATCH", "the marker list declares another Kubernetes version for this lane")
        kc = Path(kubeconfig)
        try:
            resolved = kc.resolve(strict=True)
        except OSError:
            raise _refuse("KUBECONFIG_NOT_GENERATED", "the kubeconfig does not exist") from None
        if resolved != (state / entry.kubeconfig_file).resolve() or kc.is_symlink():
            raise _refuse("KUBECONFIG_NOT_GENERATED", "the kubeconfig is not the file this tool generated")
        data = _read_bytes(resolved, "KUBECONFIG_NOT_GENERATED")
        if hashlib.sha256(data).hexdigest() != entry.kubeconfig_sha256:
            raise _refuse("KUBECONFIG_NOT_GENERATED", "the kubeconfig differs from the generated one")
        facts = inspect_kubeconfig(data)
        if facts.context != context or facts.cluster != entry.context_name or facts.server != entry.server:
            raise _refuse("CONTEXT_NOT_ALLOWED", "the kubeconfig does not describe the allow-listed cluster")
        check_server(facts.server, self._sandbox)
        return LocalCluster(entry=entry, kubeconfig_path=resolved, state_dir=state, _seal=_SEAL)

    def proof_record(self, local: LocalCluster, marker: Mapping[str, Any], server_version: str) -> Dict[str, Any]:
        """Verify the marker object and the server version against the local entry; return the canonical proof record."""
        e = local.entry
        data = marker.get("data") if isinstance(marker, Mapping) else None
        meta = marker.get("metadata") if isinstance(marker, Mapping) else None
        if not isinstance(data, Mapping) or not isinstance(meta, Mapping) or marker.get("kind") != "ConfigMap":
            raise _refuse("MARKER_OBJECT_MISSING", "the cluster has no disposable marker object")
        if meta.get("name") != MARKER_NAME or meta.get("namespace") != MARKER_NAMESPACE:
            raise _refuse("MARKER_OBJECT_MISSING", "the marker object is not at its reserved name")
        want = {"schema": MARKER_OBJECT_SCHEMA, "cluster_name": e.cluster_name, "context_name": e.context_name, "lane": e.lane,
                "nonce_sha256": e.nonce_sha256, "plan_sha256": e.plan_sha256, "created_by": CREATED_BY}
        if dict(data) != want:
            raise _refuse("MARKER_OBJECT_MISMATCH", "the marker object does not match the marker list entry")
        if server_version != e.kubernetes_version:
            raise _refuse("LANE_MISMATCH", "the server reports another Kubernetes version than the lane declares", reported=server_version)
        return {"schema": PROOF_SCHEMA, "marker": e.public(), "marker_object_nonce_sha256": e.nonce_sha256, "server_version": server_version}


def proof_ref(record: Mapping[str, Any]) -> str:
    return sha256_ref(canonical_bytes(record))


# -- the guarded session ------------------------------------------------------------------------------------------------------------

class GuardedSession:
    """The only handle through which a kubectl runner is called. Every command is checked against the argv allow-list, the marker
    object is re-read from the cluster before it runs, and the number of commands is bounded. The inner runner is not exposed."""

    def __init__(self, guard: TierKGuard, local: LocalCluster, runner: Any, *, allow_probe_mutation: bool = False,
                 probe_policy: Optional[Callable[[Mapping[str, Any]], None]] = None, max_commands: int = MAX_COMMANDS) -> None:
        if not isinstance(local, LocalCluster) or local._seal is not _SEAL:
            raise _refuse("LOCAL_CLUSTER_FORGED", "a session needs the guard's local check result")
        if allow_probe_mutation and probe_policy is None:
            raise _refuse("PROBE_POLICY_REQUIRED", "probe mutation needs a policy that accepts only the fixed probe specifications")
        self.__guard, self.__local, self.__runner = guard, local, runner
        self.__allow, self.__probe, self.__max = allow_probe_mutation, probe_policy, max_commands
        self.__count = 0
        self.__proof: Optional[Tuple[Dict[str, Any], str]] = None
        self.lane = local.entry.lane
        self.kubernetes_version = local.entry.kubernetes_version
        self.verify()

    def _raw(self, args: Sequence[str], stdin: Optional[str], timeout_s: int) -> Any:
        self.__count += 1
        if self.__count > self.__max:
            raise LimitExceeded("the session command budget is exhausted", max_commands=self.__max)
        return self.__runner.run(list(args), stdin=stdin, timeout_s=timeout_s)

    def verify(self, *, version: bool = True) -> str:
        """Read the marker object (and, at open, the server version) and (re)compute the proof reference."""
        marker = self._raw(["get", "configmap", MARKER_NAME, "-n", MARKER_NAMESPACE, "-o", "json"], None, 30)
        if marker.returncode != 0:
            raise _refuse("MARKER_OBJECT_MISSING", "the marker object cannot be read")
        try:
            mdoc = json.loads(marker.stdout)
            if version or self.__proof is None:
                got = self._raw(["version", "-o", "json"], None, 30)
                sv = json.loads(got.stdout)["serverVersion"]["gitVersion"] if got.returncode == 0 else ""
            else:
                sv = self.__proof[0]["server_version"]
        except (ValueError, KeyError, TypeError):
            raise _refuse("MARKER_OBJECT_MISSING", "the marker object or server version is not readable") from None
        record = self.__guard.proof_record(self.__local, mdoc, sv)
        self.__proof = (record, proof_ref(record))
        return self.__proof[1]

    @property
    def proof_ref(self) -> str:
        assert self.__proof is not None
        return self.__proof[1]

    @property
    def proof_record(self) -> Dict[str, Any]:
        assert self.__proof is not None
        return dict(self.__proof[0])

    def run(self, args: Sequence[str], *, stdin: Optional[str] = None, timeout_s: int = 60) -> Any:
        decision = validate_argv(args)
        if decision.stdin_required != (stdin is not None):
            raise _refuse("ARGV_STDIN", "this command takes its manifest on stdin and no other input", rule=decision.rule)
        if decision.mutating:
            if not self.__allow or self.__probe is None:
                raise _refuse("ARGV_MUTATION_NOT_ALLOWED", "persisting commands are disabled for this session", rule=decision.rule)
            if stdin is not None:
                self._check_probe_stdin(stdin)
        if not 1 <= timeout_s <= 120:
            raise _refuse("TIMEOUT_BOUND", "a command timeout is between 1 and 120 seconds")
        if stdin is not None and len(stdin) > 1 << 20:
            raise LimitExceeded("stdin is too large", size=len(stdin))
        before = self.__proof[1] if self.__proof else ""
        if self.verify(version=False) != before:                       # the marker object is proven again before every command
            raise _refuse("PROOF_CHANGED", "the disposable proof changed during the session")
        return self._raw(args, stdin, timeout_s)

    def _check_probe_stdin(self, stdin: str) -> None:
        try:
            docs = parse_documents(stdin)
        except LoadProblem:
            raise _refuse("PROBE_SPEC_REFUSED", "the probe manifest does not parse") from None
        if not docs or not all(isinstance(d, Mapping) for d in docs):
            raise _refuse("PROBE_SPEC_REFUSED", "a probe manifest is one or more objects")
        for d in docs:
            self.__probe(d)                                # raises PolicyBlocked unless it is a fixed probe specification


def local_for_lane(guard: TierKGuard, lane: str) -> LocalCluster:
    """The local cluster for a lane, taken from the tool's own marker list. There is no parameter for a kubeconfig or a context:
    a caller cannot hand in a different one."""
    state = check_state_dir(guard._state_dir)
    for e in load_marker_list(state):
        if e.lane == lane:
            return guard.local_check(lane, state / e.kubeconfig_file, e.context_name)
    raise _refuse("LANE_NOT_GENERATED", "no cluster has been generated for this lane", lane=lane)
