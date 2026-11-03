# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Kernel layers that limit the network egress of the Robot lane: what a Robot library, a thread it starts, native code it loads and every process it spawns can connect to.

A Robot library is arbitrary Python, so an allow-list inside the interpreter (a patched ``socket``) would not hold against ``ctypes``, a raw system call or a child process that
does not import it. The layers here are installed on the lane child process BEFORE the engine is started and are inherited by everything it starts (a filter cannot be removed by the
process that carries it):

1. ``seccomp`` (a BPF filter with a supervising thread of the lane child, ``SECCOMP_RET_USER_NOTIF``): ``socket`` is allowed only for TCP over IPv4 and for local stream sockets;
   UDP, raw, packet, netlink, IPv6, SCTP, MPTCP and every other kind are refused. ``connect`` is decided by the supervisor from the address the caller passed: only an
   address of the plan's allow-list is let through, a refused one fails with ``EACCES`` and is recorded. ``connect`` to a local (unix) socket path, ``sendto`` with an address,
   TCP Fast Open, ``listen`` (nothing can accept an inbound connection), ``io_uring`` and the calls that read or write another process (``ptrace``, ``process_vm_*``, ``pidfd_getfd``) are
   refused too.
2. ``Landlock`` (ABI 4 or later): ``connect`` of a TCP socket is limited, by the kernel itself, to the ports of the allow-list, and ``bind`` of a TCP socket is refused for every port (a connect
   that binds an ephemeral port by itself is not a ``bind`` call and still works).

The lane child also marks itself not dumpable (so that a same-user engine cannot read or write its memory through ``/proc``, with or without a Yama policy on the host) and a subreaper (so that
a process the engine detaches is a descendant of the lane child and is ended before the lane's result is written: ``reap_descendants``).

Both need no privilege and no helper program: ``prctl``, ``seccomp`` and the three Landlock calls, made through ``ctypes``. If a layer cannot be installed, or the self-test that
follows (a ``connect`` to a listener that is not allowed must be refused, a UDP socket must be refused) does not pass, ``install`` raises ``FenceUnavailable``: the caller does not start
the engine. There is no weaker mode.

What these layers do NOT do (the report of a run says the same):

* The address of ``connect`` is read from the caller's memory and the call is then continued by the kernel, which reads it again: a second thread (or a process sharing the
  memory) that changes the address in between can reach ANOTHER IPv4 ADDRESS on the allowed PORT (Landlock still holds the port; measured: about a fifth of the attempts of such a library
  did). Against a hostile library the allow-list is therefore enforced at the level of the PORT; the address check holds for honest code and for code that does not race it. Closing this would
  need the supervisor to connect on the caller's behalf (``pidfd_getfd``, which Docker's default profile refuses) or to replace the caller's socket (``SECCOMP_IOCTL_NOTIF_ADDFD``, which loses
  the options and the blocking mode the caller set): neither is used.
* Nothing here confines files, pipes, FIFOs, shared memory or a process that is already running and reachable that way; a descriptor the process already had is not affected;
  ``/proc`` and ``/dev`` are as before. Local (unix) stream sockets can be created, but connecting one to a path is refused.
* A caller with ``CAP_SYS_PTRACE`` (for example root outside a container with the default capabilities) can read or write the supervisor's memory; so can a same-user process
  that is not refused by ``PR_SET_DUMPABLE`` (it is) and by the host's ptrace policy; the engine itself stays dumpable, because the supervisor needs to read its address argument; a process that signals
  the lane child (same user) can stop or kill the supervisor: that ends in no connection at all (fail closed) and a lane that runs into its deadline, never in an open network; a kernel bug defeats every
  layer; a kernel without user notification, Landlock network rules, or an architecture without a table here has NO mechanism and the lane does not start.
* Names are not resolved over the network (UDP is refused): only what ``/etc/hosts`` gives resolves, and the address it gives is then checked like any other.
* Inbound: ``listen`` is refused and ``bind`` is refused by Landlock, so nothing in the lane accepts a connection; a TCP simultaneous open (two ends that connect to each other) is not excluded.

Linux only. ``x86_64`` is the platform this release makes claims for; the table for ``aarch64`` exists so the same code can be exercised on that architecture during development, it is
not measured in CI and nothing is claimed for it."""
from __future__ import annotations

import ctypes
import errno
import ipaddress
import json
import os
import platform
import select
import signal
import socket
import struct
import sys
import threading
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .egresslog import ALL_LAYERS, LAYER_LANDLOCK, LAYER_SECCOMP, MAX_ALLOW_RECORDS, MAX_DENY_RECORDS

# ---- kernel constants ---------------------------------------------------------------------------------------------------------------
PR_SET_DUMPABLE = 4
PR_SET_CHILD_SUBREAPER = 36
PR_SET_NO_NEW_PRIVS = 38
SECCOMP_SET_MODE_FILTER = 1
SECCOMP_FILTER_FLAG_NEW_LISTENER = 8
SECCOMP_GET_NOTIF_SIZES = 3
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_USER_NOTIF = 0x7FC00000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_NET_PORT = 2
LANDLOCK_ACCESS_NET_BIND_TCP = 1
LANDLOCK_ACCESS_NET_CONNECT_TCP = 2
MIN_LANDLOCK_ABI = 4
AF_UNIX, AF_INET = 1, 2
SOCK_STREAM = 1
SOCK_TYPE_MASK = 0xF
IPPROTO_TCP = 6
MSG_FASTOPEN = 0x20000000
X32_SYSCALL_BIT = 0x40000000
NR_LANDLOCK_CREATE, NR_LANDLOCK_ADD, NR_LANDLOCK_RESTRICT = 444, 445, 446

# classic BPF opcodes
BPF_LD_W_ABS, BPF_JEQ_K, BPF_JSET_K, BPF_AND_K, BPF_RET_K = 0x20, 0x15, 0x45, 0x54, 0x06

ARCHES: Dict[str, Dict[str, Any]] = {
    "x86_64": {"audit": 0xC000003E, "x32": True, "seccomp": 317,
               "nr": {"socket": 41, "connect": 42, "listen": 50, "sendto": 44, "sendmsg": 46, "socketpair": 53, "ptrace": 101, "sendmmsg": 307, "process_vm_readv": 310,
                      "process_vm_writev": 311, "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427, "pidfd_getfd": 438}},
    "aarch64": {"audit": 0xC00000B7, "x32": False, "seccomp": 277,
                "nr": {"socket": 198, "socketpair": 199, "listen": 201, "connect": 203, "sendto": 206, "sendmsg": 211, "ptrace": 117, "sendmmsg": 269, "process_vm_readv": 270,
                       "process_vm_writev": 271, "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427, "pidfd_getfd": 438}},
}
_AF = {1: "AF_UNIX", 2: "AF_INET", 10: "AF_INET6", 16: "AF_NETLINK", 17: "AF_PACKET", 40: "AF_VSOCK", 0: "AF_UNSPEC"}
_SOCK = {1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW", 5: "SOCK_SEQPACKET"}


class FenceUnavailable(RuntimeError):
    """A requested protection cannot be provided here; ``reason`` is a short stable identifier, the message says what to do."""

    def __init__(self, reason: str, message: str):
        super().__init__(f"{reason}: {message}")
        self.reason = reason
        self.message = message


# ---- the policy ---------------------------------------------------------------------------------------------------------------------
def allowed_endpoints(policy: Mapping[str, Any]) -> List[Tuple[ipaddress.IPv4Network, int]]:
    """The (network, port) pairs of a lane's egress policy (the form ``egress.policy_config`` writes). Only IPv4 networks with explicit ports count: anything else allows nothing."""
    out: List[Tuple[ipaddress.IPv4Network, int]] = []
    for entry in policy.get("private", []) if isinstance(policy, Mapping) else []:
        for net in entry.get("networks", []):
            try:
                network = ipaddress.ip_network(net, strict=True)
            except ValueError:
                continue
            if network.version != 4:
                continue
            for port in entry.get("ports", []):
                if type(port) is int and 0 < port < 65536:
                    out.append((network, port))                                     # type: ignore[arg-type]
    return out


def decide_connect(allowed: Sequence[Tuple[ipaddress.IPv4Network, int]], family: int, address: Optional[str], port: Optional[int]) -> Tuple[bool, str]:
    """The decision of the supervisor for one ``connect``: only an IPv4 address and port of the allow-list passes; the default is deny."""
    if family != AF_INET or address is None or port is None:
        return False, "address-family-not-permitted"
    ip = ipaddress.ip_address(address)
    return (True, "in-allow-list") if any(ip in net and port == p for net, p in allowed) else (False, "not-in-allow-list")


# ---- the BPF filter -----------------------------------------------------------------------------------------------------------------
class _Asm:
    """A tiny assembler for classic BPF with named jump targets (the filter is small: every jump fits the 8 bits of a conditional jump)."""

    def __init__(self) -> None:
        self.ins: List[List[Any]] = []
        self.labels: Dict[str, int] = {}

    def label(self, name: str) -> None:
        self.labels[name] = len(self.ins)

    def ld(self, offset: int) -> None:
        self.ins.append([BPF_LD_W_ABS, None, None, offset])

    def alu_and(self, k: int) -> None:
        self.ins.append([BPF_AND_K, None, None, k])

    def jeq(self, k: int, jt: Optional[str], jf: Optional[str]) -> None:
        self.ins.append([BPF_JEQ_K, jt, jf, k])

    def jset(self, k: int, jt: Optional[str], jf: Optional[str]) -> None:
        self.ins.append([BPF_JSET_K, jt, jf, k])

    def ret(self, k: int) -> None:
        self.ins.append([BPF_RET_K, None, None, k])

    def assemble(self) -> bytes:
        out = bytearray()
        for i, (code, jt, jf, k) in enumerate(self.ins):
            def rel(target: Optional[str]) -> int:
                if target is None:
                    return 0
                delta = self.labels[target] - (i + 1)
                if not 0 <= delta <= 255:
                    raise ValueError("a jump of the filter is out of range")
                return delta
            out += struct.pack("<HBBI", code, rel(jt), rel(jf), k & 0xFFFFFFFF)
        return bytes(out)


_ARG_LO = lambda i: 16 + 8 * i                       # offsets into struct seccomp_data: nr 0, arch 4, ip 8, args from 16 (little endian: the low word first)
_ARG_HI = lambda i: 20 + 8 * i


def build_filter(arch: str) -> bytes:
    """The BPF program. Anything not named here is allowed (the filter is about network egress, not about confining the process)."""
    spec = ARCHES[arch]
    nr = spec["nr"]
    a = _Asm()
    a.ld(4)
    a.jeq(spec["audit"], None, "kill")                                   # another ABI (32-bit calls on a 64-bit kernel): not a call the table describes
    a.ld(0)
    if spec["x32"]:
        a.jset(X32_SYSCALL_BIT, "kill", None)                           # the x32 call numbers are a second set of numbers for the same calls
    for name in ("socket", "socketpair", "connect", "listen", "sendto", "sendmsg", "sendmmsg", "ptrace", "process_vm_readv", "process_vm_writev", "io_uring_setup", "io_uring_enter",
                 "io_uring_register", "pidfd_getfd"):
        a.jeq(nr[name], "g_" + name, None)
    a.ret(SECCOMP_RET_ALLOW)
    # socket(domain, type, protocol): TCP over IPv4 (protocol 0 or 6) and local stream sockets only; the low 32 bits are what the kernel reads as an int
    a.label("g_socket")
    a.ld(_ARG_LO(0))
    a.jeq(AF_UNIX, "sock_unix", None)
    a.jeq(AF_INET, "sock_inet", "notify")
    a.label("sock_unix")
    a.ld(_ARG_LO(1))
    a.alu_and(SOCK_TYPE_MASK)
    a.jeq(SOCK_STREAM, None, "notify")
    a.ld(_ARG_LO(2))
    a.jeq(0, "allow", "notify")
    a.label("sock_inet")
    a.ld(_ARG_LO(1))
    a.alu_and(SOCK_TYPE_MASK)
    a.jeq(SOCK_STREAM, None, "notify")
    a.ld(_ARG_LO(2))
    a.jeq(0, "allow", None)
    a.jeq(IPPROTO_TCP, "allow", "notify")
    # socketpair(domain, type, protocol, sv): local stream sockets only (a datagram pair could send to a named path)
    a.label("g_socketpair")
    a.ld(_ARG_LO(0))
    a.jeq(AF_UNIX, None, "notify")
    a.ld(_ARG_LO(1))
    a.alu_and(SOCK_TYPE_MASK)
    a.jeq(SOCK_STREAM, "allow", "notify")
    # sendto(fd, buf, len, flags, addr, addrlen): no address, no TCP Fast Open (a connect that carries data)
    a.label("g_sendto")
    a.ld(_ARG_LO(3))
    a.jset(MSG_FASTOPEN, "notify", None)
    a.ld(_ARG_LO(4))
    a.jeq(0, None, "notify")
    a.ld(_ARG_HI(4))
    a.jeq(0, "allow", "notify")
    # sendmsg(fd, msg, flags) and sendmmsg(fd, msgvec, vlen, flags): no TCP Fast Open; the address inside a message cannot be read by a filter, but a kind of socket that could use one is refused above
    a.label("g_sendmsg")
    a.ld(_ARG_LO(2))
    a.jset(MSG_FASTOPEN, "notify", "allow")
    a.label("g_sendmmsg")
    a.ld(_ARG_LO(3))
    a.jset(MSG_FASTOPEN, "notify", "allow")
    for name in ("connect", "listen", "ptrace", "process_vm_readv", "process_vm_writev", "io_uring_setup", "io_uring_enter", "io_uring_register", "pidfd_getfd"):
        a.label("g_" + name)
        a.ret(SECCOMP_RET_USER_NOTIF)
    a.label("notify")
    a.ret(SECCOMP_RET_USER_NOTIF)
    a.label("allow")
    a.ret(SECCOMP_RET_ALLOW)
    a.label("kill")
    a.ret(SECCOMP_RET_KILL_PROCESS)
    return a.assemble()


# ---- syscalls through ctypes --------------------------------------------------------------------------------------------------------
class _Data(ctypes.Structure):
    _fields_ = [("nr", ctypes.c_int32), ("arch", ctypes.c_uint32), ("ip", ctypes.c_uint64), ("args", ctypes.c_uint64 * 6)]


class _Notif(ctypes.Structure):
    _fields_ = [("id", ctypes.c_uint64), ("pid", ctypes.c_uint32), ("flags", ctypes.c_uint32), ("data", _Data)]


class _Resp(ctypes.Structure):
    _fields_ = [("id", ctypes.c_uint64), ("val", ctypes.c_int64), ("error", ctypes.c_int32), ("flags", ctypes.c_uint32)]


class _Sizes(ctypes.Structure):
    _fields_ = [("notif", ctypes.c_uint16), ("notif_resp", ctypes.c_uint16), ("data", ctypes.c_uint16)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


class _LandlockRuleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64)]


class _LandlockNetPort(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("port", ctypes.c_uint64)]


def _ioctl_number(direction: int, size: int, nr: int) -> int:
    return (direction << 30) | (size << 16) | (ord("!") << 8) | nr


_IOC_WRITE, _IOC_READ = 1, 2
IOCTL_RECV = _ioctl_number(_IOC_READ | _IOC_WRITE, ctypes.sizeof(_Notif), 0)
IOCTL_SEND = _ioctl_number(_IOC_READ | _IOC_WRITE, ctypes.sizeof(_Resp), 1)
IOCTL_ID_VALID = _ioctl_number(_IOC_WRITE, 8, 2)


def _libc() -> Any:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.ioctl.restype = ctypes.c_int
    libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
    if hasattr(libc, "prctl"):                              # (not on macOS: the layers do not exist there, but the rest of this module can be imported and tested)
        libc.prctl.restype = ctypes.c_int
    return libc


def machine() -> str:
    return platform.machine().lower().replace("amd64", "x86_64").replace("arm64", "aarch64")


def landlock_abi(libc: Any = None) -> int:
    """The Landlock ABI version of this kernel, or 0 when Landlock is not available (not built in, not enabled, or refused by a container's own filter)."""
    libc = libc or _libc()
    r = libc.syscall(NR_LANDLOCK_CREATE, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
    return int(r) if r > 0 else 0


def kernel_facts() -> Dict[str, Any]:
    """What this host is, as far as the layers care: architecture, kernel release and the Landlock ABI. Informational (the self-test, not these facts, decides)."""
    facts: Dict[str, Any] = {"system": platform.system().lower(), "machine": machine(), "kernel": platform.release()[:60]}
    if facts["system"] == "linux":
        try:
            facts["landlock_abi"] = landlock_abi()
        except Exception:
            facts["landlock_abi"] = 0
    return facts


# ---- the supervisor -----------------------------------------------------------------------------------------------------------------
class Fence:
    """The installed layers and what the supervisor saw. Create it with ``install``; ``events()`` is the audit record (every decision of the supervisor, in order)."""

    def __init__(self, arch: str, allowed: Sequence[Tuple[ipaddress.IPv4Network, int]], layers: Sequence[str], facts: Mapping[str, Any]):
        self.arch = arch
        self.allowed = list(allowed)
        self.layers = tuple(layers)
        self.facts = dict(facts)
        self._events: List[Dict[str, Any]] = []
        self._allow_omitted = 0
        self._deny_omitted = 0
        self._lock = threading.Lock()
        self._fd: Optional[int] = None
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.lost = False
        self.selftest: Dict[str, Any] = {}
        self._libc = _libc()
        self._nr_name = {v: k for k, v in ARCHES[arch]["nr"].items()}

    # -- audit
    def events(self) -> List[Dict[str, Any]]:
        """Every decision in order and, when records were left out, a closing ``summary`` record that says how many. A refusal is written until MAX_DENY_RECORDS, an allowed connect until the
        lower MAX_ALLOW_RECORDS: the allowed ones are never the reason a refusal is missing."""
        with self._lock:
            rows = [dict(e) for e in self._events]
            if self._allow_omitted or self._deny_omitted:
                rows.append({"event": "summary", "allow_omitted": self._allow_omitted, "deny_omitted": self._deny_omitted})
            return rows

    @property
    def denied(self) -> int:
        with self._lock:
            return sum(1 for e in self._events if e["verdict"] == "deny") + self._deny_omitted

    def _record(self, **fields: Any) -> None:
        with self._lock:
            verdict = fields.get("verdict")
            allows = sum(1 for e in self._events if e["verdict"] == "allow")
            denies = len(self._events) - allows
            if verdict == "allow" and allows >= MAX_ALLOW_RECORDS:
                self._allow_omitted += 1
                return
            if verdict != "allow" and denies >= MAX_DENY_RECORDS:
                self._deny_omitted += 1 if verdict == "deny" else 0
                return
            self._events.append({"seq": len(self._events) + 1, "layer": LAYER_SECCOMP, **fields})

    def _reset(self) -> None:
        with self._lock:
            self._events, self._allow_omitted, self._deny_omitted = [], 0, 0

    def header(self) -> Dict[str, Any]:
        """The first line of the lane's egress log: which layers were installed, on what, and what the self-test measured."""
        return {"event": "mechanism", "layers": list(self.layers), "arch": self.arch, "kernel": self.facts.get("kernel"), "landlock_abi": self.facts.get("landlock_abi"),
                "allowed": sorted(f"{net}:{port}" for net, port in self.allowed), "selftest": self.selftest}

    # -- the loop (runs in a thread that was started BEFORE the filter was installed, so the filter does not apply to it)
    def _start(self) -> None:
        self._thread = threading.Thread(target=self._serve, name="qa-egress-supervisor", daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._ready.wait(0.2):
            if self._stop.is_set():
                return
        fd = self._fd
        if fd is None:
            return
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        try:
            while not self._stop.is_set():
                events = poller.poll(200)
                if not events:
                    continue
                flags = events[0][1]
                if flags & select.POLLIN:
                    req = _Notif()
                    if self._libc.ioctl(fd, IOCTL_RECV, ctypes.byref(req)) != 0:
                        err = ctypes.get_errno()
                        if err in (errno.ENOENT, errno.EINTR, errno.EAGAIN):
                            continue                                        # the caller was killed before we looked
                        raise OSError(err, "receive failed")
                    try:
                        self._handle(fd, req)
                    except Exception:                                       # a decision that could not be taken is a refusal, never a lost supervisor
                        self._refuse_after_error(fd, req)
                elif flags & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
                    break                                                   # every process that carried the filter is gone
        except Exception as exc:                                            # the supervisor is lost: every later decision call fails (ENOSYS) and the lane says so
            with self._lock:
                self.lost = not self._stop.is_set()
                self._events.append({"seq": len(self._events) + 1, "layer": LAYER_SECCOMP, "syscall": "supervisor", "verdict": "lost", "reason": type(exc).__name__})
            try:
                os.close(fd)                                                # a call that is waiting for an answer that will never come fails now (ENOTCONN) instead of at the deadline
            except OSError:
                pass

    def _refuse_after_error(self, fd: int, req: _Notif) -> None:
        self._record(verdict="deny", syscall=self._nr_name.get(req.data.nr, f"syscall-{req.data.nr}"), reason="decision-failed")
        self._libc.ioctl(fd, IOCTL_SEND, ctypes.byref(_Resp(id=req.id, val=0, error=-errno.EACCES, flags=0)))

    def _read_sockaddr(self, pid: int, addr: int, length: int) -> Optional[bytes]:
        try:
            fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        except OSError:
            return None
        try:
            return os.pread(fd, min(max(length, 0), 128), addr)
        except (OSError, OverflowError, ValueError):                       # an address the caller made up (above the range of an offset, or not mapped): refused, and the supervisor lives on
            return None
        finally:
            os.close(fd)

    def _handle(self, fd: int, req: _Notif) -> None:
        nr = req.data.nr
        name = self._nr_name.get(nr, f"syscall-{nr}")
        args = [int(x) for x in req.data.args]
        allow = False
        if name == "connect":
            allow, fields = self._decide_connect(req.pid, args)
        elif name in ("socket", "socketpair"):
            domain, kind, proto = args[0] & 0xFFFFFFFF, args[1] & SOCK_TYPE_MASK, args[2] & 0xFFFFFFFF
            fields = {"syscall": name, "family": _AF.get(domain, f"AF_{domain}"), "detail": f"{_SOCK.get(kind, 'SOCK_' + str(kind))}/{proto}", "reason": "socket-kind-not-permitted"}
        elif name in ("sendto", "sendmsg", "sendmmsg"):
            fields = {"syscall": name, "reason": "send-with-address-or-fast-open-not-permitted"}
        else:
            fields = {"syscall": name, "reason": "syscall-not-permitted"}
        resp = _Resp(id=req.id, val=0, error=0 if allow else -errno.EACCES, flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE if allow else 0)
        valid = self._libc.ioctl(fd, IOCTL_ID_VALID, ctypes.byref(ctypes.c_uint64(req.id))) == 0
        if not valid:
            return                                                          # the caller is gone: nothing to answer, nothing happened
        self._record(verdict="allow" if allow else "deny", **fields)
        self._libc.ioctl(fd, IOCTL_SEND, ctypes.byref(resp))

    def _decide_connect(self, pid: int, args: List[int]) -> Tuple[bool, Dict[str, Any]]:
        raw = self._read_sockaddr(pid, args[1], args[2] & 0xFFFFFFFF)
        if raw is None or len(raw) < 2:
            return False, {"syscall": "connect", "reason": "address-unreadable"}
        family = struct.unpack_from("=H", raw, 0)[0]
        if family == AF_INET and len(raw) >= 8:
            port = struct.unpack_from(">H", raw, 2)[0]
            address = socket.inet_ntoa(raw[4:8])
            ok, reason = decide_connect(self.allowed, family, address, port)
            return ok, {"syscall": "connect", "family": "AF_INET", "address": address, "port": port, "reason": reason}
        if family == AF_UNIX:
            path = raw[2:].split(b"\0", 1)[0] if len(raw) > 2 and raw[2:3] != b"\0" else b"@abstract"
            return False, {"syscall": "connect", "family": "AF_UNIX", "address": path.decode("utf-8", "replace")[:100], "reason": "local-socket-connect-not-permitted"}
        return False, {"syscall": "connect", "family": _AF.get(family, f"AF_{family}"), "reason": "address-family-not-permitted"}

    def reap_descendants(self, rounds: int = 100) -> int:
        """End every process the lane child has as a descendant, whatever session or group it left to (the lane child is a subreaper, so what the engine detached and orphaned is a child of this
        process by now), and reap them. Returns how many were ended. The lane's result is written after this: nothing that the engine started is left to rewrite it."""
        ended = 0
        me = os.getpid()
        for _ in range(rounds):
            victims = [p for p in _descendants(me)]
            if not victims:
                break
            for pid in victims:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            for pid in victims:
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
                except OSError:
                    pass
            ended += len(victims)
            time.sleep(0.02)
        return ended

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def _descendants(root: int) -> List[int]:
    """The processes whose parent chain leads to ``root`` (a snapshot of /proc; a process that is in the middle of exiting may be missed and is found by the next round)."""
    children: Dict[int, List[int]] = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        return []
    for name in names:
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", "rb") as fh:
                stat = fh.read().decode("utf-8", "replace")
            ppid = int(stat.rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        children.setdefault(ppid, []).append(int(name))
    found: List[int] = []
    todo = [root]
    while todo:
        for child in children.get(todo.pop(), []):
            found.append(child)
            todo.append(child)
    return found


# ---- installing -----------------------------------------------------------------------------------------------------------------------
def _fail(reason: str, message: str) -> FenceUnavailable:
    return FenceUnavailable(reason, message)


def _install_landlock(libc: Any, ports: Iterable[int]) -> None:
    attr = _LandlockRuleset(handled_access_fs=0, handled_access_net=LANDLOCK_ACCESS_NET_CONNECT_TCP | LANDLOCK_ACCESS_NET_BIND_TCP)       # no bind rule is added: every TCP bind is refused
    fd = libc.syscall(NR_LANDLOCK_CREATE, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if fd < 0:
        raise _fail("landlock-create-failed", f"landlock_create_ruleset failed ({os.strerror(ctypes.get_errno())})")
    try:
        for port in sorted(set(ports)):
            rule = _LandlockNetPort(allowed_access=LANDLOCK_ACCESS_NET_CONNECT_TCP, port=port)
            if libc.syscall(NR_LANDLOCK_ADD, fd, LANDLOCK_RULE_NET_PORT, ctypes.byref(rule), 0) != 0:
                raise _fail("landlock-rule-failed", f"landlock_add_rule failed ({os.strerror(ctypes.get_errno())})")
        if libc.syscall(NR_LANDLOCK_RESTRICT, fd, 0) != 0:
            raise _fail("landlock-restrict-failed", f"landlock_restrict_self failed ({os.strerror(ctypes.get_errno())})")
    finally:
        os.close(fd)


def _install_seccomp(libc: Any, arch: str) -> int:
    sizes = _Sizes()
    if libc.syscall(ARCHES[arch]["seccomp"], SECCOMP_GET_NOTIF_SIZES, 0, ctypes.byref(sizes)) != 0:
        raise _fail("seccomp-notification-unsupported", f"seccomp user notification is not available: this kernel lacks it or a container's seccomp profile refuses it ({os.strerror(ctypes.get_errno())})")
    if (sizes.notif, sizes.notif_resp) != (ctypes.sizeof(_Notif), ctypes.sizeof(_Resp)):
        raise _fail("seccomp-layout-unknown", "the kernel's notification structures are not the ones this code knows")
    program = build_filter(arch)
    buf = ctypes.create_string_buffer(program, len(program))
    prog = _SockFprog(len=len(program) // 8, filter=ctypes.cast(buf, ctypes.c_void_p).value)
    fd = libc.syscall(ARCHES[arch]["seccomp"], SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, ctypes.byref(prog))
    if fd < 0:
        raise _fail("seccomp-install-failed", f"the seccomp filter could not be installed ({os.strerror(ctypes.get_errno())})")
    return int(fd)


def install(policy: Mapping[str, Any], *, layers: Sequence[str] = ALL_LAYERS) -> Fence:
    """Install the layers on the calling thread (and so on every process and thread it starts afterwards) and return the ``Fence``. Call it from the main thread of the lane child before
    anything that is to be limited starts. Raises ``FenceUnavailable``; after that exception the calling thread may carry some of the layers, so the caller must not go on to start an
    engine (the lane child ends). ``layers`` exists for the experiments that show what each layer does on its own; the lane always uses ``ALL_LAYERS``."""
    if platform.system().lower() != "linux":
        raise _fail("not-linux", f"the kernel layers exist on Linux only (this is {platform.system() or 'unknown'})")
    arch = machine()
    if arch not in ARCHES:
        raise _fail("architecture-not-supported", f"no syscall table for {arch}")
    allowed = allowed_endpoints(policy)
    if not allowed:
        raise _fail("empty-policy", "the egress policy allows no IPv4 address and port: nothing to build a fence around")
    libc = _libc()
    facts = kernel_facts()
    if LAYER_LANDLOCK in layers and facts.get("landlock_abi", 0) < MIN_LANDLOCK_ABI:
        raise _fail("landlock-network-rules-unavailable", f"Landlock network rules need ABI {MIN_LANDLOCK_ABI} or later (kernel 6.7 or later with Landlock enabled, a native x86_64 host or VM, a container profile that allows the landlock calls); this host reports {facts.get('landlock_abi', 0)}")
    fence = Fence(arch, allowed, layers, facts)
    canary = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        canary.bind(("127.0.0.1", 0))
        canary.listen(1)
        if any(port == canary.getsockname()[1] for _, port in allowed):
            raise _fail("self-test-port-clash", "the self-test listener got a port of the allow-list")
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise _fail("no-new-privs-failed", f"PR_SET_NO_NEW_PRIVS failed ({os.strerror(ctypes.get_errno())})")
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:                    # a same-user engine cannot open /proc/<this process>/mem or attach to it, whatever the host's ptrace policy
            raise _fail("dumpable-failed", f"PR_SET_DUMPABLE failed ({os.strerror(ctypes.get_errno())})")
        if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:             # what the engine detaches and orphans becomes a child of this process, to be ended by reap_descendants
            raise _fail("subreaper-failed", f"PR_SET_CHILD_SUBREAPER failed ({os.strerror(ctypes.get_errno())})")
        if LAYER_SECCOMP in layers:
            fence._start()                                                  # the supervisor thread must exist before the filter does: it is then not subject to it
        if LAYER_LANDLOCK in layers:
            _install_landlock(libc, [port for _, port in allowed])
        if LAYER_SECCOMP in layers:
            fence._fd = _install_seccomp(libc, arch)
            fence._ready.set()
        fence.selftest = _selftest(fence, canary.getsockname(), layers)
        fence._reset()
    except BaseException:
        fence.close()
        raise
    finally:
        canary.close()
    return fence


def _selftest(fence: Fence, tcp_addr: Tuple[str, int], layers: Sequence[str], make_socket: Any = socket.socket) -> Dict[str, Any]:
    """A listener the policy does not allow must refuse this very thread, and (with the seccomp layer) a UDP socket must be refused. Anything else means the layers are not doing what
    they are for, and ``FenceUnavailable`` is raised: the lane does not start."""
    result: Dict[str, Any] = {}
    s = make_socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(tcp_addr)
        result["forbidden_tcp_refused"] = False
    except PermissionError:
        result["forbidden_tcp_refused"] = True
    except OSError as exc:
        result["forbidden_tcp_refused"] = False
        result["forbidden_tcp_error"] = errno.errorcode.get(exc.errno or 0, "?")
    finally:
        s.close()
    if LAYER_SECCOMP in layers:
        try:
            make_socket(socket.AF_INET, socket.SOCK_DGRAM).close()
            result["udp_refused"] = False
        except PermissionError:
            result["udp_refused"] = True
        except OSError:
            result["udp_refused"] = False
    if not result["forbidden_tcp_refused"] or (LAYER_SECCOMP in layers and not result["udp_refused"]):
        raise _fail("self-test-failed", f"the layers are installed but do not refuse what they must ({json.dumps(result, sort_keys=True)})")
    return result


# ---- measuring this host (doctor, the run's preflight) ---------------------------------------------------------------------------------------
_PROBE = "--probe"
PROBE_SETS = {"both": ALL_LAYERS, "seccomp": (LAYER_SECCOMP,), "landlock": (LAYER_LANDLOCK,)}


def all_ok(checks: Mapping[str, Any]) -> bool:
    """Every check passed: a probe with no check at all, or with one that is not exactly True, is not ok."""
    return bool(checks) and all(v is True for v in checks.values())


def probe_main(which: str = "both") -> int:
    """Run in a throwaway child: install one set of layers (both, or each alone: whether Landlock enforces by itself is measured here, where the seccomp layer cannot refuse first) around a
    synthetic allow-list (one loopback listener), then try what must pass and what must be refused, and print one JSON line."""
    layers = PROBE_SETS[which]
    out: Dict[str, Any] = {"facts": kernel_facts(), "set": which}
    allowed_l = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    other_l = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        allowed_l.bind(("127.0.0.1", 0))
        allowed_l.listen(4)
        other_l.bind(("127.0.0.1", 0))
        other_l.listen(4)
        port = allowed_l.getsockname()[1]
        policy = {"private": [{"host": "127.0.0.1", "networks": ["127.0.0.1/32"], "schemes": ["http"], "ports": [port], "label": "probe"}]}
        try:
            fence = install(policy, layers=layers)
        except FenceUnavailable as exc:
            out.update(ok=False, reason=exc.reason, message=exc.message[:300])
            print(json.dumps(out, sort_keys=True))
            return 0
        checks: Dict[str, bool] = {}
        c = socket.socket()
        c.settimeout(3)
        try:
            c.connect(("127.0.0.1", port))
            checks["allowed_connect_works"] = True
        except OSError:
            checks["allowed_connect_works"] = False
        finally:
            c.close()

        def refused(fn: Any) -> bool:
            try:
                fn().close()
                return False
            except PermissionError:
                return True
            except OSError:
                return False

        def bind_port_0() -> socket.socket:
            b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                b.bind(("127.0.0.1", 0))
            except BaseException:
                b.close()
                raise
            return b

        def listen_socket() -> socket.socket:
            b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                b.listen(1)
            except BaseException:
                b.close()
                raise
            return b
        checks["other_port_refused"] = refused(lambda: socket.create_connection(("127.0.0.1", other_l.getsockname()[1]), timeout=3))
        if LAYER_SECCOMP in layers:
            checks["udp_refused"] = refused(lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            checks["ipv6_refused"] = refused(lambda: socket.socket(socket.AF_INET6, socket.SOCK_STREAM))
            checks["listen_refused"] = refused(listen_socket)
        if LAYER_LANDLOCK in layers:
            checks["bind_refused"] = refused(bind_port_0)
        out.update(ok=all_ok(checks), checks=checks, layers=list(fence.layers), selftest=fence.selftest)
        fence.close()
    finally:
        allowed_l.close()
        other_l.close()
    print(json.dumps(out, sort_keys=True))
    return 0


def _probe_one(which: str, timeout_s: float) -> Dict[str, Any]:
    import subprocess
    done = subprocess.run([sys.executable, "-s", "-m", "qa_runner.netfence", _PROBE, which], capture_output=True, text=True, timeout=timeout_s,
                          env={"PATH": "/usr/bin:/bin", "PYTHONPATH": os.pathsep.join(p for p in sys.path if p and os.path.isdir(p))})
    doc = json.loads(done.stdout.strip().splitlines()[-1])
    if not isinstance(doc, dict) or "ok" not in doc:
        raise ValueError("not a probe result")
    return doc


def probe(timeout_s: float = 30.0) -> Dict[str, Any]:
    """Measure whether the layers work on this host, in throwaway child processes (the layers cannot be taken off the process that installs them): each layer ALONE first (so that a layer that
    does not enforce by itself is not hidden by the other one), then both. The result always has ``ok``; ``reason`` and ``message`` say why not; ``checks`` are those of the two layers
    together, ``per_set`` holds all three."""
    per_set: Dict[str, Any] = {}
    try:
        for which in ("landlock", "seccomp", "both"):
            doc = _probe_one(which, timeout_s)
            per_set[which] = doc
            if doc.get("ok") is not True:
                return {"ok": False, "reason": doc.get("reason", "layer-check-failed"), "message": str(doc.get("message") or f"the checks of the {which} layer(s) did not all pass: {doc.get('checks')}")[:300],
                        "facts": doc.get("facts") or kernel_facts(), "per_set": per_set}
        both = per_set["both"]
        return {"ok": True, "facts": both["facts"], "checks": both["checks"], "layers": both["layers"], "selftest": both["selftest"], "per_set": per_set}
    except Exception as exc:
        return {"ok": False, "reason": "probe-failed", "message": f"the probe could not run ({type(exc).__name__})", "facts": kernel_facts(), "per_set": per_set}


if __name__ == "__main__":
    sys.exit(probe_main(sys.argv[2] if len(sys.argv) == 3 else "both") if sys.argv[1:2] == [_PROBE] and (len(sys.argv) == 2 or sys.argv[2] in PROBE_SETS) else 2)
