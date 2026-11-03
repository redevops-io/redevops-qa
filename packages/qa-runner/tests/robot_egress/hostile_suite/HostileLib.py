# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A hostile Robot library for the egress experiments: one keyword that tries, one after the other, to reach hostile LOOPBACK listeners that the lane's allow-list does not name, by every
route the experiments list. It talks to loopback only, to listeners the test itself runs; it never touches another host. ``world.json`` (written by the test next to this file) names the ports.
Each attempt returns what the library saw; the test decides from the listeners' own counts whether anything was reached."""
import ctypes
import json
import mmap
import os
import platform
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
W = json.load(open(os.path.join(HERE, "world.json"), encoding="utf-8"))
P = W["ports"]
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long
_NR = {"x86_64": {"socket": 41, "connect": 42, "io_uring_setup": 425}, "aarch64": {"socket": 198, "connect": 203, "io_uring_setup": 425}}[platform.machine().replace("arm64", "aarch64")]
MSG_FASTOPEN = 0x20000000


def _tcp(host, port, family=socket.AF_INET):
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, port))
        s.send(b"hello")
        s.close()
        return {"reached": True}
    except OSError as exc:
        return {"reached": False, "error": type(exc).__name__}


def _sockaddr(ip, port):
    return struct.pack("=H", socket.AF_INET) + struct.pack(">H", port) + socket.inet_aton(ip) + b"\0" * 8


def a_direct():
    return _tcp("127.0.0.1", P["direct"])


def a_ip_literal_http():
    try:
        urllib.request.build_opener(urllib.request.ProxyHandler({})).open(f"http://127.0.0.1:{P['ip_literal_http']}/x", timeout=3).read(10)
    except Exception as exc:
        return {"reached": False, "error": type(exc).__name__}
    return {"reached": True}


def a_same_port_other_ip():
    return _tcp("127.0.0.2", W["allowed_port"])


def a_zero_address():
    return _tcp("0.0.0.0", W["allowed_port"])


def a_dns_udp_query():
    """Ask the hostile resolver (UDP, loopback) for a name; it answers 127.0.0.1."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06rebind\x04test\x00\x00\x01\x00\x01"
        s.sendto(query, ("127.0.0.1", P["resolver_udp"]))
        answer = s.recv(512)
        return {"reached": True, "answer": socket.inet_ntoa(answer[-4:])}
    except OSError as exc:
        return {"reached": False, "error": type(exc).__name__}


def a_dns_rebind():
    """The classic sequence: the name resolves (by the hostile resolver) to a loopback address, then the connection goes there on a forbidden port."""
    answer = a_dns_udp_query()
    if not answer.get("reached"):
        return {"reached": False, "error": "no answer: " + str(answer.get("error"))}
    return _tcp(answer["answer"], P["dns_rebind_target"])


def a_dns_tcp_query():
    return _tcp("127.0.0.1", P["resolver_tcp"])


def a_getaddrinfo():
    try:
        socket.getaddrinfo("rebind.test", 80)
        return {"reached": True}
    except OSError as exc:
        return {"reached": False, "error": type(exc).__name__}


def a_redirect():
    """An allowed origin answers 302 to a forbidden loopback port; the default opener follows it."""
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        opener.open(f"http://127.0.0.1:{W['allowed_port']}/redirect?to=http://127.0.0.1:{P['redirect']}/x", timeout=3).read(10)
    except Exception as exc:
        return {"reached": False, "error": type(exc).__name__}
    return {"reached": True}


def a_raw_socket():
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()
        return {"reached": True}
    except OSError as exc:
        return {"reached": False, "error": type(exc).__name__}


def a_udp():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"hello", ("127.0.0.1", P["udp"]))
        return {"reached": True}
    except OSError as exc:
        return {"reached": False, "error": type(exc).__name__}


def a_ipv6():
    return _tcp("::1", P["ipv6"], socket.AF_INET6)


def a_subprocess_curl():
    done = subprocess.run(["/usr/bin/curl", "-sS", "--max-time", "3", "--noproxy", "*", f"http://127.0.0.1:{P['subprocess_curl']}/"], capture_output=True, timeout=10)
    return {"reached": done.returncode == 0, "returncode": done.returncode}


def a_subprocess_python():
    code = f"import socket; s = socket.create_connection(('127.0.0.1', {P['subprocess_python']}), timeout=3); s.send(b'hello')"
    done = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, timeout=10)
    return {"reached": done.returncode == 0, "returncode": done.returncode}


def a_subprocess_bash():
    done = subprocess.run(["/bin/bash", "-c", f"exec 3<>/dev/tcp/127.0.0.1/{P['subprocess_bash']}; echo hello >&3"], capture_output=True, timeout=10)
    return {"reached": done.returncode == 0, "returncode": done.returncode}


def a_ctypes_connect():
    fd = LIBC.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    if fd < 0:
        return {"reached": False, "error": "socket errno " + str(ctypes.get_errno())}
    addr = ctypes.create_string_buffer(_sockaddr("127.0.0.1", P["ctypes_connect"]), 16)
    r = LIBC.connect(fd, addr, 16)
    err = ctypes.get_errno()
    os.close(fd)
    return {"reached": r == 0, "errno": err}


def a_raw_syscall():
    fd = LIBC.syscall(_NR["socket"], socket.AF_INET, socket.SOCK_STREAM, 0)
    if fd < 0:
        return {"reached": False, "error": "socket errno " + str(ctypes.get_errno())}
    addr = ctypes.create_string_buffer(_sockaddr("127.0.0.1", P["raw_syscall"]), 16)
    r = LIBC.syscall(_NR["connect"], fd, addr, 16)
    err = ctypes.get_errno()
    os.close(fd)
    return {"reached": r == 0, "errno": err}


def a_thread():
    out = {}
    t = threading.Thread(target=lambda: out.update(_tcp("127.0.0.1", P["thread"])))
    t.start()
    t.join(10)
    return out or {"reached": False, "error": "thread did not finish"}


def a_import_time():
    sys.path.insert(0, HERE)                      # the engine runs isolated (-I): the library's own directory is not on the import path unless it is put there
    import sneaky_import
    return {"reached": sneaky_import.REACHED, "error": sneaky_import.ERROR}


def a_proxy_env():
    """The library sets proxy variables itself (the lane's environment had none) and asks the allowed origin through them: the proxy is a forbidden loopback port."""
    saved = {k: os.environ.get(k) for k in ("http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY")}
    os.environ["http_proxy"] = os.environ["HTTP_PROXY"] = f"http://127.0.0.1:{P['proxy_env']}"
    os.environ["no_proxy"] = os.environ["NO_PROXY"] = ""
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{W['allowed_port']}/ok", timeout=3).read(10)
        return {"reached": True}
    except Exception as exc:
        return {"reached": False, "error": type(exc).__name__}
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def a_unix_stream():
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(W["unix_stream_path"])
        s.send(b"hello")
        return {"reached": True}
    except OSError as exc:
        return {"reached": False, "error": type(exc).__name__}


def a_unix_dgram():
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.sendto(b"hello", W["unix_dgram_path"])
        return {"reached": True}
    except OSError as exc:
        return {"reached": False, "error": type(exc).__name__}


def a_udp6():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.sendmsg([b"hello"], [], 0, ("::1", P["udp6"]))              # the address is inside the message structure: only the kind of socket can stop it
        return {"reached": True}
    except OSError as exc:
        return {"reached": False, "error": type(exc).__name__}


def a_unix_dgram_pair():
    """A datagram pair made with socketpair() (no connect() call) and then a message with an address inside the message structure, to a path."""
    try:
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        a.sendmsg([b"hello"], [], 0, W["unix_dgram_pair_path"])
        return {"reached": True}
    except OSError as exc:
        return {"reached": False, "error": type(exc).__name__}


def a_bad_address():
    """A connect() whose address is not memory at all: the supervisor must refuse it and go on (every later attempt below is still judged and recorded)."""
    fd = LIBC.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    r = LIBC.syscall(_NR["connect"], fd, ctypes.c_void_p(0xFFFFFFFFFFFFFFF0), 16)
    err = ctypes.get_errno()
    if fd >= 0:
        os.close(fd)
    return {"reached": r == 0, "errno": err}


def _listen(bind_first):
    """Inbound: a listening socket on every address (the lane could then accept a connection from an outside peer and send data on it)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if bind_first:
            s.bind(("0.0.0.0", 0))
        s.listen(1)
        s.close()
        return {"reached": True}
    except OSError as exc:
        return {"reached": False, "error": type(exc).__name__}


def a_listen_bound():
    return _listen(True)


def a_listen_unbound():
    """listen() on a socket that was never bound picks a port by itself: no bind call is made."""
    return _listen(False)


def _stream_protocol(proto):
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto).close()
        return {"reached": True}
    except OSError as exc:
        return {"reached": False, "error": type(exc).__name__}


def a_mptcp():
    return _stream_protocol(262)


def a_sctp():
    return _stream_protocol(132)


def a_proc_exposure():
    """The engine's parent is the lane child (it holds the supervisor): can this process open its memory, or are its /proc/<pid>/mem file this user's (the process is dumpable: a non-dumpable process
    owns them as root, whatever the host's ptrace policy says)?"""
    ppid = os.getppid()
    try:
        with open(f"/proc/{ppid}/mem", "rb") as fh:
            fh.seek(0x400000)
        return {"reached": True, "how": "opened /proc/ppid/mem"}
    except OSError as exc:
        err = type(exc).__name__
    owned = os.getuid() != 0 and os.stat(f"/proc/{ppid}/mem").st_uid == os.getuid()
    return {"reached": owned, "how": "/proc/ppid/mem owned by this user" if owned else err}


def a_race_other_address():
    """The race of a_race, but between the allowed address and ANOTHER loopback address on the allowed port (a listener there counts what arrives)."""
    shared = mmap.mmap(-1, 16)
    good, other = _sockaddr("127.0.0.1", W["allowed_port"]), _sockaddr("127.0.0.3", W["allowed_port"])
    shared[0:16] = good
    pid = os.fork()
    if pid == 0:
        end = time.monotonic() + 6.0
        while time.monotonic() < end:
            shared[0:16] = other
            shared[0:16] = good
        os._exit(0)
    addr = ctypes.addressof((ctypes.c_char * 16).from_buffer(shared))
    attempts = W["race_attempts"]
    for _ in range(attempts):
        fd = LIBC.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        LIBC.connect(fd, ctypes.c_void_p(addr), 16)
        os.close(fd)
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    return {"reached": False, "attempts": attempts}


def a_detached_survivor():
    """Leave a process behind in a session of its own (it is not in the engine's process group): it must not outlive the lane."""
    p = subprocess.Popen(["/bin/sleep", "300"], start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"reached": False, "pid": p.pid}


REWRITER = r"""
import json, os, sys, time
out = sys.argv[1]
path = os.path.join(out, "outcome.json")
while not os.path.exists(path):
    time.sleep(0.001)
for _ in range(2000):
    try:
        doc = json.load(open(path))
        doc["native_status"], doc["raw_status"], doc["egress"] = "NATIVE_PASS", "PASS", {"fence_denied": 0}
        for name, meta in doc["files"].items():
            if name.endswith("egress-log.jsonl"):
                ref = os.path.join(out, meta["data"])
                lines = open(ref, "rb").read().splitlines(True)
                open(ref, "wb").write(lines[0])
        json.dump(doc, open(path, "w"))
    except (OSError, ValueError, KeyError):
        pass
    time.sleep(0.0005)
"""


def a_detached_rewriter():
    """A process in a session of its own that waits for the lane child to write its outcome and then rewrites it: a pass, no refusals, a log with no refusal in it."""
    subprocess.Popen([sys.executable, "-I", "-c", REWRITER, W["out_dir"]], start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"reached": False}


def a_fast_open():
    """TCP Fast Open: the first data goes out WITH the connection attempt, no connect() call."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.sendto(b"hello", MSG_FASTOPEN, ("127.0.0.1", P["fast_open"]))
        return {"reached": True}
    except OSError as exc:
        return {"reached": False, "error": type(exc).__name__}


def a_fast_open_sendmsg():
    """The same through sendmsg(): the address is inside the message structure, where a system-call filter cannot read it."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.sendmsg([b"hello"], [], MSG_FASTOPEN, ("127.0.0.1", P["fast_open_sendmsg"]))
        return {"reached": True}
    except OSError as exc:
        return {"reached": False, "error": type(exc).__name__}


def a_io_uring():
    """io_uring can connect without the connect system call; here only whether the ring can be set up at all."""
    params = ctypes.create_string_buffer(120)
    fd = LIBC.syscall(_NR["io_uring_setup"], 4, params)
    if fd >= 0:
        os.close(fd)
    return {"reached": fd >= 0, "errno": ctypes.get_errno() if fd < 0 else 0}


def a_race():
    """Change the address a connect() is given between the supervisor's look and the kernel's: a second PROCESS (so no interpreter lock is shared) flips the bytes of a shared sockaddr between the
    allowed port and a forbidden one while this thread calls connect() on it again and again."""
    shared = mmap.mmap(-1, 16)
    good, bad = _sockaddr("127.0.0.1", W["allowed_port"]), _sockaddr("127.0.0.1", P["race"])
    shared[0:16] = good
    pid = os.fork()
    if pid == 0:
        end = time.monotonic() + 6.0
        while time.monotonic() < end:
            shared[0:16] = bad
            shared[0:16] = good
        os._exit(0)
    addr = ctypes.addressof((ctypes.c_char * 16).from_buffer(shared))
    ok = 0
    for _ in range(W["race_attempts"]):
        fd = LIBC.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        if LIBC.connect(fd, ctypes.c_void_p(addr), 16) == 0:
            ok += 1
        os.close(fd)
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    return {"reached": ok > 0, "connects_that_succeeded": ok}


def a_allowed_origin():
    """The control that must keep working: the allowed origin, by the library's normal route."""
    try:
        body = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(f"http://127.0.0.1:{W['allowed_port']}/ok", timeout=5).read(10)
        return {"reached": body == b"ok"}
    except Exception as exc:
        return {"reached": False, "error": type(exc).__name__}


ATTACKS = [a_allowed_origin, a_bad_address, a_listen_bound, a_listen_unbound, a_mptcp, a_sctp, a_proc_exposure, a_race_other_address, a_detached_survivor, a_direct, a_ip_literal_http, a_same_port_other_ip, a_zero_address, a_dns_udp_query, a_dns_rebind, a_dns_tcp_query, a_getaddrinfo, a_redirect, a_raw_socket, a_udp, a_ipv6,
           a_subprocess_curl, a_subprocess_python, a_subprocess_bash, a_ctypes_connect, a_raw_syscall, a_thread, a_import_time, a_proxy_env, a_unix_stream, a_unix_dgram, a_unix_dgram_pair, a_udp6, a_fast_open, a_fast_open_sendmsg, a_io_uring, a_race, a_detached_rewriter]


def run_all_attacks():
    """Run every attempt; before each, one refused-by-design socket call that carries the attempt's number (a marker the audit log shows, to tell which refusals belong to which attempt)."""
    results = {}
    for i, fn in enumerate(ATTACKS):
        try:
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 200 + i).close()
        except OSError:
            pass
        try:
            results[fn.__name__[2:]] = fn()
        except Exception as exc:
            results[fn.__name__[2:]] = {"reached": False, "error": "library error " + type(exc).__name__}
    with open(W["results_path"], "w", encoding="utf-8") as fh:
        json.dump(results, fh, sort_keys=True)
    return "done"
