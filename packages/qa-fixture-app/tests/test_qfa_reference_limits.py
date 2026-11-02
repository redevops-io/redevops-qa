# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The reference check is bounded (review finding R3 of the retest): no answer larger than its cap is read, the whole run has a deadline (not one per socket operation), and a cancel ends it.
Each probe runs in a child with a hard timeout (and an address-space cap where the platform enforces one); the servers are capped (at most 64 MiB, or 25 seconds)."""
import subprocess
import sys
import textwrap

SRC = __import__("pathlib").Path(__file__).resolve().parents[1] / "src"

PRELUDE = f"""
import resource, socket, sys, threading, time
try:
    resource.setrlimit(resource.RLIMIT_AS, (1536 * 2**20, 1536 * 2**20))
except (ValueError, OSError, AttributeError):
    pass
sys.path.insert(0, {str(SRC)!r})
from qa_fixture_app import reference_check as rc

def serve(handler):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5); srv.settimeout(40)
    def loop():
        try:
            while True:
                conn, _ = srv.accept()
                threading.Thread(target=handler, args=(conn,), daemon=True).start()
        except OSError:
            pass
    threading.Thread(target=loop, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.getsockname()[1]

def read_request(conn):
    conn.settimeout(5)
    data = b""
    while b"\\r\\n\\r\\n" not in data:
        data += conn.recv(4096)
"""


def child(code: str, timeout: float = 90.0) -> str:
    proc = subprocess.run([sys.executable, "-c", PRELUDE + textwrap.dedent(code)], capture_output=True, text=True, timeout=timeout)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


def test_an_answer_larger_than_the_cap_is_not_read_beyond_it():
    out = child("""
        sent = [0]
        def big(conn):
            try:
                read_request(conn)
                conn.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nContent-Length: %d\\r\\n\\r\\n" % (64 * 2**20))
                chunk = b"x" * 65536
                while sent[0] < 64 * 2**20:                      # a capped server: at most 64 MiB
                    conn.sendall(chunk); sent[0] += len(chunk)
            except OSError:
                pass
        srv, url = serve(big)
        t0 = time.monotonic()
        try:
            rc.run_checks(url, max_bytes=1024 * 1024, deadline_s=30)
            print("NO ERROR")
        except rc.CheckAborted as exc:
            print("ABORTED", exc)
        print("SECONDS", round(time.monotonic() - t0, 1), "RSS_MB", int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024 if sys.platform == "darwin" else 1024)))
        """)
    assert "ABORTED an answer is larger than 1048576 bytes" in out
    seconds = float(out.split("SECONDS")[1].split()[0])
    assert seconds < 10
    assert int(out.split("RSS_MB")[1].split()[0]) < 200                  # the 64 MiB answer was not accumulated


def test_a_server_that_drips_one_byte_at_a_time_is_ended_by_the_total_deadline_not_the_per_read_timeout():
    out = child("""
        def drip(conn):
            try:
                read_request(conn)
                conn.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 1000\\r\\n\\r\\n")
                for _ in range(50):                               # a capped server: one byte every 0.5 s, 25 s at most
                    conn.sendall(b"x"); time.sleep(0.5)
            except OSError:
                pass
        srv, url = serve(drip)
        t0 = time.monotonic()
        try:
            rc.run_checks(url, deadline_s=3)
            print("NO ERROR")
        except rc.CheckAborted as exc:
            print("ABORTED", exc)
        print("SECONDS", round(time.monotonic() - t0, 1))
        """)
    assert "ABORTED" in out and "deadline" in out
    assert float(out.split("SECONDS")[1].split()[0]) < 8


def test_a_server_that_drips_its_headers_is_ended_by_the_total_deadline_too():
    out = child("""
        def drip(conn):
            try:
                read_request(conn)
                for ch in b"HTTP/1.1 200 OK\\r\\nX-Slow: " + b"a" * 40:
                    conn.sendall(bytes([ch])); time.sleep(0.4)
            except OSError:
                pass
        srv, url = serve(drip)
        t0 = time.monotonic()
        try:
            rc.run_checks(url, deadline_s=3)
            print("NO ERROR")
        except rc.CheckAborted as exc:
            print("ABORTED", exc)
        print("SECONDS", round(time.monotonic() - t0, 1))
        """)
    assert "ABORTED" in out and float(out.split("SECONDS")[1].split()[0]) < 8


def test_a_cancel_ends_the_check_during_a_stalled_request():
    out = child("""
        def stall(conn):
            try:
                read_request(conn)
                conn.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 1000\\r\\n\\r\\n")
                time.sleep(20)                                    # capped: 20 s
            except OSError:
                pass
        srv, url = serve(stall)
        flag = {"cancel": False}
        threading.Timer(1.0, lambda: flag.update(cancel=True)).start()
        t0 = time.monotonic()
        try:
            rc.run_checks(url, deadline_s=30, cancelled=lambda: flag["cancel"])
            print("NO ERROR")
        except rc.CheckAborted as exc:
            print("ABORTED", exc)
        print("SECONDS", round(time.monotonic() - t0, 1))
        """)
    assert "ABORTED the run was cancelled" in out and float(out.split("SECONDS")[1].split()[0]) < 6
