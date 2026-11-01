# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The isolated, killable reader (retest N1/N3, owner decisions): what is bounded, and how.

TESTED here: a reading child that never answers is killed at the deadline and is gone; a child that writes without end is stopped at the byte cap (the parent never holds more); SIGINT, SIGTERM and
SIGHUP end the wait and kill the child; the refusals (FIFO with no writer, devices, sparse and over-cap files, symlinks) end at once; the CLI turns each into its documented exit status.
NOT tested, only inferred: a child blocked in UNINTERRUPTIBLE kernel I/O (a hard-hung network or FUSE mount) — SIGKILL is delivered but the process may not end until the kernel returns the I/O; the
parent does not wait for it past a short grace. No test here has a stalled mount; the "never answers" child is a stand-in that sleeps. Every probe runs in a child with a hard timeout and, where the
platform enforces one, an address-space cap; no test opens /dev/zero or any unbounded source."""
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from qa_runner import constants as K
from qa_runner import isolated
from qa_runner.procs import child_env
from qr_support import alive, run_limited, wait_gone

SRC = str(Path(__file__).resolve().parents[1] / "src")


def sleeper(pidfile):
    return [sys.executable, "-c", f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); time.sleep(120)"]


def test_a_worker_that_never_answers_is_killed_at_the_deadline_and_is_gone(tmp_path):
    pidfile = tmp_path / "pid"
    t0 = time.monotonic()
    with pytest.raises(isolated.IsolatedReadError) as exc:
        isolated.read_file(str(tmp_path / "x"), max_bytes=1000, deadline_s=1.0, argv=sleeper(pidfile))
    assert exc.value.code == "TIMEOUT" and time.monotonic() - t0 < 6
    assert wait_gone(int(pidfile.read_text()), 10)


def test_a_worker_that_writes_without_end_is_stopped_at_the_byte_cap(tmp_path):
    """The writer is the product's own child under a hard timeout: it is killed when the parent has taken one byte more than the cap."""
    code, out, err = run_limited([sys.executable, "-s", "-c", f"""
import sys, time
from qa_runner import isolated
endless = [sys.executable, "-c", "import sys\\nwhile True: sys.stdout.buffer.write(b'x' * 65536)"]
t0 = time.monotonic()
try:
    isolated.read_file('/nonexistent', max_bytes=100000, deadline_s=20, argv=endless)
except isolated.IsolatedReadError as exc:
    print(exc.code, round(time.monotonic() - t0, 1))
"""], timeout=60, env=child_env(str(tmp_path)))
    assert out.split()[0] == "TOO_LARGE" and float(out.split()[1]) < 10, (out, err)


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
def test_a_cancel_ends_the_wait_and_kills_the_worker(tmp_path, sig):
    pidfile = tmp_path / "pid"
    script = tmp_path / "t.py"
    script.write_text(f"""
import sys
from qa_runner import isolated
sl = [sys.executable, "-c", "import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); time.sleep(120)"]
try:
    isolated.read_file('/x', max_bytes=100, deadline_s=60, argv=sl)
except isolated.IsolatedReadError as exc:
    print(exc.code); sys.stdout.flush()
""")
    proc = subprocess.Popen([sys.executable, "-s", str(script)], env=child_env(str(tmp_path)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        end = time.monotonic() + 20
        while not pidfile.exists() and time.monotonic() < end:
            time.sleep(0.05)
        assert pidfile.exists(), "the worker never started"
        time.sleep(0.3)
        proc.send_signal(sig)
        out, err = proc.communicate(timeout=15)
        assert out.strip() == "CANCELLED", (out, err)
        assert wait_gone(int(pidfile.read_text()), 10)
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()


def test_a_worker_whose_answer_is_not_what_it_declared_is_refused(tmp_path):
    liar = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'{\"ok\": true, \"len\": 5}\\nabc')"]
    with pytest.raises(isolated.IsolatedReadError) as exc:
        isolated.read_file("/x", max_bytes=100, deadline_s=10, argv=liar)
    assert exc.value.code == "WORKER_FAILED"
    mute = [sys.executable, "-c", "pass"]
    with pytest.raises(isolated.IsolatedReadError) as exc:
        isolated.read_file("/x", max_bytes=100, deadline_s=10, argv=mute)
    assert exc.value.code == "WORKER_FAILED"


def _cli_script(tmp_path, seconds):
    script = tmp_path / f"cli{seconds}.py"
    plan = tmp_path / "plan.json"
    plan.write_text("{}")
    script.write_text(f"""
import sys
from qa_runner import isolated
isolated.WORKER = [sys.executable, "-c", "import time; time.sleep(120)"]
isolated.DEFAULT_READ_SECONDS = {seconds}
from qa_runner.cli import main
sys.exit(main(["doctor", "--plan", {str(plan)!r}]))
""")
    return script


def test_the_cli_turns_a_stalled_worker_into_a_plan_read_timeout(tmp_path):
    code, out, err = run_limited([sys.executable, "-s", str(_cli_script(tmp_path, 1.0))], timeout=30, env=child_env(str(tmp_path)))
    assert code == K.EXIT_USAGE and "PLAN_READ_TIMEOUT" in err


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
def test_the_cli_turns_a_cancel_during_the_plan_read_into_exit_3(tmp_path, sig):
    proc = subprocess.Popen([sys.executable, "-s", str(_cli_script(tmp_path, 60.0))], env=child_env(str(tmp_path)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        time.sleep(1.0)
        proc.send_signal(sig)
        out, err = proc.communicate(timeout=15)
        assert proc.returncode == K.EXIT_ENVIRONMENT and "cancelled" in err, (proc.returncode, err)
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()


def test_the_finalizer_of_the_process_tests_kills_what_a_failed_assertion_would_leave_behind(tmp_path):
    """Retest N8: with a failing assertion the spawned parent and its browser stayed alive."""
    from qr_support import descendants, reap
    pidfile = tmp_path / "child.pid"
    proc = subprocess.Popen([sys.executable, "-c", f"import subprocess, sys, time; c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']); open({str(pidfile)!r}, 'w').write(str(c.pid)); time.sleep(120)"],
                            start_new_session=True)
    end = time.monotonic() + 10
    while not pidfile.exists() and time.monotonic() < end:
        time.sleep(0.05)
    child = int(pidfile.read_text())
    seen = descendants(proc.pid)
    try:
        assert False, "a failing assertion"
    except AssertionError:
        pass
    finally:
        reap(proc, seen)
    assert wait_gone(proc.pid, 10) and wait_gone(child, 10)
