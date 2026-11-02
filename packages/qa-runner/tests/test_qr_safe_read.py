# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Bounded reads (review finding R1 of the retest): a plan, a lock or a file a lane or the target wrote is read through ONE descriptor, regular files only, with a byte cap and a time cap.
Every probe runs in a child with a hard timeout (and an address-space cap where the platform has one); the sources are FIFOs, /dev/null, sparse and growing regular files, and writers that
are capped in size. Nothing here opens /dev/zero or any unbounded source."""
import json
import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

from qa_runner import constants as K
from qa_runner.golden import golden_plan
from qa_runner.plan import MAX_PLAN_BYTES
from qa_runner.procs import child_env
from qa_runner.safe_read import UnsafeRead, read_regular
from qr_support import run_limited


def freeze(tmp_path, path, timeout=60):
    """The command line given ``path`` as the plan: ``doctor --plan`` reads it through the same ``_read_plan`` as ``run`` and ``freeze`` (and starts nothing)."""
    env = child_env(str(tmp_path))
    return run_limited([sys.executable, "-s", "-m", "qa_runner", "doctor", "--plan", str(path)], timeout=timeout, env=env, cwd=str(tmp_path))


def test_a_fifo_with_no_writer_is_refused_at_once_and_nothing_hangs(tmp_path):
    fifo = tmp_path / "plan.fifo"
    os.mkfifo(fifo)
    t0 = time.monotonic()
    code, out, err = freeze(tmp_path, fifo, timeout=25)
    assert code == K.EXIT_USAGE and "PLAN_NOT_A_FILE" in err
    assert time.monotonic() - t0 < 20


def test_a_fifo_fed_more_than_the_cap_is_refused_without_a_single_byte_being_read(tmp_path):
    fifo = tmp_path / "plan.fifo"
    os.mkfifo(fifo)
    fd = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)                  # a capped writer: at most the pipe's own buffer, never blocking
    written = 0
    try:
        while written < MAX_PLAN_BYTES + 1:
            try:
                written += os.write(fd, b"x" * 65536)
            except BlockingIOError:
                break
        assert 0 < written <= MAX_PLAN_BYTES + 1
        code, out, err = freeze(tmp_path, fifo)
        assert code == K.EXIT_USAGE and "PLAN_NOT_A_FILE" in err
        left = b""
        while True:
            try:
                got = os.read(fd, 1 << 20)
            except BlockingIOError:
                break
            if not got:
                break
            left += got
        assert len(left) == written                                 # nothing was consumed by the refused read
    finally:
        os.close(fd)


def test_a_character_device_is_refused(tmp_path):
    code, out, err = freeze(tmp_path, "/dev/null")
    assert code == K.EXIT_USAGE and "PLAN_NOT_A_FILE" in err


def test_a_sparse_file_far_over_the_cap_is_refused_from_its_size_without_being_read(tmp_path):
    big = tmp_path / "plan.json"
    with open(big, "wb") as fh:
        fh.truncate(300 * 1024 * 1024)
    t0 = time.monotonic()
    code, out, err = freeze(tmp_path, big)
    assert code == K.EXIT_USAGE and "at most" in err and time.monotonic() - t0 < 25


def test_a_symlink_to_a_regular_plan_is_followed_once_and_a_link_to_a_fifo_is_not_read(tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(golden_plan()))
    link = tmp_path / "link.json"
    link.symlink_to(plan)
    code, out, err = freeze(tmp_path, link)
    assert "error:" not in err, err                                    # read and parsed (doctor itself may report on this machine)
    fifo = tmp_path / "f.fifo"
    os.mkfifo(fifo)
    flink = tmp_path / "flink.json"
    flink.symlink_to(fifo)
    code, out, err = freeze(tmp_path, flink)
    assert code == K.EXIT_USAGE and "PLAN_NOT_A_FILE" in err


def test_the_helper_stops_a_file_that_grows_while_it_is_read(tmp_path):
    """A regular file that is small when it is opened and grows (a capped writer thread appends up to 4 MiB): the read ends at the cap, it does not follow the file."""
    code, out, err = run_limited([sys.executable, "-s", "-c", f"""
import sys, threading, os
sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / 'src')!r})
from qa_runner.safe_read import read_regular, UnsafeRead
path = {str(tmp_path / 'grow.bin')!r}
open(path, 'wb').write(b'x' * 10)
stop = threading.Event()
def grow():
    with open(path, 'ab') as fh:
        for _ in range(64):
            if stop.is_set(): return
            fh.write(b'y' * 65536); fh.flush()
t = threading.Thread(target=grow); t.start()
try:
    read_regular(path, max_bytes=256 * 1024)
    print('NO ERROR')
except UnsafeRead as exc:
    print(exc.code)
stop.set(); t.join()
"""], timeout=30, env=child_env(str(tmp_path)))                  # the module roots come from the product's own list: the read now lives in the adapter kit
    assert out.strip() in ("TOO_LARGE", "NO ERROR"), (out, err)
    # whichever way the race went the read ended; a second, deterministic form of the same rule:
    path = tmp_path / "big.bin"
    path.write_bytes(b"z" * 2048)
    with pytest.raises(UnsafeRead) as exc:
        read_regular(str(path), max_bytes=1024)
    assert exc.value.code == "TOO_LARGE"
    assert read_regular(str(path), max_bytes=2048) == b"z" * 2048


def test_the_running_total_caps_a_read_whose_size_was_small_at_the_open(tmp_path, monkeypatch):
    path = tmp_path / "liar.bin"
    path.write_bytes(b"q" * 5000)
    real = os.fstat
    monkeypatch.setattr(os, "fstat", lambda fd: type("S", (), {"st_mode": real(fd).st_mode, "st_size": 10})())      # fstat says 10 bytes, the file has 5000
    with pytest.raises(UnsafeRead) as exc:
        read_regular(str(path), max_bytes=1000)
    assert exc.value.code == "TOO_LARGE"


def test_a_read_that_runs_out_of_time_is_stopped(tmp_path):
    path = tmp_path / "f.bin"
    path.write_bytes(b"x" * 100)
    with pytest.raises(UnsafeRead) as exc:
        read_regular(str(path), max_bytes=1000, deadline_s=-1)
    assert exc.value.code == "TIMEOUT"


def test_an_internal_read_never_follows_a_symlink_and_never_opens_a_fifo_blocking(tmp_path):
    real = tmp_path / "real.json"
    real.write_text("{}")
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(UnsafeRead) as exc:
        read_regular(str(link), max_bytes=100, follow_symlinks=False)
    assert exc.value.code == "NOT_A_REGULAR_FILE"
    fifo = tmp_path / "x.fifo"
    os.mkfifo(fifo)
    t0 = time.monotonic()
    with pytest.raises(UnsafeRead) as exc:
        read_regular(str(fifo), max_bytes=100, follow_symlinks=False)
    assert exc.value.code == "NOT_A_REGULAR_FILE" and time.monotonic() - t0 < 2
    assert read_regular(str(real), max_bytes=100, follow_symlinks=False) == b"{}"


def test_the_orchestrators_reads_of_lane_and_target_files_are_the_same_bounded_read(tmp_path):
    from qa_runner.orchestrate import _read_bounded
    fifo = tmp_path / "lane-result.json"
    os.mkfifo(fifo)
    t0 = time.monotonic()
    assert _read_bounded(fifo, 1000) is None and time.monotonic() - t0 < 2
    link = tmp_path / "l"
    (tmp_path / "t").write_text("x")
    link.symlink_to(tmp_path / "t")
    assert _read_bounded(link, 1000) is None and _read_bounded(tmp_path / "t", 1000) == b"x" and _read_bounded(tmp_path / "t", 0) is None
    assert _read_bounded(tmp_path / "missing", 10) is None
    assert _read_bounded(tmp_path, 10) is None                                              # a directory


def test_the_lane_input_is_read_through_the_bounded_read(tmp_path):
    code, out, err = run_limited([sys.executable, "-s", "-m", "qa_runner.lane_browser", str(tmp_path)], timeout=20, env=child_env(str(tmp_path)), cwd=str(tmp_path))
    assert code == 2 and "lane input unreadable: UnsafeRead" in err


def test_a_file_larger_than_the_cap_is_refused_before_a_single_read(tmp_path, monkeypatch):
    big = tmp_path / "sparse.bin"
    with open(big, "wb") as fh:
        fh.truncate(300 * 1024 * 1024)
    reads = []
    real = os.read
    monkeypatch.setattr(os, "read", lambda fd, n: reads.append(n) or real(fd, n))
    with pytest.raises(UnsafeRead) as exc:
        read_regular(str(big), max_bytes=1000)
    assert exc.value.code == "TOO_LARGE" and reads == []


@pytest.mark.parametrize("kind", ["fifo", "devnull", "sparse", "symlink-to-fifo", "directory"])
def test_run_refuses_an_unusable_plan_at_once_and_creates_nothing(tmp_path, kind):
    """Retest N3: the same refusals for `run` (the command that would start a target), in a time-capped child; the output directory is not created."""
    path = tmp_path / "plan"
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "devnull":
        path = Path("/dev/null")
    elif kind == "sparse":
        with open(path, "wb") as fh:
            fh.truncate(300 * 1024 * 1024)
    elif kind == "symlink-to-fifo":
        os.mkfifo(tmp_path / "f")
        path.symlink_to(tmp_path / "f")
    else:
        path.mkdir()
    out = tmp_path / "out"
    t0 = time.monotonic()
    code, so, err = run_limited([sys.executable, "-s", "-m", "qa_runner", "run", str(path), "--out", str(out)], timeout=60, env=child_env(str(tmp_path)), cwd=str(tmp_path))
    assert code == K.EXIT_USAGE and ("PLAN_NOT_A_FILE" in err or "PLAN_TOO_LARGE" in err or "PLAN_UNREADABLE" in err), (kind, err)
    assert not out.exists() and time.monotonic() - t0 < 30
