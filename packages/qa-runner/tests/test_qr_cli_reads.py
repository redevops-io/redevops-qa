# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Retest N1/N3 across the commands that read a user-supplied path: `freeze`, `run`, `report` and `inspect` (and `verify` from the next part). Every probe runs in a child with a hard timeout and,
where the platform enforces one, an address-space cap; the sources are FIFOs, /dev/null, sparse files, symlinks and entries of a bundle directory; the timeout and the three cancel signals are
exercised with a reading child that never answers. Nothing here opens /dev/zero or an unbounded source. What is inferred and not tested (a child stuck in uninterruptible kernel I/O) is in the README."""
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from qa_evidence.build import write_directory
from qa_runner import constants as K
from qa_runner.procs import child_env
from qr_support import fake, fake_robot, reap, run_limited

SRC = str(Path(__file__).resolve().parents[1] / "src")


def cli(tmp_path, *argv, timeout=60):
    return run_limited([sys.executable, "-s", "-m", "qa_runner", *argv], timeout=timeout, env=child_env(str(tmp_path)), cwd=str(tmp_path))


@pytest.fixture(scope="module")
def bundle(up, tmp_path_factory):
    """A bundle directory written by a run whose two engines are test doubles (it has every file of a real one; what is read is what matters here, not what the run proves)."""
    from qa_runner.golden import demo_plan
    from qa_runner.orchestrate import RunOptions, run_plan
    from qa_runner.plan import freeze_plan
    s = run_plan(up, freeze_plan(up, demo_plan()), RunOptions(lane_command=fake("pass"), robot_launcher=fake_robot("live"), lane_deadline_s=60, run_id="r0-test"))
    target = tmp_path_factory.mktemp("rb") / "b"
    write_directory(s.bundle.files, str(target))
    return target


@pytest.mark.parametrize("command", [["freeze"], ["run"], ["doctor", "--plan"]])
@pytest.mark.parametrize("kind", ["fifo", "devnull", "sparse", "symlink-to-fifo"])
def test_a_plan_that_is_not_a_small_regular_file_is_refused_by_every_command_that_reads_one(tmp_path, command, kind):
    path = tmp_path / "plan"
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "devnull":
        path = Path("/dev/null")
    elif kind == "sparse":
        with open(path, "wb") as fh:
            fh.truncate(300 * 1024 * 1024)
    else:
        os.mkfifo(tmp_path / "f")
        path.symlink_to(tmp_path / "f")
    tail = {"freeze": ["--out", str(tmp_path / "lock.json")], "run": ["--out", str(tmp_path / "o")], "doctor --plan": []}.get(" ".join(command), [])
    argv = command + [str(path)] + tail if command != ["doctor", "--plan"] else ["doctor", "--plan", str(path)]
    t0 = time.monotonic()
    code, out, err = cli(tmp_path, *argv)
    assert code == K.EXIT_USAGE and ("PLAN_NOT_A_FILE" in err or "PLAN_TOO_LARGE" in err), (command, kind, err)
    assert time.monotonic() - t0 < 30 and not (tmp_path / "lock.json").exists() and not (tmp_path / "o").exists()


@pytest.mark.parametrize("command", ["report", "inspect"])
@pytest.mark.parametrize("kind", ["fifo", "devnull", "sparse-archive", "symlink", "missing"])
def test_report_and_inspect_refuse_a_location_that_is_not_a_bundle_at_once(tmp_path, command, kind):
    path = tmp_path / "loc"
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "devnull":
        path = Path("/dev/null")
    elif kind == "sparse-archive":
        with open(path, "wb") as fh:
            fh.truncate(3 * 1024 * 1024 * 1024)
    elif kind == "symlink":
        (tmp_path / "d").mkdir()
        path.symlink_to(tmp_path / "d")
    t0 = time.monotonic()
    code, out, err = cli(tmp_path, command, str(path))
    if kind == "sparse-archive":                              # a 3 GiB file is a location that opens: its size is a finding (ARCHIVE_TOO_LARGE), and none of it is read
        assert code == 1 and "ARCHIVE_TOO_LARGE" in out, (code, out[:300])
    else:
        assert code == K.EXIT_USAGE and "BUNDLE_UNREADABLE" in err, (kind, code, err)
    assert time.monotonic() - t0 < 30


@pytest.mark.parametrize("command", ["report", "inspect"])
def test_a_special_or_huge_entry_inside_a_bundle_directory_is_a_finding_and_never_read(tmp_path, bundle, command):
    import shutil
    copy = tmp_path / "b"
    shutil.copytree(bundle, copy)
    os.mkfifo(copy / "logs" / "pipe")
    with open(copy / "logs" / "huge.bin", "wb") as fh:
        fh.truncate(400 * 1024 * 1024)
    t0 = time.monotonic()
    code, out, err = cli(tmp_path, command, str(copy))
    assert code == 1
    assert ("SPECIAL_FILE" in out or "FAILED" in out) and time.monotonic() - t0 < 30


def _script(tmp_path, command, seconds):
    script = tmp_path / f"c{command}{seconds}.py"
    bundle = tmp_path / "somebundle"
    bundle.mkdir(exist_ok=True)
    script.write_text(f"""
import sys
from qa_runner import isolated
isolated.WORKER = [sys.executable, "-c", "import time; time.sleep(120)"]
isolated.DEFAULT_BUNDLE_SECONDS = {seconds}
from qa_runner.cli import main
sys.exit(main([{command!r}, {str(bundle)!r}]))
""")
    return script


@pytest.mark.parametrize("command", ["report", "inspect"])
def test_a_stalled_read_of_a_bundle_is_ended_at_the_deadline(tmp_path, command):
    code, out, err = run_limited([sys.executable, "-s", str(_script(tmp_path, command, 1.0))], timeout=40, env=child_env(str(tmp_path)))
    assert code == K.EXIT_USAGE and "BUNDLE_READ_TIMEOUT" in err


@pytest.mark.parametrize("command", ["report", "inspect"])
@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
def test_a_cancel_while_a_bundle_is_read_ends_with_exit_3(tmp_path, command, sig):
    proc = subprocess.Popen([sys.executable, "-s", str(_script(tmp_path, command, 60.0))], env=child_env(str(tmp_path)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        time.sleep(1.0)
        proc.send_signal(sig)
        out, err = proc.communicate(timeout=20)
        assert proc.returncode == K.EXIT_ENVIRONMENT and "cancelled" in err, (proc.returncode, err)
    finally:
        reap(proc)


def test_report_and_inspect_read_the_bundle_once_into_a_snapshot_that_later_changes_cannot_reach(tmp_path, bundle, monkeypatch):
    """Retest N4 (the part #32 has): the verification, the summary and the chain heads come from ONE snapshot; a file changed after the snapshot was taken is not seen."""
    import io
    import shutil
    from qa_runner import isolated
    from qa_runner.cli import main
    copy = tmp_path / "b"
    shutil.copytree(bundle, copy)
    real = isolated.snapshot_bundle
    taken = []

    def snapshot_then_swap(location, **kw):
        snap = real(location, **kw)
        taken.append(snap)
        (copy / "report.json").write_bytes(b"{}\n")                  # changed after the snapshot was taken
        return snap
    monkeypatch.setattr(isolated, "snapshot_bundle", snapshot_then_swap)
    out, err = io.StringIO(), io.StringIO()
    code = main(["inspect", str(copy)], out, err)
    assert len(taken) == 1 and "verification: OK, internally consistent" in out.getvalue()      # the snapshot verifies; the changed file on disk would not
    assert "verdict: INCONCLUSIVE" in out.getvalue() and "lane browser:" in out.getvalue()      # the summary of the snapshot, not of the changed file
