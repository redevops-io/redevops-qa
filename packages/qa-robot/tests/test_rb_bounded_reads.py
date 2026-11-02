# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The Robot adapter reads what the engine wrote and what a suite contains through the kit's bounded read (retest L-R1): a FIFO where the report should be, a symbolic link in the engine's home or in the
workspace, an oversize file: refused, never waited for. The FIFO probes run in a child with a hard timeout so a regression cannot hang the suite."""
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from qa_adapter_kit import MalformedReport, PolicyRefused, RunLayout, SuiteRunRequest
from qa_adapter_kit.supervisor import ProcessOutcome
from qa_robot import RobotConfig, RobotSuiteAdapter

from rb_support import SIMPLE, workspace

SRC = [str(Path(__file__).resolve().parents[1] / "src"), str(Path(__file__).resolve().parents[2] / "qa-adapter-kit" / "src")]


def setup(tmp_path, create=True):
    ws, out = (tmp_path / "workspace", tmp_path / "output")
    home = tmp_path / "home"
    if create:
        workspace(tmp_path)
        (home / "robot").mkdir(parents=True)
    layout = RunLayout(workspace=ws, suite=ws / "suite", output_dir=out, home=home)
    request = SuiteRunRequest(run_id="r1", adapter_id="robot-suite", workspace=str(ws), suite_path="suite", output_dir=str(out))
    return layout, request, ProcessOutcome(exit_code=0, signal=None, stdout=b"", stderr=b"", duration_s=0.1)


def test_a_fifo_where_the_report_should_be_is_refused_at_once_never_waited_for(tmp_path):
    layout, request, outcome = setup(tmp_path)
    os.mkfifo(layout.home / "robot" / "output.xml")
    code = (f"import sys\nsys.path[:0] = {SRC!r}\nsys.path.insert(0, {str(Path(__file__).parent)!r})\nfrom test_rb_bounded_reads import setup\nfrom qa_adapter_kit import MalformedReport\n"
            f"from qa_robot import RobotSuiteAdapter\nfrom pathlib import Path\nl, r, o = setup(Path({str(tmp_path)!r}), create=False)\n"
            "try:\n    RobotSuiteAdapter(sys.executable).import_report(r, l, o)\nexcept MalformedReport as e:\n    print('REFUSED', e)\n")
    t0 = time.monotonic()
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
    assert "REFUSED" in done.stdout and time.monotonic() - t0 < 20, done.stderr[-300:]


def test_a_report_that_is_a_symlink_or_in_a_linked_directory_is_refused(tmp_path):
    layout, request, outcome = setup(tmp_path)
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "output.xml").write_bytes(b"<robot/>")
    (layout.home / "robot" / "output.xml").symlink_to(tmp_path / "elsewhere" / "output.xml")
    with pytest.raises(MalformedReport):
        RobotSuiteAdapter(sys.executable).import_report(request, layout, outcome)
    (layout.home / "robot" / "output.xml").unlink()
    (layout.home / "robot").rmdir()
    (layout.home / "robot").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(MalformedReport):
        RobotSuiteAdapter(sys.executable).import_report(request, layout, outcome)


def test_a_report_over_the_cap_is_refused_without_being_parsed(tmp_path):
    layout, request, outcome = setup(tmp_path)
    with open(layout.home / "robot" / "output.xml", "wb") as fh:
        fh.truncate(33 * 1024 * 1024)
    with pytest.raises(MalformedReport):
        RobotSuiteAdapter(sys.executable).import_report(request, layout, outcome)


def test_a_suite_file_that_is_a_link_or_oversize_is_refused_by_the_scan(tmp_path):
    from qa_robot.policy import scan_suite
    ws, out = workspace(tmp_path)
    (ws / "suite" / "big.robot").write_bytes(b"#" * 1_000_001)
    with pytest.raises(PolicyRefused):
        scan_suite(ws, ws / "suite", RobotConfig())
    (ws / "suite" / "big.robot").unlink()
    (ws / "suite" / "link.robot").symlink_to(ws / "suite" / "suite.robot")
    with pytest.raises(PolicyRefused):
        scan_suite(ws, ws / "suite", RobotConfig())


def test_a_reviewed_library_that_is_replaced_by_a_link_is_refused(tmp_path):
    from qa_robot.policy import scan_suite
    text = "*** Settings ***\nLibrary    lib.py\n\n*** Test Cases ***\nT\n    Log    x\n"
    ws, out = workspace(tmp_path, text)
    (ws / "suite" / "real_lib.py").write_text("def f():\n    pass\n")
    (ws / "suite" / "lib.py").symlink_to(ws / "suite" / "real_lib.py")
    import hashlib
    config = RobotConfig(allowed_library_files={"suite/lib.py": hashlib.sha256((ws / "suite" / "real_lib.py").read_bytes()).hexdigest()})
    with pytest.raises((PolicyRefused, Exception)):
        scan_suite(ws, ws / "suite", config)
