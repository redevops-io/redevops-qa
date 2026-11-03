# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A lane child that is killed by a signal, through the real orchestrator path (``run_plan`` with the product's own handling of a child; only the command the child runs is replaced by the test
double of ``fake_lane.py``, which has no way to produce a verdict by itself). Whatever the child left behind, the lane is an engine error, the run is INCONCLUSIVE with exit 3, nothing is a
sealed pass, no process the child started survives, and the bundle is one that ``verify`` accepts as honest (not one it refuses as a relabelled status)."""
import json
import sys

import pytest

import qa_runner.orchestrate as orchestrate
from qa_runner import constants as K
from qa_runner.orchestrate import RunOptions, run_plan
from qr_support import FAKE, wait_gone
from qr_tamper import codes, verify_files_in


@pytest.fixture()
def real_lane_path(monkeypatch, tmp_path):
    """Run the real orchestrator path (no ``lane_command``, so the lane is not marked as a test double) with the double standing in for the child."""
    pidfile = tmp_path / "grandchild.pid"
    real = orchestrate.run_child

    def run_child(argv, **kw):
        return real([sys.executable, FAKE, run_child.mode, argv[-1], str(pidfile)], **kw)
    monkeypatch.setattr(orchestrate, "run_child", run_child)
    run_child.pidfile = pidfile
    return run_child


@pytest.mark.parametrize("mode", ["crash-before-result", "crash-after-result"])
def test_a_child_killed_by_a_signal_is_a_lane_error_never_a_pass_and_leaves_nothing_behind(up, golden_frozen, real_lane_path, tmp_path, mode):
    real_lane_path.mode = mode
    s = run_plan(up, golden_frozen, RunOptions(lane_deadline_s=60, run_id="r0-crash"))
    r = json.loads(s.bundle.files["report.json"])
    assert (s.outcome, s.exit_code, s.lanes) == ("INCONCLUSIVE", K.EXIT_ENVIRONMENT, (("browser", "NATIVE_ERROR"),)), (s.outcome, s.lanes)
    assert r["lanes"][0]["native"]["raw_status"] == "child-signal-9" and r["verdict"]["outcome"] == "INCONCLUSIVE"
    assert r["accounting"]["verified"] == 0 and r["accounting"]["failed"] == 0 and r["accounting"]["inconclusive"] == 3
    assert "TEST_DOUBLE" not in json.dumps(r["accounting"]["results"]) and "test_double" not in (r.get("extensions") or {})        # the real path, not the lane-command seam
    pid = int(real_lane_path.pidfile.read_text())
    assert wait_gone(pid, 10), "the grandchild the killed child had started survived"


def test_nothing_the_killed_child_wrote_is_kept_as_the_engines_own_record_so_verify_accepts_the_bundle_as_honest(up, golden_frozen, real_lane_path, tmp_path):
    real_lane_path.mode = "crash-after-result"           # a complete PASS result file exists when the child dies
    s = run_plan(up, golden_frozen, RunOptions(lane_deadline_s=60, run_id="r0-crash"))
    assert not [p for p in s.bundle.files if p.startswith("lanes/browser/native/")], sorted(s.bundle.files)
    v = verify_files_in(tmp_path, s.bundle.files)
    assert "NATIVE_STATUS_RELABELLED" not in codes(v) and v.accepted, codes(v)
