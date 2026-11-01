# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The lane child process plumbing that needs no engine: the parent-death watchdog and the outcome files the Robot lane child hands back."""
import json
import os
import threading

import pytest

from qa_evidence.canon import dumps_canonical
from qa_runner import watchdog
from qa_runner.bundle import LaneOutcome
from qa_runner.lane_robot import _Lane, _read_outcome, _write_outcome

LANE = _Lane(lane_id="robot", engine="robot-framework", suite="order-discount", suite_files={})


def test_the_watchdog_calls_back_when_the_parent_is_not_the_one_it_was_told_about():
    gone = threading.Event()
    watchdog.start(os.getppid() + 100000, gone.set, interval_s=0.02)
    assert gone.wait(2)


def test_the_watchdog_stays_quiet_while_the_parent_is_the_one_it_was_told_about():
    gone = threading.Event()
    watchdog.start(os.getppid(), gone.set, interval_s=0.02)
    assert not gone.wait(0.4)


def outcome(**kw):
    base = dict(lane_id="robot", engine_name="robot-framework", engine_version="7.5", native_status="NATIVE_PASS", raw_status="PASS", exit_code=0,
                native_files={"output.xml": b"<robot/>", "adapter-result.json": b"{}"}, files={"lanes/robot/observations.json": (b"obs\n", "observation"), "logs/robot.stdout.txt": (b"", "log")},
                counts={"passed": 1, "failed": 0, "errored": 0, "skipped": 0})
    base.update(kw)
    return LaneOutcome(**base)


def test_an_outcome_written_by_the_child_is_read_back_by_the_parent_exactly(tmp_path):
    original = outcome()
    _write_outcome(original, ["lane robot: native NATIVE_PASS (PASS), exit 0"], tmp_path)
    back, log = _read_outcome(LANE, tmp_path)
    assert back == original and log == ["lane robot: native NATIVE_PASS (PASS), exit 0"]


def test_no_outcome_file_or_one_that_is_not_ours_is_no_outcome(tmp_path):
    assert _read_outcome(LANE, tmp_path) == (None, [])
    (tmp_path / "outcome.json").write_bytes(b"{not json")
    assert _read_outcome(LANE, tmp_path) == (None, [])
    _write_outcome(outcome(), [], tmp_path / "ok")
    good = json.loads((tmp_path / "ok" / "outcome.json").read_text())
    assert _read_outcome(LANE, tmp_path / "ok")[0] is not None
    for field, value in (("schema", "something-else"), ("status", "ERROR")):               # a complete document that is not a finished lane result of ours
        (tmp_path / "ok" / "outcome.json").write_bytes(dumps_canonical(dict(good, **{field: value})))
        assert _read_outcome(LANE, tmp_path / "ok") == (None, [])


@pytest.mark.parametrize("name", ["../secret.txt", "/etc/hostname", "data/../../secret.txt"])
def test_a_file_the_child_names_outside_its_output_directory_is_refused(tmp_path, name):
    out = tmp_path / "out"
    _write_outcome(outcome(), [], out)
    (tmp_path / "secret.txt").write_text("not for the bundle")
    doc = json.loads((out / "outcome.json").read_text())
    doc["native"]["output.xml"] = name
    (out / "outcome.json").write_bytes(dumps_canonical(doc))
    assert _read_outcome(LANE, out) == (None, [])


def test_an_oversize_file_is_refused(tmp_path):
    _write_outcome(outcome(), [], tmp_path)
    assert _read_outcome(LANE, tmp_path, limit=3) == (None, [])
