# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The lane child process plumbing that needs no engine: the parent-death watchdog and the outcome files the Robot lane child hands back."""
import json
import os
import threading

import pytest

from qa_evidence.canon import dumps_canonical
from qa_runner import watchdog
from qa_runner.bundle import LaneOutcome
from qa_runner import constants as K
from qa_runner.lane_robot import _Lane, _read_outcome as _read, _write_outcome
from qa_runner.safe_read import Budget

LANE = _Lane(lane_id="robot", engine="robot-framework", suite="order-discount", suite_files={})


def _read_outcome(lane, out, budget=None, limit=64 * 1024 * 1024):
    return _read(lane, out, budget or Budget(K.DEFAULT_MAX_EVIDENCE_BYTES), limit=limit)


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


def test_an_oversize_file_is_not_kept_and_the_lane_is_an_engine_error_that_keeps_the_rest(tmp_path):
    _write_outcome(outcome(), [], tmp_path)
    back, _ = _read_outcome(LANE, tmp_path, limit=3)
    assert back.native_status == "NATIVE_ERROR" and back.raw_status == "evidence-over-cap" and back.counts is None and not back.native_files.get("output.xml")


def test_files_over_the_evidence_budget_are_not_kept_and_say_so(tmp_path):
    _write_outcome(outcome(), [], tmp_path)
    budget = Budget(10)                                   # the lane's control file is not charged (it is not kept); the files it names do not fit
    back, _ = _read_outcome(LANE, tmp_path, budget)
    assert back.raw_status == "evidence-over-cap" and budget.dropped and budget.used <= 10 and "outcome.json" not in budget.dropped


def test_a_data_file_that_is_a_fifo_a_symlink_or_missing_is_never_waited_for_or_followed(tmp_path):
    """Retest N1: the parent read what the child named with `is_file()` then `read_bytes()`: a FIFO swapped in after the check would block it for ever."""
    import time
    out = tmp_path / "out"
    _write_outcome(outcome(), [], out)
    doc = json.loads((out / "outcome.json").read_text())
    ref = doc["native"]["output.xml"]
    (out / ref).unlink()
    os.mkfifo(out / ref)
    other = doc["native"]["adapter-result.json"]
    (out / other).unlink()
    (out / other).symlink_to(tmp_path / "elsewhere")
    t0 = time.monotonic()
    back, _ = _read_outcome(LANE, out)
    assert time.monotonic() - t0 < 5 and "output.xml" not in back.native_files and "adapter-result.json" not in back.native_files
    assert back.files                                                                       # the files that are fine are kept


@pytest.mark.parametrize("ref", ["data/../x.bin", "data/1.bin/", "other/1.bin", "data/abc.bin", "data/1.bin\n"])
def test_only_numbered_data_files_can_be_named(tmp_path, ref):
    out = tmp_path / "out"
    _write_outcome(outcome(), [], out)
    doc = json.loads((out / "outcome.json").read_text())
    doc["native"]["output.xml"] = ref
    (out / "outcome.json").write_bytes(dumps_canonical(doc))
    assert _read_outcome(LANE, out) == (None, [])


def test_an_outcome_that_names_more_files_than_a_lane_can_write_is_refused(tmp_path):
    out = tmp_path / "out"
    _write_outcome(outcome(), [], out)
    doc = json.loads((out / "outcome.json").read_text())
    doc["native"] = {f"f{i}": "data/1.bin" for i in range(600)}
    (out / "outcome.json").write_bytes(dumps_canonical(doc))
    assert _read_outcome(LANE, out) == (None, [])


def test_an_outcome_json_that_is_a_fifo_is_no_outcome_and_is_not_waited_for(tmp_path):
    import time
    os.mkfifo(tmp_path / "outcome.json")
    t0 = time.monotonic()
    assert _read_outcome(LANE, tmp_path) == (None, []) and time.monotonic() - t0 < 5
