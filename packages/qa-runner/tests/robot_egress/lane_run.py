# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Run the Robot lane child (``qa_runner.lane_robot.main``) against the hostile world with a hostile suite, and read back what it wrote: the library's own report of each attempt, the lane's
outcome and its egress log. One run per configuration (no layer, each layer alone, both)."""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from qa_runner import constants as K, egresslog
from qa_runner.egress import policy_config
from qa_runner.lane_robot import _read_outcome
from qa_runner.procs import child_env, run_child
from qa_runner.safe_read import Budget

from hostile_world import World

HERE = Path(__file__).resolve().parent
FILES = ("hostile.robot", "HostileLib.py", "sneaky_import.py")


@dataclass
class Fl:
    lane_id: str = "robot"
    engine: str = K.ENGINE_ROBOT


@dataclass
class LaneRun:
    world: World
    exit_code: Optional[int]
    stderr: str
    results: Dict[str, Any]
    outcome: Any
    log_header: Optional[Dict[str, Any]]
    log_events: List[Dict[str, Any]]
    log_problems: List[str]


def run_hostile(tmp: Path, world: World, *, profile: str, layers: str = "-", race_attempts: int = 1500, deadline_s: int = 150) -> LaneRun:
    suite = tmp / "suite"
    suite.mkdir(parents=True)
    for name in FILES:
        shutil.copy(HERE / "hostile_suite" / name, suite / name)
    results_path = tmp / "results.json"
    (suite / "world.json").write_text(json.dumps({"ports": world.ports, "allowed_port": world.allowed_port, "unix_stream_path": world.unix_stream_path, "unix_dgram_path": world.unix_dgram_path, "unix_dgram_pair_path": world.unix_dgram_pair_path,
                                                  "results_path": str(results_path), "race_attempts": race_attempts}), encoding="utf-8")
    digests = {n: "sha256:" + hashlib.sha256((suite / n).read_bytes()).hexdigest() for n in (*FILES, "world.json")}
    origin = f"http://127.0.0.1:{world.allowed_port}"
    work = tmp / "work"
    lane_dir = work / "lanes" / "robot"
    home, out = lane_dir / "home", lane_dir / "out"
    home.mkdir(parents=True)
    out.mkdir(parents=True)
    cfg = {"schema": K.LANE_INPUT_SCHEMA, "schema_version": K.SCHEMA_VERSION, "lane_id": "robot", "engine": K.ENGINE_ROBOT, "suite": "hostile", "suite_files": digests, "run_id": "r0-experiment",
           "origin": origin, "deadline_s": deadline_s, "out_dir": str(out), "workdir": str(work), "suite_dir": str(suite), "launcher": None, "parent_pid": None, "evidence_budget": 64 * 1024 * 1024,
           "egress": profile, "egress_policy": policy_config("origin-only", origin) if profile == "origin-only" else None}
    from qa_evidence.canon import dumps_canonical
    (lane_dir / "input.json").write_bytes(dumps_canonical(cfg))
    proc = run_child([sys.executable, "-s", str(HERE / "driver.py"), str(lane_dir / "input.json"), layers], cwd=str(lane_dir), env=child_env(str(home)), deadline_s=deadline_s + 20, kill_grace_s=12.0)
    outcome, _ = _read_outcome(Fl(), out, Budget(64 * 1024 * 1024, root=str(work)))
    results = json.loads(results_path.read_text()) if results_path.exists() else {}
    header, events, problems = None, [], []
    if outcome is not None and "lanes/robot/egress-log.jsonl" in outcome.files:
        header, events, problems = egresslog.parse(outcome.files["lanes/robot/egress-log.jsonl"][0])
    return LaneRun(world, proc.exit_code, proc.stderr.decode("utf-8", "replace")[-3000:], results, outcome, header, events, problems)
