# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A parent process for the hard-kill test of the Robot lane: it runs the Robot plan with ``slow_robot.py`` as the engine and prints its own pid first."""
import os
import sys
from pathlib import Path

from qa_runner.deps import verified_bootstrap
from qa_runner.golden import robot_plan
from qa_runner.orchestrate import RunOptions, run_plan
from qa_runner.plan import freeze_plan

up = verified_bootstrap()
print("parent", os.getpid(), flush=True)
run_plan(up, freeze_plan(up, robot_plan()), RunOptions(run_id="r0-slow", robot_launcher=(str(Path(__file__).resolve().parent / "slow_robot.py"),)))
