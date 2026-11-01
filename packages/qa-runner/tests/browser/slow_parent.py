# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A parent process for the hard-kill test: it runs the golden plan with the REAL browser lane held open after its steps (``slow_browser_lane.py``) and prints its own pid first."""
import os
import sys
from pathlib import Path

from qa_runner.deps import verified_bootstrap
from qa_runner.golden import golden_plan
from qa_runner.orchestrate import RunOptions, run_plan
from qa_runner.plan import freeze_plan

up = verified_bootstrap()
print("parent", os.getpid(), flush=True)
run_plan(up, freeze_plan(up, golden_plan()), RunOptions(run_id="r0-slow", lane_command=lambda fl, inp: [sys.executable, "-s", str(Path(__file__).resolve().parent / "slow_browser_lane.py"), inp]))
