# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A parent process for the hard-kill test: it runs the demo plan with a Robot suite that sleeps (so the engine is alive long enough to be seen and the parent killed),
printing its own pid first. The suite is a throwaway copy; the shipped one is not touched."""
import os
import shutil
import sys
import tempfile
from pathlib import Path

from qa_runner import suites
from qa_runner.deps import verified_bootstrap
from qa_runner.golden import demo_plan
from qa_runner.orchestrate import RunOptions, run_plan
from qa_runner.plan import freeze_plan

which = sys.argv[1]                                # "robot": a sleeping Robot suite, run first; "browser": the real browser lane held open (slow_browser_lane.py), run first
if which == "robot":
    copy = Path(tempfile.mkdtemp(prefix="slow-suite-"))
    shutil.copytree(suites.SUITE_DIR, copy / "s")
    rb = copy / "s" / "order_discount.robot"
    rb.write_text(rb.read_text().replace("Order Discount Rule\n", "Order Discount Rule\n    Sleep    600\n", 1))
    suites.SUITE_DIR = copy / "s"
plan = demo_plan()
if which == "robot":
    plan["lanes"].reverse()                         # the Robot lane first, so the engine is what is running when the parent is killed
up = verified_bootstrap()
print("parent", os.getpid(), flush=True)
command = None
if which == "browser":                              # the real browser lane, held open after its steps (slow_browser_lane.py)
    command = lambda fl, input_path: [sys.executable, "-s", str(Path(__file__).resolve().parent / "slow_browser_lane.py"), input_path]
run_plan(up, freeze_plan(up, plan), RunOptions(run_id="r0-slow", lane_command=command))
