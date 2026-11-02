# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Rewrite the Robot-lane fixtures from REAL runs of the real Robot Framework: ``TMPDIR=/tmp/qa-golden python packages/qa-runner/tests/golden/regen_robot.py`` (needs ``robotframework==7.5``, the
pinned trees and the packages on PYTHONPATH, as for the Robot CI job; set a neutral TMPDIR, the engine writes the path of its workspace into ``output.xml``). Each ``robot-<defect>.tar``
holds the files of one real run that the judge reads for the Robot lane (the engine's report, its summary and the adapter result, the observation record, the reviewed suite files, the
target's request log for the lane and the reference check), under their bundle paths. The offline tests use them as the real thing and change them one way at a time. Regenerate when
the reviewed suite, the plan or the Robot adapter changes."""
import sys
from pathlib import Path

from qa_evidence.build import write_archive

from qa_runner.deps import verified_bootstrap
from qa_runner.golden import robot_plan
from qa_runner.orchestrate import RunOptions, run_plan
from qa_runner.plan import freeze_plan

HERE = Path(__file__).resolve().parent
KEEP = ("lanes/robot/native/output.xml", "lanes/robot/native/robot-summary.json", "lanes/robot/native/adapter-result.json", "lanes/robot/observations.json",
        "lanes/robot/suite/OrderApi.py", "lanes/robot/suite/order_discount.robot", "lanes/robot/target-requests.jsonl", "logs/reference-check.json")
up = verified_bootstrap()
frozen = freeze_plan(up, robot_plan())
for defect in ("none", "discount"):
    summary = run_plan(up, frozen, RunOptions(defect=defect, run_id=f"r0-golden-robot-{defect}"))
    target = HERE / f"robot-{defect}.tar"
    if target.exists():
        target.unlink()
    write_archive({p: summary.bundle.files[p] for p in KEEP}, str(target))
    print(defect, summary.outcome, target.stat().st_size, "bytes", file=sys.stderr)
