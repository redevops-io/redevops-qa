# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Rewrite the golden bundles from REAL runs: ``python packages/qa-runner/tests/golden/regen_bundles.py`` (needs Playwright with Chromium and Robot Framework installed, the pinned
trees in place and the packages on PYTHONPATH, as for the end-to-end job). The bundles are what ``redevops-qa demo`` writes for the clean target and for the discount defect, in the
canonical single-file archive form; the verify tests start from them. Regenerate them when the check program, the reviewed suite, the plan or the runner version changes, and review
the diff of ``verify`` results, not of the bytes: a bundle contains the machine and the ports of the run that wrote it."""
import json
import sys
from pathlib import Path

from qa_runner.deps import verified_bootstrap
from qa_runner.golden import demo_plan
from qa_runner.orchestrate import RunOptions, run_plan
from qa_runner.plan import freeze_plan

HERE = Path(__file__).resolve().parent
up = verified_bootstrap()
frozen = freeze_plan(up, demo_plan())
for defect in ("none", "discount"):                       # (the over-cap bundle is written below)
    summary = run_plan(up, frozen, RunOptions(defect=defect, run_id=f"r0-golden-{defect}"))
    target = HERE / f"bundle-{defect}.tar"
    if target.exists():
        target.unlink()
    summary.bundle.write_archive(str(target))
    print(defect, summary.outcome, target.stat().st_size, "bytes", summary.manifest_digest, file=sys.stderr)
# a run that hit the evidence cap (150000 bytes): the incomplete result, both lanes cut; ``verify`` accepts it as such (exit 3) and the over-cap tests start from it
summary = run_plan(up, frozen, RunOptions(defect="none", run_id="r0-golden-overcap", max_evidence_bytes=150_000))
target = HERE / "bundle-overcap.tar"
if target.exists():
    target.unlink()
summary.bundle.write_archive(str(target))
print("overcap", summary.outcome, target.stat().st_size, "bytes", summary.manifest_digest, file=sys.stderr)
