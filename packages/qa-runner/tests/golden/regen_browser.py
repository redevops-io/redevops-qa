# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Rewrite the browser-lane fixtures from REAL runs: ``TMPDIR=/tmp/qa-golden python packages/qa-runner/tests/golden/regen_browser.py`` (needs Playwright with Chromium, the pinned trees and the packages on
PYTHONPATH, as for the browser CI job). Each ``browser-<defect>.tar`` holds the files of one real run that the judge reads for the browser lane (the lane result, the harness run record,
the observations, the egress profile, the blobs the run record refers to, the target's request log for the lane and the reference check), under their bundle paths. The offline tests use them as the real thing and change
them one way at a time. Regenerate when the plan's browser spec or the harness record format changes."""
import sys
from pathlib import Path

from qa_evidence.build import write_archive

from qa_runner.deps import verified_bootstrap
from qa_runner.golden import golden_plan
from qa_runner.orchestrate import RunOptions, run_plan
from qa_runner.plan import freeze_plan

HERE = Path(__file__).resolve().parent
KEEP = ("lanes/browser/native/lane-result.json", "lanes/browser/native/run-record.json", "lanes/browser/observations.json", "lanes/browser/egress-profile.json",
        "lanes/browser/target-requests.jsonl", "logs/reference-check.json")
up = verified_bootstrap()
frozen = freeze_plan(up, golden_plan())
for defect in ("none", "settings"):
    summary = run_plan(up, frozen, RunOptions(defect=defect, run_id=f"r0-golden-browser-{defect}"))
    target = HERE / f"browser-{defect}.tar"
    if target.exists():
        target.unlink()
    keep = list(KEEP) + sorted(p for p in summary.bundle.files if p.startswith("lanes/browser/native/blobs/"))          # the blobs the harness integrity check looks for
    write_archive({p: summary.bundle.files[p] for p in keep}, str(target))
    print(defect, summary.outcome, target.stat().st_size, "bytes", file=sys.stderr)
