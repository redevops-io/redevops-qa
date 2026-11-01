# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``redevops-qa``: one command for the whole path. This part provides ``doctor`` and ``run``; ``freeze``, ``verify``, ``report``, ``inspect`` and ``demo`` follow.

Exit status of ``run``: 0 the run is VERIFIED; 1 an assertion FAILED; 2 the plan, the lock or an option was refused before anything ran; 3 a lane did not run
to completion (error, timeout, cancelled, unavailable) or the environment could not provide what the run needs; 4 inconclusive (every lane completed but not
every assertion is verified, or an engine and the verifier disagree); 6 an internal error of the runner. A crash is never reported as a product failure."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import sys
from pathlib import Path
from typing import List, Optional, TextIO

from qa_adapter_kit.supervisor import CancelToken
from qa_evidence.canon import safe_text

from . import __version__
from . import constants as K
from .deps import verified_bootstrap
from .doctor import render, run_doctor
from .errors import EnvironmentFault, PlanError, RunnerError
from .orchestrate import RunOptions, new_run_id, run_plan
from .plan import MAX_PLAN_BYTES, load_plan_or_lock


def _deadline(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{safe_text(text, 20)!r} is not a whole number of seconds") from None
    if not 1 <= value <= 3600:
        raise argparse.ArgumentTypeError("a lane deadline is between 1 and 3600 seconds")
    return value


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="redevops-qa", description="Run a frozen test plan, keep the evidence, report what was and was not shown.")
    p.add_argument("--version", action="version", version=f"redevops-qa {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    sp = sub.add_parser("doctor", help="check this machine (Python, pins, Playwright and Chromium, Robot, the fixture app, the egress gateway); installs nothing")
    sp.add_argument("--plan", metavar="PLAN", help="check only what this plan needs")
    sp.add_argument("--json", action="store_true", help="print the checks as JSON")
    sp = sub.add_parser("run", help="run a plan (or a lock) and write the evidence bundle")
    sp.add_argument("plan", help="a redevops-qa/plan or redevops-qa/plan-lock file")
    sp.add_argument("--out", required=True, metavar="DIR", help="directory to create the bundle in: DIR/<run id> (must not exist)")
    sp.add_argument("--defect", choices=K.DEFECTS, default="none", help="the seeded defect of the fixture app to start the target with (default: none)")
    sp.add_argument("--run-id", metavar="ID", help="run id (default: generated)")
    sp.add_argument("--lane-deadline", type=_deadline, metavar="SECONDS", help="lower every lane's deadline to this many seconds (1 to 3600)")
    return p


def _read_plan(path: str) -> bytes:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_PLAN_BYTES:
            raise PlanError("PLAN_TOO_LARGE", f"a plan is at most {MAX_PLAN_BYTES} bytes")
        return p.read_bytes()
    except OSError as exc:
        raise PlanError("PLAN_UNREADABLE", f"cannot read {safe_text(path)}: {safe_text(exc.strerror or type(exc).__name__)}") from None


def _doctor(args, out: TextIO, err: TextIO) -> int:
    engines = (K.ENGINE_PLAYWRIGHT, K.ENGINE_ROBOT)
    if args.plan:
        up = verified_bootstrap()
        frozen, _ = load_plan_or_lock(up, _read_plan(args.plan))
        engines = tuple(sorted({l.engine for l in frozen.lanes}))
    checks = run_doctor(engines)
    out.write(json.dumps([c.to_json() for c in checks], indent=2, sort_keys=True) + "\n" if args.json else render(checks))
    return K.EXIT_ENVIRONMENT if any(c.status == "FAIL" for c in checks) else 0


def _reserve(target: Path, run_id: str) -> Path:
    """Reserve ``DIR/<run id>`` before anything runs: a directory that already exists (a bundle, or another run with the same id that is still going) or one that cannot be created fails
    here, with a clear error, not after a whole run."""
    try:
        target.mkdir(parents=True, exist_ok=True)
        reserved = target / run_id
        reserved.mkdir()
    except FileExistsError:
        raise PlanError("OUTPUT_EXISTS", f"{safe_text(str(target / run_id))} already exists: a bundle is never overwritten, and another run may be using this run id") from None
    except OSError as exc:
        raise PlanError("OUTPUT_UNWRITABLE", f"cannot create {safe_text(str(target / run_id))}: {safe_text(exc.strerror or type(exc).__name__)}") from None
    return reserved


def _write_atomically(bundle, reserved: Path) -> None:
    """Write the bundle next to the reserved directory and rename it over (an empty directory can be replaced): a reader sees no bundle or the whole bundle."""
    partial = reserved.parent / f".{reserved.name}.partial"
    try:
        bundle.write_directory(str(partial))
        os.rename(partial, reserved)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise


def _run(args, out: TextIO, err: TextIO) -> int:
    data = _read_plan(args.plan)
    target = Path(args.out)
    run_id = new_run_id() if args.run_id is None else args.run_id
    if not K.RUN_ID_RE.fullmatch(run_id):
        raise PlanError("BAD_RUN_ID", "a run id is 1 to 40 characters: letters, digits, '.', '_' and '-', starting with a letter or digit")
    up = verified_bootstrap()
    frozen, kind = load_plan_or_lock(up, data)
    reserved = _reserve(target, run_id)
    cancel = CancelToken()
    previous = {}
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[sig] = signal.signal(sig, lambda *_: cancel.cancel())
    try:
        summary = run_plan(up, frozen, RunOptions(defect=args.defect, run_id=run_id, lane_deadline_s=args.lane_deadline, cancel=cancel))
        _write_atomically(summary.bundle, reserved)
    except BaseException:
        shutil.rmtree(reserved, ignore_errors=True)       # the reservation is empty unless the bundle was completed: leave nothing half-made
        raise
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    bundle_dir = reserved
    report = json.loads(summary.bundle.files["report.json"])
    print(f"run {summary.run_id}: {report['verdict']['outcome']} ({report['verdict']['reason_code']})" + ("  [cancelled]" if summary.cancelled else ""), file=out)
    acc = report["accounting"]
    for lane in report["lanes"]:
        mine = [r for r in acc["results"] if r["lane_id"] == lane["lane_id"]]
        tally = {s: sum(1 for r in mine if r["verdict"]["state"] == s) for s in ("VERIFIED", "FAILED", "INCONCLUSIVE", "UNACCOUNTED")}
        print(f"  lane {lane['lane_id']}: engine reported {lane['native']['status']} ({safe_text(lane['native']['raw_status'], 40)}); independent verdicts: "
              f"{tally['VERIFIED']} verified, {tally['FAILED']} failed, {tally['INCONCLUSIVE']} inconclusive, {tally['UNACCOUNTED']} unaccounted", file=out)
    ext = report.get("extensions") or {}
    if "egress_gateway_denied" in ext or "egress_gate_denied" in ext:
        print(f"  egress: the gateway denied {ext.get('egress_gateway_denied', 0)} request(s), the in-browser request gate denied {ext.get('egress_gate_denied', 0)} (details in the lane's logs)", file=out)
    if ext.get("test_double"):
        print("  TEST DOUBLE: a lane of this run was produced by a test double; no assertion of it can be verified", file=out)
    print(f"  assertions: frozen {acc['frozen']} = verified {acc['verified']} + failed {acc['failed']} + inconclusive {acc['inconclusive']} + unaccounted {acc['unaccounted']}", file=out)
    print(f"  plan digest: {summary.plan_digest}   (the value to give `verify --plan-digest`)", file=out)
    print(f"  bundle: {bundle_dir}", file=out)
    print(f"  manifest digest: {summary.manifest_digest}   (an anchor only if published where this machine cannot rewrite it)", file=out)
    if kind == "plan":
        print("  note: the plan was frozen by this run; keep the plan digest from a separate `freeze` step to detect a changed plan", file=err)
    return summary.exit_code


def main(argv: Optional[List[str]] = None, out: Optional[TextIO] = None, err: Optional[TextIO] = None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else K.EXIT_USAGE
    try:
        return {"doctor": _doctor, "run": _run}[args.command](args, out, err)
    except PlanError as exc:
        print(f"error: {safe_text(str(exc))}", file=err)
        return K.EXIT_USAGE
    except EnvironmentFault as exc:
        print(f"error: {safe_text(str(exc))}", file=err)
        return K.EXIT_ENVIRONMENT
    except FileExistsError as exc:
        print(f"error: the output location already exists and is not empty ({safe_text(str(exc.filename or ''))})", file=err)
        return K.EXIT_USAGE
    except RunnerError as exc:
        print(f"error: {safe_text(str(exc))}", file=err)
        return K.EXIT_USAGE
    except Exception as exc:
        print(f"internal error: {type(exc).__name__}", file=err)
        return K.EXIT_INTERNAL
