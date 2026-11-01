# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``redevops-qa``: one command for the whole path: ``doctor``, ``freeze``, ``run``, ``report``, ``inspect`` and the one-shot ``demo`` (``verify`` follows).

Exit status of ``run`` and ``demo``: 0 the run is VERIFIED; 1 an assertion FAILED; 2 the plan, the lock or an option was refused before anything ran; 3 a lane did not run
to completion (error, timeout, cancelled, unavailable) or the environment could not provide what the run needs; 4 inconclusive (every lane completed but not every
assertion is verified, or an engine and the verifier disagree); 6 an internal error of the runner. A crash is never reported as a product failure. ``freeze``: 0 or 2.
``report`` and ``inspect``: 0 the bundle verified as internally consistent, 1 it did not, 2 it cannot be opened. They never recompute a verdict."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import stat
import sys
from pathlib import Path
from typing import List, Optional, TextIO

from qa_adapter_kit.supervisor import CancelToken
from qa_evidence.canon import safe_text
from qa_evidence.constants import ANCHOR_ABSENT_NOTICE
from qa_evidence.inspector import inspect_bundle
from qa_evidence.render import render_html, render_text
from qa_evidence.sources import SourceError

from . import __version__
from . import constants as K
from .deps import verified_bootstrap
from .doctor import render, run_doctor
from .errors import EnvironmentFault, PlanError, RunnerError
from .golden import demo_plan
from .inspect_cmd import inspect_text
from .orchestrate import RunOptions, RunSummary, new_run_id, run_plan
from .plan import MAX_PLAN_BYTES, FrozenPlan, freeze_plan, load_plan_or_lock


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

    sp = sub.add_parser("freeze", help="validate a plan with the runtime-contracts parser and write its lock (the frozen assertions, their digests and the plan digest)")
    sp.add_argument("plan", help="a redevops-qa/plan file")
    sp.add_argument("--out", required=True, metavar="FILE", help="the lock file to create (an existing file is never overwritten)")

    def run_options(sp):
        sp.add_argument("--defect", choices=K.DEFECTS, default="none", help="the seeded defect of the fixture app to start the target with (default: none)")
        sp.add_argument("--run-id", metavar="ID", help="run id (default: generated); lane run ids are <run id>.<lane id>")
        sp.add_argument("--lane-deadline", type=_deadline, metavar="SECONDS", help="lower every lane's deadline to this many seconds (1 to 3600)")

    sp = sub.add_parser("run", help="run a plan (or a lock) and write the evidence bundle")
    sp.add_argument("plan", help="a redevops-qa/plan or redevops-qa/plan-lock file")
    sp.add_argument("--out", required=True, metavar="DIR", help="directory to create the bundle in: DIR/<run id> (must not exist)")
    run_options(sp)

    sp = sub.add_parser("demo", help="freeze and run the built-in two-lane plan (Playwright Chromium, then Robot Framework) against the fixture app and print the report")
    sp.add_argument("--out", default="qa-evidence", metavar="DIR", help="directory to create the bundle in: DIR/<run id> (default: ./qa-evidence)")
    run_options(sp)

    for name, text in (("report", "print the report of a bundle for people (text, JSON or one HTML file); it verifies the bundle first and never recomputes a verdict"),
                       ("inspect", "list what is in a bundle: files, digests, tool versions, lanes and the heads of the chains inside it")):
        sp = sub.add_parser(name, help=text)
        sp.add_argument("bundle", help="a bundle directory or archive")
        sp.add_argument("--anchor", metavar="sha256:HEX", help="external anchor value: the manifest digest published outside the bundle")
        sp.add_argument("--plan-digest", metavar="sha256:HEX", help="the plan digest printed by `freeze`, obtained from outside the bundle")
        if name == "report":
            sp.add_argument("--format", choices=("text", "json", "html"), default="text")
            sp.add_argument("-o", "--output", metavar="FILE", help="write to FILE (never overwritten) instead of standard output")
    return p


def _read_plan(path: str) -> bytes:
    """The bytes of a plan: a regular file, read with a cap (a size from ``stat`` is 0 for ``/dev/zero``, a FIFO or a process substitution, so the cap is on what is read)."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                raise PlanError("PLAN_NOT_A_FILE", f"{safe_text(path)} is not a regular file")
            data = fh.read(MAX_PLAN_BYTES + 1)
        if len(data) > MAX_PLAN_BYTES:
            raise PlanError("PLAN_TOO_LARGE", f"a plan is at most {MAX_PLAN_BYTES} bytes")
        return data
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


def _freeze(args, out: TextIO, err: TextIO) -> int:
    data = _read_plan(args.plan)
    up = verified_bootstrap()
    frozen, kind = load_plan_or_lock(up, data)
    if kind != "plan":
        raise PlanError("ALREADY_A_LOCK", "this file is already a lock; freeze takes a plan")
    target = Path(args.out)
    try:
        with open(target, "xb") as fh:
            fh.write(frozen.lock_bytes())
    except FileExistsError:
        raise PlanError("OUTPUT_EXISTS", f"{safe_text(args.out)} already exists: a lock is never overwritten") from None
    except OSError as exc:
        raise PlanError("OUTPUT_UNWRITABLE", f"cannot write {safe_text(args.out)}: {safe_text(exc.strerror or type(exc).__name__)}") from None
    print(f"frozen plan {frozen.plan_id}: {len(frozen.lanes)} lane(s), {len(frozen.rows)} assertion(s), validated by the runtime-contracts parser", file=out)
    print(f"  lock file: {target}   sha256 {frozen.lock_digest}", file=out)
    print(f"  plan digest: {frozen.plan_digest}", file=out)
    print("  record the plan digest where whoever runs the plan cannot rewrite it: `verify --plan-digest` compares a bundle with it, and without it a removed assertion "
          "would not be noticed", file=err)
    return 0


def _execute(frozen: FrozenPlan, args, out: TextIO, err: TextIO, *, report_text: bool = False) -> int:
    target = Path(args.out)
    run_id = new_run_id() if args.run_id is None else args.run_id
    if not K.RUN_ID_RE.fullmatch(run_id):
        raise PlanError("BAD_RUN_ID", "a run id is 1 to 40 characters: letters, digits, '.', '_' and '-', starting with a letter or digit")
    up = verified_bootstrap()
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
    _print_summary(summary, bundle_dir, out)
    if report_text:
        print("", file=out)
        out.write(render_text(inspect_bundle(str(bundle_dir))))          # no plan digest supplied: the one this process computed would only match itself
    return summary.exit_code


def _print_summary(summary: RunSummary, bundle_dir: Path, out: TextIO) -> None:
    report = json.loads(summary.bundle.files["report.json"])
    print(f"run {summary.run_id}: {report['verdict']['outcome']} ({report['verdict']['reason_code']})" + ("  [cancelled]" if summary.cancelled else ""), file=out)
    print(f"  external anchor: {ANCHOR_ABSENT_NOTICE} (a manifest digest published where this machine cannot rewrite it is an anchor)", file=out)
    acc = report["accounting"]
    for lane in report["lanes"]:
        mine = [r for r in acc["results"] if r["lane_id"] == lane["lane_id"]]
        tally = {s: sum(1 for r in mine if r["verdict"]["state"] == s) for s in ("VERIFIED", "FAILED", "INCONCLUSIVE", "UNACCOUNTED")}
        print(f"  lane {lane['lane_id']}: engine reported {lane['native']['status']} ({safe_text(lane['native']['raw_status'], 40)}); independent verdicts: "
              f"{tally['VERIFIED']} verified, {tally['FAILED']} failed, {tally['INCONCLUSIVE']} inconclusive, {tally['UNACCOUNTED']} unaccounted", file=out)
    for d in _disagreements(report):
        print(f"  ENGINE_VERIFIER_DISAGREE lane {d['lane_id']}: native {d['native_status']}, verdicts {', '.join(d['verdict_states']) or 'none'}", file=out)
    ext = report.get("extensions") or {}
    if "egress_gateway_denied" in ext or "egress_gate_denied" in ext:
        print(f"  egress: the gateway denied {ext.get('egress_gateway_denied', 0)} request(s), the in-browser request gate denied {ext.get('egress_gate_denied', 0)} (details in the lane's logs)", file=out)
    if ext.get("test_double"):
        print("  TEST DOUBLE: a lane of this run was produced by a test double; no assertion of it can be verified", file=out)
    print(f"  assertions: frozen {acc['frozen']} = verified {acc['verified']} + failed {acc['failed']} + inconclusive {acc['inconclusive']} + unaccounted {acc['unaccounted']}", file=out)
    print(f"  plan digest: {summary.plan_digest}   (the value to give `verify --plan-digest`)", file=out)
    print(f"  bundle: {bundle_dir}", file=out)
    print(f"  manifest digest: {summary.manifest_digest}   (an anchor only if published where this machine cannot rewrite it)", file=out)


def _disagreements(report):
    from qa_evidence.report import engine_verifier_disagreements
    return engine_verifier_disagreements(report)


def _run(args, out: TextIO, err: TextIO) -> int:
    data = _read_plan(args.plan)
    up = verified_bootstrap()
    frozen, kind = load_plan_or_lock(up, data)
    if kind == "plan":
        print("  note: the plan was frozen by this run; keep the plan digest from a separate `freeze` step to detect a changed plan", file=err)
    return _execute(frozen, args, out, err)


def _demo(args, out: TextIO, err: TextIO) -> int:
    up = verified_bootstrap()
    return _execute(freeze_plan(up, demo_plan()), args, out, err, report_text=True)


#: ``report`` and ``inspect`` check a bundle's own consistency (files, digests, accounting) and show what it says; they never recompute a verdict, so what they print is not a verification of the verdicts
NOT_RECOMPUTED = "verdicts NOT recomputed by this command: only the bundle's files, digests and accounting were checked; what the bundle says is not shown to be true"


def _inspection(args):
    try:
        return inspect_bundle(args.bundle, anchor=args.anchor, plan_digest=args.plan_digest)
    except SourceError as exc:
        raise PlanError("BUNDLE_UNREADABLE", safe_text(str(exc))) from None


def _report(args, out: TextIO, err: TextIO) -> int:
    ins = _inspection(args)
    ok = ins.verification.ok
    if args.format == "json":
        text = json.dumps({**ins.to_json(), "verdicts_recomputed": False, "notice": NOT_RECOMPUTED}, sort_keys=True, indent=2) + "\n"
    elif args.format == "html":
        text = render_html(ins).replace("<body>", '<body><div class="banner warn">' + NOT_RECOMPUTED + "</div>", 1)
    else:
        text = f"Verdicts      : {NOT_RECOMPUTED}\n" + render_text(ins)
    if args.output:
        try:
            with open(args.output, "x", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        except OSError as exc:
            raise PlanError("OUTPUT_UNWRITABLE", f"cannot write {safe_text(args.output)}: {safe_text(exc.strerror or type(exc).__name__)}") from None
    else:
        out.write(text)
    if not ok:
        print(f"the bundle did not verify: {len(ins.verification.findings)} finding(s); what is shown must not be relied on", file=err)
    return 0 if ok else 1


def _inspect(args, out: TextIO, err: TextIO) -> int:
    try:
        text = inspect_text(args.bundle, anchor=args.anchor, plan_digest=args.plan_digest)
    except SourceError as exc:
        raise PlanError("BUNDLE_UNREADABLE", safe_text(str(exc))) from None
    out.write(text)
    return 0 if text.splitlines()[1].startswith("verification: OK") else 1


def main(argv: Optional[List[str]] = None, out: Optional[TextIO] = None, err: Optional[TextIO] = None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else K.EXIT_USAGE
    try:
        return {"doctor": _doctor, "freeze": _freeze, "run": _run, "demo": _demo, "report": _report, "inspect": _inspect}[args.command](args, out, err)
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
        # the class of the failure, and the module name when an import failed (ours, not content from a page or a bundle)
        missing = f" (module {safe_text(exc.name, 80)})" if isinstance(exc, ImportError) and exc.name else ""
        print(f"internal error: {type(exc).__name__}{missing}", file=err)
        return K.EXIT_INTERNAL
