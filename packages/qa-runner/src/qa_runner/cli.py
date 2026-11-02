# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``redevops-qa``: one command for the whole path: ``doctor``, ``freeze``, ``run``, ``verify``, ``report``, ``inspect`` and the one-shot ``demo``.

Exit status of ``run`` and ``demo``: 0 the run is VERIFIED; 1 an assertion FAILED; 2 the plan, the lock or an option was refused before anything ran; 3 a lane did not run
to completion (error, timeout, cancelled, unavailable) or the environment could not provide what the run needs; 4 inconclusive (every lane completed but not every
assertion is verified, or an engine and the verifier disagree); 6 an internal error of the runner. A crash is never reported as a product failure. ``freeze``: 0 or 2.
``report`` and ``inspect``: 0 the bundle verified as internally consistent, 1 it did not, 2 it cannot be opened. They never recompute a verdict.
``verify``: the same table as ``run`` for an accepted bundle (0 VERIFIED, 1 FAILED, 3 a lane did not complete, 4 inconclusive), 5 when ANY finding rejects the evidence, 2 when the bundle
cannot be opened. ``run`` and ``demo`` end by calling ``verify`` in a separate interpreter and exit 5 if it does not accept what the run just wrote."""
from __future__ import annotations

import argparse
import html
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
from qa_evidence.inspector import inspect_source
from qa_evidence.render import render_html, render_text
from qa_evidence.sources import SourceError

from . import __version__
from . import constants as K
from .deps import verified_bootstrap
from .errors import EnvironmentFault, PlanError, RunnerError
from .golden import demo_plan
from .inspect_cmd import inspect_text
from .plan import MAX_PLAN_BYTES, FrozenPlan, freeze_plan, load_plan_or_lock
from . import isolated


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

    sp = sub.add_parser("verify", help="re-verify a finished run from its bundle alone, offline: recompute every digest, the frozen assertions and every verdict; exit 5 on any finding")
    sp.add_argument("bundle", help="a bundle directory or archive")
    sp.add_argument("--anchor", metavar="sha256:HEX", help="external anchor value: the manifest digest published outside the bundle (print it with `run`, publish it where the producer cannot rewrite it)")
    sp.add_argument("--plan-digest", metavar="sha256:HEX", help="the plan digest printed by `freeze`, obtained from outside the bundle")
    sp.add_argument("--require-anchor", action="store_true", help="a finding unless --anchor matches the recomputed manifest digest (a match is not proof of integrity: nothing here authenticates where the supplied value came from)")
    sp.add_argument("--require-plan-digest", action="store_true", help="a finding unless --plan-digest matches the plan digest of the bundle")
    sp.add_argument("--json", action="store_true", help="print the result as JSON")

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
    """The bytes of a plan or lock: a regular file only, at most ``MAX_PLAN_BYTES``, read by a child process that is killed at ``REDEVOPS_QA_READ_TIMEOUT`` seconds (default 30), so a stalled mount, a FIFO
    or a file that keeps growing cannot hold this process or its memory (see ``isolated``)."""
    try:
        return isolated.read_file(path, max_bytes=MAX_PLAN_BYTES)
    except isolated.IsolatedReadError as exc:
        if exc.code == "CANCELLED":
            raise EnvironmentFault("CANCELLED", "cancelled while reading the plan") from None
        code = {"NOT_A_REGULAR_FILE": "PLAN_NOT_A_FILE", "TOO_LARGE": "PLAN_TOO_LARGE", "TIMEOUT": "PLAN_READ_TIMEOUT"}.get(exc.code, "PLAN_UNREADABLE")
        detail = f"a plan is at most {MAX_PLAN_BYTES} bytes" if exc.code == "TOO_LARGE" else f"cannot read {safe_text(path)}: {safe_text(str(exc), 80)}"
        raise PlanError(code, detail) from None


def _doctor(args, out: TextIO, err: TextIO) -> int:
    from .doctor import render, run_doctor
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
    from .orchestrate import RunOptions, new_run_id, run_plan
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
    from .exits import exit_code_for
    # verify cannot know whether the run was cancelled (a SIGTERM after the last lane): it returns the status of the report alone, which is what it is compared with
    code = _verify_in_a_new_process(bundle_dir, summary.plan_digest, exit_code_for(json.loads(summary.bundle.files["report.json"])), summary.exit_code, out)
    if report_text:
        print("", file=out)
        if code == K.EXIT_REJECTED:
            print("the report is not printed: the bundle was rejected by the separate verification above", file=out)
        else:
            out.write(render_text(inspect_source(_snapshot(str(bundle_dir)))))          # no plan digest supplied: the one this process computed would only match itself
    return code


def _verify_in_a_new_process(bundle_dir: Path, plan_digest: str, expected_exit: int, run_exit: int, out: TextIO) -> int:
    """The run's own re-verification: ``verify`` in a fresh interpreter with a fresh environment (no state shared with this process), given the bundle and the plan digest this process
    froze. The plan digest comes from the same process that ran the plan, so it checks that the run wrote what it froze, not that the plan is the one somebody asked for."""
    import subprocess
    from .procs import child_env, make_workdir
    import shutil
    home = make_workdir("redevops-qa-verify-")
    try:
        done = subprocess.run([sys.executable, "-s", "-m", "qa_runner", "verify", str(bundle_dir.resolve()), "--plan-digest", plan_digest, "--json"], env=child_env(home), cwd=home,
                              capture_output=True, text=True, timeout=300)
        try:
            doc = json.loads(done.stdout)
        except ValueError:
            doc = None
    except (OSError, subprocess.SubprocessError):
        done, doc = None, None
    finally:
        shutil.rmtree(home, ignore_errors=True)
    if doc is None or done is None or done.returncode == K.EXIT_INTERNAL:
        print("  re-verification in a fresh process (the same code as the run, not independent code): COULD NOT RUN; nothing is accepted", file=out)
        return K.EXIT_REJECTED
    if not doc["accepted"]:
        codes = ", ".join(sorted({safe_text(f["code"], 60) for f in doc["findings"]}))
        print(f"  re-verification in a fresh process (the same code as the run, not independent code): REJECTED ({codes})", file=out)
        return K.EXIT_REJECTED
    if doc["exit_code"] != expected_exit:
        print(f"  re-verification in a fresh process (the same code as the run, not independent code): ACCEPTED, but its exit status ({doc['exit_code']}) is not the report's ({expected_exit}); nothing is accepted", file=out)
        return K.EXIT_REJECTED
    print(f"  re-verification in a fresh process (the same code as the run, not independent code): ACCEPTED as internally consistent; {doc['agreeing_assertions']} of {doc['recomputed_assertions']} verdict(s) recomputed from the bundle alone "
          "agree with the report; no external anchor", file=out)
    return run_exit


def _print_summary(summary, bundle_dir: Path, out: TextIO) -> None:
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
    if ext.get("no_independent_probe"):
        print(f"  no independent probe (declared ui-only in the plan; the verdict rests on the engine's record and the target's request log): {safe_text(ext['no_independent_probe'], 200)}", file=out)
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


def _verify(args, out: TextIO, err: TextIO) -> int:
    from .verify import render_text as verify_text, verify_location
    try:
        v = verify_location(args.bundle, anchor=args.anchor, plan_digest=args.plan_digest, require_anchor=args.require_anchor, require_plan_digest=args.require_plan_digest)
    except isolated.IsolatedReadError as exc:
        raise _bundle_read_error(exc) from None
    out.write(json.dumps(v.to_json(), sort_keys=True, indent=2) + "\n" if args.json else verify_text(args.bundle, v))
    return v.exit_code


def _bundle_read_error(exc: "isolated.IsolatedReadError") -> Exception:
    if exc.code == "CANCELLED":
        return EnvironmentFault("CANCELLED", "cancelled while reading the bundle")
    return PlanError("BUNDLE_READ_TIMEOUT" if exc.code == "TIMEOUT" else "BUNDLE_UNREADABLE", safe_text(str(exc), 200))


def _snapshot(location: str):
    """ONE immutable snapshot of a bundle, taken by a child that is killed at the deadline (``isolated``); everything ``report`` and ``inspect`` look at, and the recomputation, comes from it."""
    try:
        return isolated.snapshot_bundle(location)
    except isolated.IsolatedReadError as exc:
        raise _bundle_read_error(exc) from None


def _recomputed(args, snapshot):
    """The recomputation of the verdicts from the bundle alone (``verify``), over the snapshot ``report`` and ``inspect`` also show."""
    from .verify import verify_snapshot
    return verify_snapshot(snapshot, anchor=args.anchor, plan_digest=args.plan_digest)


def _recomputed_line(v) -> str:
    if v.accepted:
        return f"verdicts recomputed from the bundle alone: {v.agreeing} of {v.recomputed} agree with the report (ACCEPTED as internally consistent)"
    if v.unavailable:
        return "NOT VERIFIED: the verifier cannot run here (nothing was verified, and nothing of the bundle is shown)"
    codes = ", ".join(sorted({safe_text(f.code, 60) for f in v.findings})[:8])
    return f"REJECTED: the bundle does not verify, {len(v.findings)} finding(s) ({codes}); nothing of what it says is shown"


def _findings_lines(v, limit: int = 30) -> List[str]:
    lines = [f"  {safe_text(f.code, 60)} {safe_text(f.where, 100)}: {safe_text(f.message, 200)}" for f in v.findings[:limit]]
    if len(v.findings) > limit:
        lines.append(f"  ... and {len(v.findings) - limit} more (run `redevops-qa verify` for all of them)")
    return lines


def _report(args, out: TextIO, err: TextIO) -> int:
    snap = _snapshot(args.bundle)
    ins = inspect_source(snap, anchor=args.anchor, plan_digest=args.plan_digest)
    v = _recomputed(args, snap)
    line = _recomputed_line(v)
    if v.accepted:
        if args.format == "json":
            text = json.dumps({**ins.to_json(), "verdicts_recomputed": True, "recomputation": v.to_json()}, sort_keys=True, indent=2) + "\n"
        elif args.format == "html":
            text = render_html(ins).replace("<body>", '<body><div class="banner ok">%s</div>' % html.escape(line), 1)
        else:
            text = f"Recomputation : {line}\n" + render_text(ins)
    else:
        # A bundle that does not verify is not summarised: nothing the qa-evidence report would say ("Verification : OK", an outcome, ``content_trusted``) is printed next to a rejection.
        if args.format == "json":
            text = json.dumps({"verdicts_recomputed": not v.unavailable, "content_trusted": False, "verification": {"ok": False}, "recomputation": v.to_json()}, sort_keys=True, indent=2) + "\n"
        elif args.format == "html":
            text = ('<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'"><title>bundle rejected</title></head><body>'
                    '<div class="banner bad">%s</div><ul>%s</ul></body></html>\n' % (html.escape(line), "".join("<li>%s</li>" % html.escape(l.strip()) for l in _findings_lines(v))))
        else:
            text = f"Recomputation : {line}\n" + "\n".join(_findings_lines(v)) + "\n"
    if args.output:
        try:
            with open(args.output, "x", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        except OSError as exc:
            raise PlanError("OUTPUT_UNWRITABLE", f"cannot write {safe_text(args.output)}: {safe_text(exc.strerror or type(exc).__name__)}") from None
    else:
        out.write(text)
    if not v.accepted:
        print(f"the bundle did not verify: {len(v.findings)} finding(s) (run `redevops-qa verify` for the findings)", file=err)
    return 0 if v.accepted else v.exit_code


def _inspect(args, out: TextIO, err: TextIO) -> int:
    snap = _snapshot(args.bundle)              # ONE snapshot: the listing and the recomputation below see the same bytes
    v = _recomputed(args, snap)
    if not v.accepted:
        out.write(f"bundle {safe_text(args.bundle, 200)}: {snap.kind}, {len(snap.entries)} file(s)\nrecomputation: {_recomputed_line(v)}\n" + "\n".join(_findings_lines(v)) + "\n")
        return v.exit_code
    text = inspect_text(snap, args.bundle, anchor=args.anchor, plan_digest=args.plan_digest)
    lines = text.splitlines()
    lines.insert(2, "recomputation: " + _recomputed_line(v))
    out.write("\n".join(lines) + "\n")
    return 0


def main(argv: Optional[List[str]] = None, out: Optional[TextIO] = None, err: Optional[TextIO] = None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else K.EXIT_USAGE
    try:
        return {"doctor": _doctor, "freeze": _freeze, "run": _run, "verify": _verify, "demo": _demo, "report": _report, "inspect": _inspect}[args.command](args, out, err)
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
    except KeyboardInterrupt:
        print("cancelled", file=err)
        return K.EXIT_ENVIRONMENT
    except Exception as exc:
        # the class of the failure, and the module name when an import failed (ours, not content from a page or a bundle)
        missing = f" (module {safe_text(exc.name, 80)})" if isinstance(exc, ImportError) and exc.name else ""
        print(f"internal error: {type(exc).__name__}{missing}", file=err)
        return K.EXIT_INTERNAL
