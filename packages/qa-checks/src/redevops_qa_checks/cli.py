# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Hash-pinned command line over the check engine.

``redevops-qa-checks list`` prints every registered program as ``id version program_hash``.
``redevops-qa-checks view --results FILE --view full|playwright|script`` prints a reporting view of the results of one run (read
only; a view is never a second run). ``redevops-qa-checks seed-copy create-work-root|list|apply`` makes development variants as
copies in a work root (see ``seed_copy``); nothing is ever edited in place.
``redevops-qa-checks run --case-root DIR --program ID@VERSION --program-hash sha256:HEX --input PATH [--input PATH ...]``
runs one offline check and prints the observed value as canonical JSON. The hash is required: a missing or different hash
refuses to run (exit 2) before any input is read. There is no option for an expected value and the output is never a verdict.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .canonical import canonical_bytes
from .engine import CheckEngine
from .errors import CheckError
from .registry import builtin_registry

EXIT_OK, EXIT_REFUSED, EXIT_UNRESOLVED = 0, 2, 3


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="redevops-qa-checks", allow_abbrev=False)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    view = sub.add_parser("view", allow_abbrev=False)
    view.add_argument("--results", required=True, help="a JSON file: {results: [...], manifest?: {...}, assertions?: [...]} of one run")
    view.add_argument("--view", required=True, choices=("full", "playwright", "script", "reconciliation"))
    seed = sub.add_parser("seed-copy", allow_abbrev=False)
    seed_sub = seed.add_subparsers(dest="seed_cmd", required=True)
    cw = seed_sub.add_parser("create-work-root", allow_abbrev=False)
    cw.add_argument("path")
    seed_sub.add_parser("list")
    ap_ = seed_sub.add_parser("apply", allow_abbrev=False)
    ap_.add_argument("--source", required=True)
    ap_.add_argument("--work-root", required=True)
    ap_.add_argument("--name", required=True)
    ap_.add_argument("--transform", required=True)
    ap_.add_argument("--params", default="{}", help="a JSON object of transformation parameters")
    run = sub.add_parser("run", allow_abbrev=False)
    run.add_argument("--case-root", required=True)
    run.add_argument("--program", required=True, help="ID@VERSION")
    run.add_argument("--program-hash", required=True, help="sha256:<64 hex>")
    run.add_argument("--input", action="append", default=[], help="a manifest path relative to the case root")
    args = ap.parse_args(argv)
    if args.cmd == "view":
        return _view(args)
    if args.cmd == "seed-copy":
        return _seed(args)
    registry = builtin_registry()
    if args.cmd == "list":
        for s in registry.entries():
            print(f"{s.id} {s.version} {s.program_hash}")
        return EXIT_OK
    pid, _, ver = args.program.partition("@")
    subject = {"check_program_ref": {"id": pid, "version": ver, "program_hash": args.program_hash},
               "inputs": [{"kind": "MANIFEST_PATH", "path": p} for p in args.input], "tier": "OFFLINE"}
    try:
        outcome = CheckEngine(Path(args.case_root), registry).run_check(subject)
    except CheckError as exc:
        print(json.dumps({"error": exc.code, "message": exc.message}, sort_keys=True), file=sys.stderr)
        return EXIT_REFUSED
    if outcome.resolution != "RESOLVED":
        print(json.dumps({"resolution": outcome.resolution, "match_count": outcome.match_count}, sort_keys=True))
        return EXIT_UNRESOLVED
    sys.stdout.write(canonical_bytes({"resolution": "RESOLVED", "value": outcome.value}).decode("ascii") + "\n")
    return EXIT_OK


def _view(args: argparse.Namespace) -> int:
    from . import views
    try:
        with open(args.results, "rb") as fh:
            doc = json.loads(fh.read().decode("utf-8"))
        if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
            raise views.ViewRefused("the file needs a results list")
        run = views.run_data(doc["results"], manifest=doc.get("manifest"), assertions=doc.get("assertions"))
        out = {"full": views.full_view, "playwright": views.playwright_view, "script": views.script_view,
               "reconciliation": views.reconciliation}[args.view](run)
    except (CheckError, OSError, ValueError) as exc:
        print(json.dumps({"error": getattr(exc, "code", type(exc).__name__), "message": str(exc)[:200]}, sort_keys=True), file=sys.stderr)
        return EXIT_REFUSED
    sys.stdout.write(canonical_bytes(out).decode("ascii") + "\n")
    return EXIT_OK


def _seed(args: argparse.Namespace) -> int:
    from . import seed_copy as sc
    try:
        if args.seed_cmd == "list":
            for t in sc.LIBRARY.values():
                print(json.dumps({"id": t.id, "version": t.version, "description": t.description, "params": dict(t.params)}, sort_keys=True))
            return EXIT_OK
        if args.seed_cmd == "create-work-root":
            print(str(sc.create_work_root(Path(args.path))))
            return EXIT_OK
        record = sc.seed_copy(Path(args.source), Path(args.work_root), args.name, args.transform, json.loads(args.params))
        sys.stdout.write(canonical_bytes(record).decode("ascii") + "\n")
        return EXIT_OK
    except sc.SeedRefused as exc:
        print(json.dumps({"error": exc.code, "reason": exc.reason, "message": exc.message[:200]}, sort_keys=True), file=sys.stderr)
        return EXIT_REFUSED
    except (CheckError, ValueError) as exc:
        print(json.dumps({"error": getattr(exc, "code", "ARGUMENT_INVALID"), "message": str(exc)[:200]}, sort_keys=True), file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
