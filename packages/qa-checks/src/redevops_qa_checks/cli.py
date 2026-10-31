# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Hash-pinned command line over the check engine.

``redevops-qa-checks list`` prints every registered program as ``id version program_hash``.
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
    run = sub.add_parser("run", allow_abbrev=False)
    run.add_argument("--case-root", required=True)
    run.add_argument("--program", required=True, help="ID@VERSION")
    run.add_argument("--program-hash", required=True, help="sha256:<64 hex>")
    run.add_argument("--input", action="append", default=[], help="a manifest path relative to the case root")
    args = ap.parse_args(argv)
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


if __name__ == "__main__":
    raise SystemExit(main())
