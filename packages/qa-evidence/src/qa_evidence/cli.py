# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Command line: ``python -m qa_evidence {inspect,verify,html,digest,anchor} BUNDLE``.

Exit status: 0 verification clean; 1 verification found a problem; 2 usage or the bundle cannot be opened; 3 ``--require-anchor`` was
given and no supplied value matched; 4 an internal error (a crash is never reported as a finding). Every string that comes from a bundle
(paths, messages, references) is passed through ``safe_text`` before it is printed.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional, TextIO

from . import __version__
from .build import anchor_document
from .canon import dumps_canonical, safe_text
from .constants import ANCHOR_TYPES, DIGEST_ORIGIN_NOTICE
from .inspector import inspect_bundle
from .render import render_html, render_text
from .sources import SourceError


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m qa_evidence", description="Inspect and verify a QA evidence bundle (offline).")
    p.add_argument("--version", action="version", version=f"qa-evidence {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp, checks=True):
        sp.add_argument("bundle", help="bundle directory or archive file")
        if checks:
            sp.add_argument("--anchor", metavar="sha256:HEX", help="external anchor value: the manifest digest published outside the bundle")
            sp.add_argument("--require-anchor", action="store_true", help="exit 3 unless the supplied anchor matches the recomputed manifest digest")
            sp.add_argument("--plan-digest", metavar="sha256:HEX", help="the digest of the frozen plan (the assertion set), obtained from outside the bundle")
    sp = sub.add_parser("inspect", help="verify and print a human-readable summary")
    common(sp)
    sp.add_argument("--json", action="store_true", help="print the inspection as JSON")
    sp = sub.add_parser("verify", help="verify only")
    common(sp)
    sp.add_argument("--json", action="store_true", help="print the verification result as JSON")
    sp = sub.add_parser("html", help="write a self-contained HTML rendering (no script, no external resource)")
    common(sp)
    sp.add_argument("-o", "--output", help="file to create (default: standard output); an existing file is not overwritten")
    sp = sub.add_parser("digest", help="print the digest of the bundle manifest (the value an external anchor should hold)")
    common(sp, checks=False)
    sp = sub.add_parser("anchor", help="print anchor.json data for the bundle (data only; no attestation is created)")
    common(sp, checks=False)
    sp.add_argument("--type", dest="anchor_type", required=True, choices=ANCHOR_TYPES)
    sp.add_argument("--reference", required=True, help="where the anchor value is published")
    return p


def main(argv: Optional[List[str]] = None, out: Optional[TextIO] = None, err: Optional[TextIO] = None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    try:
        return _main(argv, out, err)
    except Exception as exc:          # a crash is not a finding: it gets its own exit status and says what it was, nothing from the bundle
        print(f"internal error: {type(exc).__name__}", file=err)
        return 4


def _main(argv, out: TextIO, err: TextIO) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    try:
        ins = inspect_bundle(args.bundle, anchor=getattr(args, "anchor", None), plan_digest=getattr(args, "plan_digest", None))
    except SourceError as exc:
        print(f"error: {safe_text(str(exc))}", file=err)
        return 2
    v = ins.verification
    status = 0 if v.ok else 1
    if args.command == "digest":
        if v.manifest_digest is None or not v.ok:
            print("error: refusing to print the manifest digest of a bundle that does not verify", file=err)
            return 1
        print(v.manifest_digest, file=out)
        print(DIGEST_ORIGIN_NOTICE, file=err)
        return 0
    if args.command == "anchor":
        if v.manifest_digest is None or not v.ok:
            print("error: refusing to name an anchor for a bundle that does not verify", file=err)
            return 1
        out.write(dumps_canonical(anchor_document(args.anchor_type, args.reference, v.manifest_digest)).decode("ascii"))
        print(DIGEST_ORIGIN_NOTICE, file=err)
        return 0
    if args.command == "verify":
        if args.json:
            out.write(json.dumps(v.to_json(), sort_keys=True, indent=2) + "\n")
        else:
            print(("OK: internally consistent" if v.ok else f"FAILED: {len(v.findings)} finding(s)"), file=out)
            print(f"external anchor: {v.anchor.notice}", file=out)
            if v.plan is not None:
                print(f"frozen assertion set: {v.plan.notice}", file=out)
            for f in v.findings:
                print(f"  {safe_text(f.code)} {safe_text(f.path)}: {safe_text(f.message)}", file=out)
    elif args.command == "inspect":
        if args.json:
            out.write(json.dumps(ins.to_json(), sort_keys=True, indent=2) + "\n")
        else:
            out.write(render_text(ins))
    elif args.command == "html":
        page = render_html(ins)
        if args.output:
            try:
                with open(args.output, "x", encoding="utf-8", newline="\n") as fh:
                    fh.write(page)
            except OSError as exc:
                print(f"error: cannot write {safe_text(args.output)}: {safe_text(exc.strerror or '')}", file=err)
                return 2
        else:
            out.write(page)
    if status == 0 and args.require_anchor and not v.anchor.matches:
        print(f"error: --require-anchor: {v.anchor.notice}", file=err)
        return 3
    if status == 0 and args.require_anchor:
        print("--require-anchor: the manifest digest matches the supplied value; where that value came from is not checked", file=err)
    return status
