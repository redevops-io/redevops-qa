# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Command line: ``python -m qa_evidence {inspect,verify,html,digest,anchor} BUNDLE``.

Exit status: 0 verification clean; 1 verification found a problem; 2 usage or the bundle cannot be opened; 3 ``--require-anchor`` was
given and the external anchor check did not succeed.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional, TextIO

from . import __version__
from .build import anchor_document
from .canon import dumps_canonical
from .constants import ANCHOR_TYPES
from .inspector import inspect_bundle
from .render import render_html, render_text
from .sources import SourceError


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m qa_evidence", description="Inspect and verify a QA evidence bundle (offline).")
    p.add_argument("--version", action="version", version=f"qa-evidence {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp, anchor=True):
        sp.add_argument("bundle", help="bundle directory or archive file")
        if anchor:
            sp.add_argument("--anchor", metavar="sha256:HEX", help="external anchor value: the manifest digest published outside the bundle")
            sp.add_argument("--require-anchor", action="store_true", help="exit 3 unless the supplied anchor matches the recomputed manifest digest")
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
    common(sp, anchor=False)
    sp = sub.add_parser("anchor", help="print anchor.json data for the bundle (data only; no attestation is created)")
    common(sp, anchor=False)
    sp.add_argument("--type", dest="anchor_type", required=True, choices=ANCHOR_TYPES)
    sp.add_argument("--reference", required=True, help="where the anchor value is published")
    return p


def main(argv: Optional[List[str]] = None, out: Optional[TextIO] = None, err: Optional[TextIO] = None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    try:
        ins = inspect_bundle(args.bundle, anchor=getattr(args, "anchor", None))
    except SourceError as exc:
        print(f"error: {exc}", file=err)
        return 2
    v = ins.verification
    status = 0 if v.ok else 1
    if args.command == "digest":
        if v.manifest_digest is None or not v.ok:
            print("error: refusing to print the manifest digest of a bundle that does not verify", file=err)
            return 1
        print(v.manifest_digest, file=out)
        return 0
    if args.command == "anchor":
        if v.manifest_digest is None or not v.ok:
            print("error: refusing to name an anchor for a bundle that does not verify", file=err)
            return 1
        out.write(dumps_canonical(anchor_document(args.anchor_type, args.reference, v.manifest_digest)).decode("ascii"))
        return 0
    if args.command == "verify":
        if args.json:
            out.write(json.dumps(v.to_json(), sort_keys=True, indent=2) + "\n")
        else:
            print(("OK: internally consistent" if v.ok else f"FAILED: {len(v.findings)} finding(s)"), file=out)
            print(f"external anchor: {v.anchor.notice}", file=out)
            for f in v.findings:
                print(f"  {f.code} {f.path}: {f.message}", file=out)
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
                print(f"error: cannot write {args.output}: {exc.strerror}", file=err)
                return 2
        else:
            out.write(page)
    if status == 0 and args.require_anchor and not v.anchor.established:
        print(f"error: --require-anchor: {v.anchor.notice}", file=err)
        return 3
    return status
