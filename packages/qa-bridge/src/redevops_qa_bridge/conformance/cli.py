# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Command line of the conformance suite.

``run``     run the suite against the selected pin set; write the receipt (and optionally the divergence report);
            exit 0 only if the receipt's result is PASS.
``verify``  re-check a receipt's hash and report VALID, STALE, TAMPERED, INVALID or FAILED against the current pins.

Examples::

    python -m redevops_qa_bridge.conformance.cli run --pin-set c4 --receipt receipt.json --report report.json
    python -m redevops_qa_bridge.conformance.cli verify receipt.json --pin-set c4
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .. import deps
from ..errors import BridgeError
from ..pins import Pins, find_pins_file, load_pins

DEFAULT_TESTS = Path("packages") / "qa-bridge" / "tests" / "conformance"


def _load(args: argparse.Namespace) -> Pins:
    return load_pins(Path(args.pins) if args.pins else None, args.pin_set)


def _write(path: str, doc) -> None:
    Path(path).write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def cmd_run(args: argparse.Namespace) -> int:
    import pytest
    from . import context, model
    from .pytest_plugin import ConformancePlugin
    from .receipt import build_receipt
    from .report import build_report, render_markdown

    pins = _load(args)
    context.set_pins(pins)
    model.reset_evidence()
    deps.prepare_paths(pins)
    availability = deps.availability()
    root = pins.root
    tests_dir = Path(args.tests_dir) if args.tests_dir else root / DEFAULT_TESTS
    plugin = ConformancePlugin()
    argv = [str(tests_dir), "-q", "--no-header", "-p", "no:cacheprovider", "--strict-markers", "-W", "error"]
    if args.junit:
        argv += ["--junitxml", args.junit]
    code = pytest.main(argv, plugins=[plugin])
    summary = plugin.summary()
    receipt = build_receipt(pins, summary, model.EVIDENCE, availability, root)
    _write(args.receipt, receipt)
    print(f"receipt {args.receipt}: result {receipt['result']}, {receipt['collected_tests']} collected, "
          f"{receipt['skipped_tests']} skipped, {receipt['failed_tests']} failed, {receipt['not_applicable_tests']} "
          f"not applicable, receipt_hash {receipt['receipt_hash']}")
    for c in receipt["checks"]:
        print(f"  {c['check_id']} {c['name']}: {c['status']} ({c['passed']}/{c['collected']} passed"
              f"{', ' + str(c['not_applicable']) + ' n/a' if c['not_applicable'] else ''}"
              f"{', codes ' + ','.join(c['failure_codes']) if c['failure_codes'] else ''})")
    if args.report:
        report = build_report(summary, receipt)
        _write(args.report, report)
        if args.report_md:
            Path(args.report_md).write_text(render_markdown(report), encoding="utf-8")
    return 0 if receipt["result"] == "PASS" else 1


def cmd_verify(args: argparse.Namespace) -> int:
    from .verify import EXIT, verify_receipt
    pins = _load(args)
    if args.pin_set is None:
        try:
            recorded = json.loads(Path(args.receipt).read_text(encoding="utf-8")).get("subjects", {}).get("pin_set")
            if recorded and recorded in pins.available_sets:
                pins = load_pins(Path(args.pins) if args.pins else None, recorded)
        except (OSError, ValueError, AttributeError):
            pass
    deps.prepare_paths(pins)
    root = None if args.skip_redevops_commit else pins.root
    status, reasons = verify_receipt(Path(args.receipt), pins, redevops_root=root, accept_equal_tree=args.accept_equal_tree,
                                     forbid_not_applicable=args.forbid_not_applicable)
    print(status)
    for reason in reasons:
        print(f"  {reason}")
    return EXIT[status]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="redevops-qa-conformance")
    parser.add_argument("--pins", default=None, help="path to pins.toml (default: found from the package or REDEVOPS_QA_PINS)")
    parser.add_argument("--pin-set", default=None, help="pin set to use (default: REDEVOPS_QA_PIN_SET or default_set)")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--receipt", required=True)
    run.add_argument("--report", default=None)
    run.add_argument("--report-md", default=None)
    run.add_argument("--junit", default=None)
    run.add_argument("--tests-dir", default=None)
    run.set_defaults(func=cmd_run)
    ver = sub.add_parser("verify")
    ver.add_argument("receipt")
    ver.add_argument("--skip-redevops-commit", action="store_true",
                     help="do not compare the receipt's redevops-qa commit with the working tree's HEAD")
    ver.add_argument("--accept-equal-tree", action="store_true",
                     help="a different redevops-qa commit with the same git tree is current (patches re-applied with git am)")
    ver.add_argument("--forbid-not-applicable", action="store_true",
                     help="the pin set must have no not-applicable item: a receipt that lists one is FAILED")
    ver.set_defaults(func=cmd_verify)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BridgeError as exc:
        print(f"FAIL {exc.code}: {exc.message}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
