# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Fail unless a JUnit XML report shows at least one collected test and no skip, failure or error.

CI runs ``pytest --junitxml=...`` and then this script, so a job that collected nothing, or that skipped anything
(including through a ``skip`` or ``xfail`` marker), is red. Usage: ``python tools/check_junit.py REPORT.xml``.
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple


def summarize(path: str) -> Dict[str, int]:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    totals = {"tests": 0, "skipped": 0, "failures": 0, "errors": 0}
    for suite in suites:
        for key in totals:
            totals[key] += int(suite.attrib.get(key, 0))
    cases = list(root.iter("testcase"))
    totals["testcases"] = len(cases)
    totals["skip_elements"] = sum(1 for c in cases if c.find("skipped") is not None)
    return totals


def problems(totals: Dict[str, int]) -> List[Tuple[str, str]]:
    found = []
    if totals["tests"] <= 0 or totals["testcases"] <= 0:
        found.append(("NO_TESTS_COLLECTED", "the report contains no test"))
    if totals["skipped"] or totals["skip_elements"]:
        found.append(("SKIPPED_TESTS", f"{max(totals['skipped'], totals['skip_elements'])} test(s) were skipped"))
    if totals["failures"]:
        found.append(("FAILED_TESTS", f"{totals['failures']} test(s) failed"))
    if totals["errors"]:
        found.append(("ERRORED_TESTS", f"{totals['errors']} test(s) errored"))
    return found


def main(argv: List[str]) -> int:
    if len(argv) != 2:
        print("usage: check_junit.py REPORT.xml", file=sys.stderr)
        return 2
    try:
        totals = summarize(argv[1])
    except (OSError, ET.ParseError) as exc:
        print(f"FAIL REPORT_UNREADABLE: {exc}")
        return 1
    found = problems(totals)
    for code, message in found:
        print(f"FAIL {code}: {message}")
    if found:
        return 1
    print(f"OK {totals['tests']} tests, 0 skipped, 0 failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
