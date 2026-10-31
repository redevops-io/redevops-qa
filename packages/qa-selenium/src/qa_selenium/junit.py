# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Import a JUnit XML report (what a pytest-based Selenium suite writes with ``--junitxml``) as native assertions.

The importer is strict. A report with a DOCTYPE or entity declaration is refused (no entity expansion), an oversized report is
refused, and so is one whose declared test counts disagree with the testcases it contains (a truncated file). Every testcase is
one native assertion: ERROR over FAIL over SKIP over PASS when several outcomes were recorded. A property ``qa-assert`` names the
canonical assertion id the test declares itself evidence for; an invalid id is ignored (and so cannot support a mapping).
"""
from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Tuple

from qa_adapter_kit import MalformedReport, NativeAssertion, Status

MAX_REPORT_BYTES = 20 * 1024 * 1024
MAX_TESTCASES = 10_000
ASSERT_PROPERTY = "qa-assert"
_ID_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_BAD_ID_CHARS = re.compile(r"[^A-Za-z0-9._:-]")
_DOCTYPE = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


def _native_id(classname: str, name: str, taken: Dict[str, int]) -> str:
    raw = f"{classname}::{name}" if classname else name
    cleaned = _BAD_ID_CHARS.sub("_", raw).lstrip("._:-") or "t"
    if len(cleaned) > 100:
        cleaned = cleaned[:80] + "-" + hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]
    candidate, n = cleaned, 1
    while candidate in taken:
        n += 1
        candidate = f"{cleaned}.dup{n}"
    taken[candidate] = 1
    return candidate


def _seconds(value: str | None) -> float:
    try:
        x = float(value) if value is not None else 0.0
    except ValueError:
        return 0.0
    return x if 0.0 <= x < 1e7 else 0.0


def _message(child: ET.Element) -> str:
    text = (child.get("message") or (child.text or "")).strip()
    return text[:500]


def parse_junit(data: bytes) -> Tuple[NativeAssertion, ...]:
    if len(data) > MAX_REPORT_BYTES:
        raise MalformedReport("the JUnit report is larger than the limit")
    if _DOCTYPE.search(data[:65536]) or _DOCTYPE.search(data):
        raise MalformedReport("the JUnit report declares a DOCTYPE or an entity, which is refused")
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise MalformedReport("the JUnit report is not well-formed XML") from None
    if root.tag not in ("testsuites", "testsuite"):
        raise MalformedReport("the JUnit report has no testsuite")
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    cases = list(root.iter("testcase"))
    if len(cases) > MAX_TESTCASES:
        raise MalformedReport("the JUnit report has too many testcases")
    declared = [s.get("tests") for s in suites if s.get("tests") is not None]
    if declared and len(declared) == len(suites):
        try:
            if sum(int(x) for x in declared) != len(cases):
                raise MalformedReport("the declared test counts disagree with the testcases (a truncated report)")
        except ValueError:
            raise MalformedReport("a testsuite has a test count that is not a number") from None
    taken: Dict[str, int] = {}
    out: List[NativeAssertion] = []
    for case in cases:
        name = case.get("name")
        if not name:
            raise MalformedReport("a testcase has no name")
        children = {c.tag for c in case if c.tag in ("failure", "error", "skipped")}
        if "error" in children:
            status, node = Status.ERROR, case.find("error")
        elif "failure" in children:
            status, node = Status.FAIL, case.find("failure")
        elif "skipped" in children:
            status, node = Status.SKIP, case.find("skipped")
        else:
            status, node = Status.PASS, None
        declared_ids = tuple(dict.fromkeys(
            p.get("value", "").strip() for p in case.iter("property")
            if p.get("name") == ASSERT_PROPERTY and _ID_OK.match(p.get("value", "").strip())))
        out.append(NativeAssertion(
            native_id=_native_id(case.get("classname", ""), name, taken), name=name[:512], status=status,
            message=_message(node) if node is not None else "", duration_s=_seconds(case.get("time")),
            declared_assertion_ids=declared_ids[:32], source=(case.get("file") or case.get("classname") or "")[:512]))
    return tuple(out)


def read_junit(path: Path) -> Tuple[NativeAssertion, ...]:
    try:
        size = path.stat().st_size
        if size > MAX_REPORT_BYTES:
            raise MalformedReport("the JUnit report is larger than the limit")
        return parse_junit(path.read_bytes())
    except OSError:
        raise MalformedReport("the JUnit report was not written") from None
