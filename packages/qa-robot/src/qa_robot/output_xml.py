# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Strict import of a Robot Framework 7 ``output.xml`` (schema version 5).

Only test-level facts are read: the test's status and message, its tags (``qa-assert:<id>`` declares a canonical assertion id), its
duration and the long name made of its suites. Keyword arguments and log messages are never copied, so a password passed to a keyword
cannot reach a result through this importer. Keyword *owners* (the library or resource a keyword belongs to) are collected only to verify
the library allowlist after the run.

Refused: a DOCTYPE or entity declaration, an oversized file, a root that is not ``robot`` with ``schemaversion="5"``, an RPA run, a test
without a PASS, FAIL or SKIP status, and statistics that disagree with the tests (a truncated file).
"""
from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Tuple

from qa_adapter_kit import MalformedReport, NativeAssertion, Status

MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_TESTS = 10_000
SCHEMA_VERSION = "5"
ASSERT_TAG = re.compile(r"^qa-assert:([A-Za-z0-9][A-Za-z0-9._:-]{0,127})$", re.IGNORECASE)
_BAD = re.compile(r"[^A-Za-z0-9._:-]")
_DOCTYPE = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)
_STATUS = {"PASS": Status.PASS, "FAIL": Status.FAIL, "SKIP": Status.SKIP}


@dataclass(frozen=True)
class ParsedRobot:
    assertions: Tuple[NativeAssertion, ...]
    owners: FrozenSet[str]                # every ``owner`` attribute of a keyword anywhere in the run
    keyword_names: FrozenSet[str]         # every keyword name (for the dynamic-construct check)
    generator: str
    raw_sha256: str


def _native_id(longname: str, taken: Dict[str, int]) -> str:
    cleaned = _BAD.sub("_", longname.replace(" ", "_")).lstrip("._:-") or "t"
    if len(cleaned) > 100:
        cleaned = cleaned[:80] + "-" + hashlib.sha256(longname.encode("utf-8", "replace")).hexdigest()[:16]
    candidate, n = cleaned, 1
    while candidate in taken:
        n += 1
        candidate = f"{cleaned}.dup{n}"
    taken[candidate] = 1
    return candidate


def _seconds(value) -> float:
    try:
        x = float(value)
    except (TypeError, ValueError):
        return 0.0
    return x if 0.0 <= x < 1e7 else 0.0


def parse_output_xml(data: bytes) -> ParsedRobot:
    if len(data) > MAX_OUTPUT_BYTES:
        raise MalformedReport("output.xml is larger than the limit")
    if _DOCTYPE.search(data):
        raise MalformedReport("output.xml declares a DOCTYPE or an entity, which is refused")
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise MalformedReport("output.xml is not well-formed XML") from None
    if root.tag != "robot":
        raise MalformedReport("output.xml has no robot root")
    if root.get("schemaversion") != SCHEMA_VERSION:
        raise MalformedReport(f"output.xml has schema version {root.get('schemaversion')!r}; only version {SCHEMA_VERSION} (Robot Framework 7) is read")
    if root.get("rpa") == "true":
        raise MalformedReport("an RPA run has tasks, not tests, and is not imported")
    top = root.find("suite")
    if top is None:
        raise MalformedReport("output.xml has no suite")
    taken: Dict[str, int] = {}
    out: List[NativeAssertion] = []

    def walk(suite: ET.Element, prefix: str) -> None:
        name = suite.get("name") or ""
        longname = f"{prefix}.{name}" if prefix else name
        for child in suite:
            if child.tag == "suite":
                walk(child, longname)
            elif child.tag == "test":
                if len(out) >= MAX_TESTS:
                    raise MalformedReport("output.xml has too many tests")
                tname = child.get("name")
                status_el = child.find("status")
                if not tname or status_el is None or status_el.get("status") not in _STATUS:
                    raise MalformedReport("a test has no name or no PASS, FAIL or SKIP status")
                ids = tuple(dict.fromkeys(m.group(1) for t in child.findall("tag") if (m := ASSERT_TAG.match((t.text or "").strip()))))
                out.append(NativeAssertion(
                    native_id=_native_id(f"{longname}.{tname}", taken), name=tname[:512], status=_STATUS[status_el.get("status")],
                    message=(status_el.text or "").strip()[:500], duration_s=_seconds(status_el.get("elapsed")),
                    declared_assertion_ids=ids[:32], source=longname[:512]))

    walk(top, "")
    stat = root.find("statistics/total/stat")
    if stat is None:
        raise MalformedReport("output.xml has no statistics, so it may be truncated")
    try:
        counted = sum(int(stat.get(k, "0")) for k in ("pass", "fail", "skip"))
    except ValueError:
        raise MalformedReport("the statistics are not numbers") from None
    if counted != len(out):
        raise MalformedReport("the statistics disagree with the tests in output.xml")
    owners = frozenset(k.get("owner") for k in root.iter("kw") if k.get("owner"))
    names = frozenset(k.get("name") for k in root.iter("kw") if k.get("name"))
    return ParsedRobot(tuple(out), owners, names, root.get("generator") or "", hashlib.sha256(data).hexdigest())
