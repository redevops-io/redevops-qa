# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Observations recorded by a Robot suite: ``qa-observe:<name>=<value>`` tags in ``output.xml``.

A suite *records* what it saw (``Set Tags    qa-observe:order_101_total_cents=${total}`` at run time; Robot Framework 7.5 writes the tag into the test's
``<tag>`` list) and never judges it for the verifier: the importer here turns the tags into an observation record, and an independent check program
compares the record with the value frozen in an assertion. Nothing in this module knows an expected value or produces a verdict.

Strict on purpose: it reads the same hardened document as ``parse_output_xml`` (no DOCTYPE or entity, size cap, schema version 5, statistics that agree with
the tests), refuses a tag that starts with ``qa-observe:`` but does not match the grammar (it is never skipped quietly), refuses a name that is used twice
(whether the values agree or not), a name that looks like a verdict or an expected value, and more than ``MAX_OBSERVATIONS`` names. A value is an integer when it is
a canonical decimal integer (at most 15 digits), otherwise a string of ``A-Za-z0-9._:/@+-``.

``observation_document`` renders the record as a ``qa-checks/reference-1`` document of kind ``RobotObservations`` with the run it belongs to and the digest
of the raw ``output.xml`` it was read from, so a record can be re-derived from the native report and compared.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

from qa_adapter_kit import MalformedReport

from .output_xml import parse_output_xml

OBSERVE_PREFIX = "qa-observe:"
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
VALUE_RE = re.compile(r"^[A-Za-z0-9._:/@+-]{1,128}$")
INT_RE = re.compile(r"^-?(0|[1-9][0-9]{0,14})$")
MAX_OBSERVATIONS = 64
#: names an observation may not have: they would read as a verdict or an expected value to whoever reads the record
RESERVED_NAMES = frozenset({"verdict", "verified", "pass", "passed", "fail", "failed", "ok", "success", "expected", "expect", "expected_value", "predicate",
                            "result", "outcome", "status", "compliant", "compliance", "violation", "violations", "finding", "findings", "severity", "threshold"})
REFERENCE_API_VERSION = "qa-checks/reference-1"
DOCUMENT_KIND = "RobotObservations"
Value = Union[int, str]


@dataclass(frozen=True)
class RobotObservations:
    values: Mapping[str, Value]                 # sorted by name
    tests: Tuple[Tuple[str, str], ...]          # (native test id, native status) of every test in the run
    raw_sha256: str                             # of the raw output.xml, hex
    engine_release: str                         # "7.5"


def _typed(value: str) -> Value:
    return int(value) if INT_RE.fullmatch(value) else value


def parse_observations(data: bytes) -> RobotObservations:
    """Read the ``qa-observe:`` tags of every test of an ``output.xml``. Raises ``MalformedReport`` for anything the grammar does not allow."""
    parsed = parse_output_xml(data)                  # the hardening and the consistency checks of the test importer come first
    root = ET.fromstring(data)
    values: Dict[str, Value] = {}
    for test in root.iter("test"):
        for tag in test.findall("tag"):
            text = (tag.text or "").strip()
            if not text.lower().startswith(OBSERVE_PREFIX):
                continue
            name, sep, value = text[len(OBSERVE_PREFIX):].partition("=")
            if not sep or not NAME_RE.fullmatch(name) or not VALUE_RE.fullmatch(value):
                raise MalformedReport("an observation tag does not match qa-observe:<name>=<value> (name: lower case letters, digits and '_'; value: A-Za-z0-9._:/@+-)")
            if name in RESERVED_NAMES:
                raise MalformedReport(f"an observation may not be named {name!r}: it would read as a verdict or an expected value")
            if name in values:
                raise MalformedReport(f"the observation {name!r} is recorded twice")
            if len(values) >= MAX_OBSERVATIONS:
                raise MalformedReport(f"more than {MAX_OBSERVATIONS} observations")
            values[name] = _typed(value)
    release = re.match(r"^Robot (\d+\.\d+(?:\.\d+)?)", parsed.generator)
    return RobotObservations(values=dict(sorted(values.items())), tests=tuple((a.native_id, a.status.value) for a in parsed.assertions),
                             raw_sha256=parsed.raw_sha256, engine_release=release.group(1) if release else "unknown")


def observation_document(obs: RobotObservations, *, run_id: str, lane_id: str) -> Dict[str, Any]:
    """The record as a ``qa-checks/reference-1`` document (the ids of the tests that ran, no native status: that stays in the engine's own report). It carries no expected value and no verdict (the check program and the loader both refuse one)."""
    return {"apiVersion": REFERENCE_API_VERSION, "kind": DOCUMENT_KIND, "metadata": {"name": lane_id},
            "spec": {"engine": "robot-framework", "engine_release": obs.engine_release, "run_id": run_id, "lane_id": lane_id,
                     "output_xml_sha256": "sha256:" + obs.raw_sha256, "tests": [i for i, _ in obs.tests],
                     "observations": dict(obs.values)}}
