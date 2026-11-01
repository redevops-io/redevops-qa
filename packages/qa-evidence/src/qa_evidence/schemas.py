# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Loading of the checked-in JSON Schema files and validation of a document against one, including the version gate.

Version gate and the security-sensitive / informational split (also in the README):

* ``schema`` must be the expected schema id. ``schema_version`` is ``MAJOR.MINOR``.
* A MAJOR other than the supported one is refused (``UNSUPPORTED_MAJOR_VERSION``) before anything else is read.
* A newer MINOR is read with the rules of this reader: it adds nothing that is trusted. A new property is accepted only inside an
  object the schema marks informational (``environment``, ``producer``, ``extensions``) and is then listed; anywhere else it is refused
  (``UNKNOWN_FIELD``), because every other object (files, digests, lanes, accounting, verdicts, provenance, anchor) is security-sensitive.
* Informational values can never change a verdict, a digest check or the anchor check.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .constants import SUPPORTED_MAJOR, SUPPORTED_MINOR, VERSION_RE
from .minischema import Validator

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
FILES = {"qa-evidence/bundle-manifest": "bundle-manifest-1.schema.json", "qa-evidence/run-report": "run-report-1.schema.json",
         "qa-evidence/anchor": "anchor-1.schema.json"}


@lru_cache(maxsize=None)
def load_schema(schema_id: str) -> Dict[str, Any]:
    return json.loads((SCHEMA_DIR / FILES[schema_id]).read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def validator_for(schema_id: str) -> Validator:
    return Validator(load_schema(schema_id))


def parse_version(text: Any):
    m = VERSION_RE.fullmatch(text) if isinstance(text, str) else None
    return (int(m.group(1)), int(m.group(2))) if m else None


def check_document(doc: Any, schema_id: str) -> Tuple[List[Tuple[str, str, str]], List[str], List[Tuple[str, str]]]:
    """Gate and validate. Returns (problems as (code, pointer, message), informational pointers, notes as (code, message))."""
    problems: List[Tuple[str, str, str]] = []
    notes: List[Tuple[str, str]] = []
    if not isinstance(doc, dict):
        return [("SCHEMA_INVALID", "/", "the document must be a JSON object")], [], notes
    if doc.get("schema") != schema_id:
        return [("WRONG_SCHEMA", "/schema", f"expected {schema_id!r}")], [], notes
    version = parse_version(doc.get("schema_version"))
    if version is None:
        return [("SCHEMA_INVALID", "/schema_version", "schema_version must look like MAJOR.MINOR")], [], notes
    if version[0] != SUPPORTED_MAJOR:
        return [("UNSUPPORTED_MAJOR_VERSION", "/schema_version", f"major version {version[0]} is not supported (this reader supports {SUPPORTED_MAJOR})")], [], notes
    if version[1] > SUPPORTED_MINOR:
        notes.append(("NEWER_MINOR_VERSION", f"schema version {doc['schema_version']} is newer than {SUPPORTED_MAJOR}.{SUPPORTED_MINOR}; "
                                             "only informational additions are tolerated"))
    issues, info = validator_for(schema_id).validate(doc)
    for issue in issues:
        code = "UNKNOWN_FIELD" if issue.code == "UNKNOWN_FIELD" else "SCHEMA_INVALID"
        message = issue.message if code == "UNKNOWN_FIELD" else f"{issue.code}: {issue.message}"
        problems.append((code, issue.pointer, message))
    return problems, info, notes
