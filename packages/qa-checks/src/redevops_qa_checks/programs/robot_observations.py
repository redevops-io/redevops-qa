# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The observations a Robot Framework suite recorded (``qa-observe:<name>=<value>`` tags, imported into a ``RobotObservations`` reference document).

This program observes and nothing else. It never receives an expected value (there is no parameter for one) and never returns a verdict: the harness verifier
compares what it returns with the value frozen in the assertion. It returns the number of ``RobotObservations`` documents it was given (a record is exactly one),
the name/value pairs of that document (integers and strings only) and the load errors of its input, so a missing, duplicated or unreadable record cannot equal a
frozen value that was written for a good one."""
from __future__ import annotations

from ._common import error_rows

PROGRAM_ID = "evidence.robot-observations"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Name/value observations recorded by a Robot Framework run through qa-observe tags (observed values only)"
SUPPORT = ("programs/_common.py",)


def run(data):
    docs = [r for r in data.references if r.kind == "RobotObservations"]
    observed = {}
    if len(docs) == 1:
        found = docs[0].spec.get("observations")
        if hasattr(found, "items"):
            for name, value in found.items():
                if type(name) is str and (type(value) is int or type(value) is str):
                    observed[name] = value
    return {"documents": len(docs), "observations": observed, "input_errors": error_rows(data)}
