# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A pytest plugin that records, per conformance check, what was collected and what happened to it.

A test that carries the ``not_applicable`` marker and passes is reported as ``not_applicable`` (a receipt category, never a
pytest skip). It counts a skip (including an ``xfail``) as a skip, a setup error as a failure, and a collection error as a failure.
A test of the conformance directory that carries no ``check`` marker is recorded under ``UNMAPPED`` and fails the run:
nothing outside the seven checks may count towards the receipt.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from .model import ConformanceFailure

UNMAPPED = "UNMAPPED"


class ConformancePlugin:
    def __init__(self) -> None:
        self.collected: Dict[str, str] = {}              # nodeid -> check id
        self.not_applicable_nodes: set = set()           # nodeids carrying the not_applicable marker
        self.item_ids: Dict[str, Optional[str]] = {}     # nodeid -> parametrised item id
        self.results: Dict[str, Dict[str, Any]] = {}     # nodeid -> {"check", "outcome", "code", "message", "details"}
        self.collection_errors: List[str] = []
        self._pending: Dict[str, Dict[str, Any]] = {}

    # -- collection --------------------------------------------------------------------------------------------
    def pytest_collection_modifyitems(self, items: List[Any]) -> None:
        for item in items:
            marker = item.get_closest_marker("check")
            self.collected[item.nodeid] = str(marker.args[0]) if marker and marker.args else UNMAPPED
            if item.get_closest_marker("not_applicable"):
                self.not_applicable_nodes.add(item.nodeid)
            callspec = getattr(item, "callspec", None)
            self.item_ids[item.nodeid] = callspec.id if callspec is not None else None

    def pytest_collectreport(self, report: Any) -> None:
        if report.failed:
            self.collection_errors.append(str(report.nodeid))

    # -- outcomes ----------------------------------------------------------------------------------------------
    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item: Any, call: Any):
        outcome = yield
        report = outcome.get_result()
        info = self._pending.setdefault(item.nodeid, {"code": None, "message": "", "details": {}})
        exc = call.excinfo.value if call.excinfo is not None else None
        if isinstance(exc, ConformanceFailure):
            info.update(code=exc.code, message=exc.message, details=exc.details)
        elif exc is not None and not info["code"]:
            info.update(code=type(exc).__name__.upper(), message=str(exc)[:500], details={})

    def pytest_runtest_logreport(self, report: Any) -> None:
        nodeid = report.nodeid
        check = self.collected.get(nodeid, UNMAPPED)
        entry = self.results.setdefault(nodeid, {"check": check, "outcome": None, "code": None, "message": "",
                                                 "details": {}})
        info = self._pending.get(nodeid, {})
        if hasattr(report, "wasxfail"):
            entry["outcome"] = "skipped"
            return
        if report.when == "call":
            entry["outcome"] = "passed" if report.passed else ("skipped" if report.skipped else "failed")
            if entry["outcome"] == "passed" and nodeid in self.not_applicable_nodes:
                entry["outcome"] = "not_applicable"
        elif report.when in ("setup", "teardown"):
            if report.failed:
                entry["outcome"] = "failed"
            elif report.skipped and entry["outcome"] is None:
                entry["outcome"] = "skipped"
        if entry["outcome"] == "failed":
            entry.update(code=info.get("code") or entry["code"] or "TEST_FAILED",
                         message=info.get("message") or entry["message"], details=info.get("details") or entry["details"])

    # -- summary ----------------------------------------------------------------------------------------------
    def summary(self) -> Dict[str, Any]:
        outcomes = {nodeid: self.results.get(nodeid, {"check": check, "outcome": "failed", "code": "NOT_RUN",
                                                      "message": "collected but never reported", "details": {}})
                    for nodeid, check in self.collected.items()}
        return {"collected": len(self.collected), "collection_errors": list(self.collection_errors),
                "tests": [{"nodeid": nodeid, "item": self.item_ids.get(nodeid), **entry}
                          for nodeid, entry in sorted(outcomes.items())]}
