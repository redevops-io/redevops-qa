# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``SeleniumSuiteAdapter``: run an existing pytest-based Selenium suite under the shared supervisor and import its JUnit XML.

The adapter only builds the command (``python -m pytest <suite> --junitxml=<output>/junit.xml``) and reads the report afterwards.
It does not steer a test while it runs. The Python executable and the pinned files come from the manifest; nothing is installed or
downloaded (a sealed run refuses it). The browser and the driver executable are the worker's: the suite is given their paths through
the allowlisted variables ``QA_CHROME_BINARY`` and ``QA_CHROMEDRIVER_PATH`` and must pass the driver path to Selenium itself, which then
never invokes Selenium Manager.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional, Sequence

from qa_adapter_kit import (AdapterClass, AdapterManifest, ArtifactRef, CommandSpec, FrameworkRef, ImportedReport, Limits, MalformedReport,
                            ModelError, PinnedFile, ProcessOutcome, RunLayout, SuiteRunRequest)

from .junit import read_junit

ADAPTER_ID = "selenium-suite"
ADAPTER_VERSION = "0.1.0"
SELENIUM_RELEASE = "4.52.0"
LICENSE_COMPONENT = "selenium-python"
ENV_ALLOWLIST = ("QA_BASE_URL", "QA_CHROMEDRIVER_PATH", "QA_CHROME_BINARY")
REPORT_NAME = "junit.xml"
_SELECTOR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
# pytest exit codes whose report can be trusted: 0 all passed, 1 some failed, 5 nothing collected (the runner then reports ERROR)
_TRUSTED_EXIT = (0, 1, 5)


def suite_manifest(python: str, *, pinned_files: Sequence[PinnedFile] = (), limits: Optional[Limits] = None) -> AdapterManifest:
    """``python`` is the absolute path of the interpreter that has pytest and Selenium installed at the pinned versions."""
    return AdapterManifest(
        adapter_id=ADAPTER_ID, adapter_version=ADAPTER_VERSION, adapter_class=AdapterClass.SUITE,
        framework=FrameworkRef(name="selenium", pinned_release=SELENIUM_RELEASE, license_component=LICENSE_COMPONENT),
        capabilities=("run_suite", "import_native_report"), allowed_executables=(python,), env_allowlist=ENV_ALLOWLIST,
        pinned_files=tuple(pinned_files), limits=limits or Limits(deadline_s=600, output_limit_bytes=2_000_000, kill_grace_s=5),
        report_formats=("junit-xml",), network="egress-gateway")


class SeleniumSuiteAdapter:
    def __init__(self, python: str, manifest: Optional[AdapterManifest] = None):
        self.python = python
        self.manifest = manifest or suite_manifest(python)

    def build_command(self, request: SuiteRunRequest, layout: RunLayout) -> CommandSpec:
        for selector in request.selectors:
            if not _SELECTOR.match(selector):
                raise ModelError("a selector for this adapter is a test or marker name made of letters, digits and underscores")
        argv = [self.python, "-m", "pytest", str(layout.suite), "-p", "no:cacheprovider", "-q", "--color=no", "-o", "junit_family=xunit1",
                f"--junitxml={layout.output_dir / REPORT_NAME}"]
        if request.selectors:
            argv += ["-k", " or ".join(request.selectors)]
        return CommandSpec(argv=tuple(argv), cwd=str(layout.workspace))

    def import_report(self, request: SuiteRunRequest, layout: RunLayout, outcome: ProcessOutcome) -> ImportedReport:
        if outcome.exit_code not in _TRUSTED_EXIT:
            raise MalformedReport(f"pytest ended with exit code {outcome.exit_code}, so its report is not trusted")
        assertions = read_junit(layout.output_dir / REPORT_NAME)
        return ImportedReport(assertions=assertions, artifacts=[ArtifactRef(path=REPORT_NAME, media_type="application/xml", role="native-report")])
