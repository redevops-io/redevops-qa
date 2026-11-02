# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``RobotSuiteAdapter``: run an existing Robot Framework suite under the shared supervisor and import its ``output.xml``.

The adapter builds ``python -I -m robot ...`` (isolated: no working directory or ``PYTHON*`` variable on the import path, so a file in the
workspace cannot shadow a library), checks the library allowlist before and after the run, and imports test-level results only. It does
not steer a test and it never installs anything. The raw ``output.xml`` stays in the run's throwaway directory (it holds log messages and
keyword arguments, which can carry secrets); the evidence artifact is ``robot-summary.json``, which has no messages or arguments and records
the digest of the raw file. ``RobotConfig.keep_raw_output`` copies the raw file as well (the runner then refuses it if a known secret is in it).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional, Sequence

from qa_adapter_kit import (AdapterClass, AdapterManifest, ArtifactRef, CommandSpec, FrameworkRef, ImportedReport, Limits, MalformedReport,
                            ModelError, PinnedFile, ProcessOutcome, RunLayout, SuiteRunRequest)

from qa_adapter_kit.boundedread import UnsafeRead, read_regular

from .output_xml import MAX_OUTPUT_BYTES, parse_output_xml
from .policy import RobotConfig, check_run, scan_suite

ADAPTER_ID = "robot-suite"
ADAPTER_VERSION = "0.1.0"
ROBOT_RELEASE = "7.5"
LICENSE_COMPONENT = "robotframework"
ENV_ALLOWLIST = ("QA_BASE_URL",)
SUMMARY_NAME = "robot-summary.json"
SUMMARY_SCHEMA = "redevops-qa/robot-summary/1"
_SELECTOR = re.compile(r"^(tag:)?[A-Za-z0-9_][A-Za-z0-9_ .-]{0,127}$")
# Robot Framework's exit code is the number of failed tests (0 to 250); 251 and above mean an invalid call, a stop or an internal error
_TRUSTED_MAX = 250
_DEFAULT_LAUNCHER = ("-m", "robot")


def suite_manifest(python: str, *, pinned_files: Sequence[PinnedFile] = (), limits: Optional[Limits] = None) -> AdapterManifest:
    """``python`` is the absolute path of the interpreter that has Robot Framework 7.5 installed."""
    return AdapterManifest(
        adapter_id=ADAPTER_ID, adapter_version=ADAPTER_VERSION, adapter_class=AdapterClass.SUITE,
        framework=FrameworkRef(name="robotframework", pinned_release=ROBOT_RELEASE, license_component=LICENSE_COMPONENT),
        capabilities=("run_suite", "import_native_report"), allowed_executables=(python,), env_allowlist=ENV_ALLOWLIST,
        pinned_files=tuple(pinned_files), limits=limits or Limits(deadline_s=600, output_limit_bytes=2_000_000, kill_grace_s=5),
        report_formats=("robot-output-xml",), network="egress-gateway")


class RobotSuiteAdapter:
    """``launcher`` replaces ``-m robot`` for the offline tests, which start a small script that writes a recorded ``output.xml``."""

    def __init__(self, python: str, *, config: Optional[RobotConfig] = None, manifest: Optional[AdapterManifest] = None,
                 launcher: Sequence[str] = _DEFAULT_LAUNCHER):
        self.python = python
        self.config = config or RobotConfig()
        self.manifest = manifest or suite_manifest(python)
        self.launcher = tuple(launcher)
        self._scan = None

    def _raw_dir(self, layout: RunLayout) -> Path:
        return layout.home / "robot"

    def build_command(self, request: SuiteRunRequest, layout: RunLayout) -> CommandSpec:
        for selector in request.selectors:
            if not _SELECTOR.match(selector):
                raise ModelError("a selector for this adapter is a test name or 'tag:' and a tag name")
        self._scan = scan_suite(layout.workspace, layout.suite, self.config)         # refuses before anything starts
        raw = self._raw_dir(layout)
        raw.mkdir(parents=True, exist_ok=True)
        argv = [self.python, "-I", *self.launcher, "--outputdir", str(raw), "--output", "output.xml", "--log", "NONE", "--report", "NONE",
                "--loglevel", "WARN", "--console", "quiet", "--consolecolors", "off"]
        for selector in request.selectors:
            argv += ["--include", selector[4:]] if selector.startswith("tag:") else ["--test", selector]
        argv.append(str(layout.suite))
        return CommandSpec(argv=tuple(argv), cwd=str(layout.workspace))

    def import_report(self, request: SuiteRunRequest, layout: RunLayout, outcome: ProcessOutcome) -> ImportedReport:
        if outcome.exit_code is None or outcome.exit_code > _TRUSTED_MAX:
            raise MalformedReport(f"Robot Framework ended with exit code {outcome.exit_code}, so its report is not trusted")
        raw_path = self._raw_dir(layout) / "output.xml"
        try:
            # one descriptor, regular files only, byte cap and deadline, no symbolic link below the engine's home (a FIFO where the report should be would hang a plain read)
            data = read_regular(str(raw_path), max_bytes=MAX_OUTPUT_BYTES, deadline_s=30.0, follow_symlinks=False, root=str(layout.home))
        except UnsafeRead:
            raise MalformedReport("output.xml was not written, is not a regular file, or is too large") from None
        parsed = parse_output_xml(data)
        scan = self._scan or scan_suite(layout.workspace, layout.suite, self.config)
        check_run(parsed.owners, parsed.keyword_names, scan, self.config)
        summary = {"schema": SUMMARY_SCHEMA, "generator": parsed.generator, "raw_output_sha256": parsed.raw_sha256,
                   "libraries_used": sorted(parsed.owners),
                   "tests": [{"native_id": a.native_id, "name": a.name, "status": a.status.value, "declared_assertion_ids": list(a.declared_assertion_ids),
                              "duration_s": a.duration_s} for a in parsed.assertions]}
        (layout.output_dir / SUMMARY_NAME).write_text(json.dumps(summary, sort_keys=True, indent=1), encoding="utf-8")
        artifacts = [ArtifactRef(path=SUMMARY_NAME, media_type="application/json", role="native-summary")]
        if self.config.keep_raw_output:
            (layout.output_dir / "output.xml").write_bytes(data)             # the bytes that were read and parsed, not a second read of the path
            artifacts.append(ArtifactRef(path="output.xml", media_type="application/xml", role="native-report"))
        return ImportedReport(assertions=parsed.assertions, artifacts=artifacts)
