# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The two adapter classes.

``SuiteAdapter``: builds the command that runs an existing suite and imports the framework's native report afterwards. It cannot
steer a test while it runs; the only things it controls are what is started and how the finished report is read.

``InteractiveAdapter``: performs one bounded action at a time and returns an observation. The runner owns the budget (steps,
retries, deadline); the adapter owns only what one action does.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Mapping, Protocol, Sequence, Tuple, runtime_checkable

from .errors import AdapterKitError
from .models import (AdapterManifest, InteractiveActionRequest, InteractiveObservation, NativeAssertion, SuiteRunRequest)
from .status import ErrorCode
from .supervisor import CommandSpec, ProcessOutcome


class MalformedReport(AdapterKitError):
    """The native report cannot be read or does not have the expected shape."""
    code = ErrorCode.MALFORMED_RESULT


@dataclass(frozen=True)
class RunLayout:
    """Resolved, allowlisted locations of one suite run. ``home`` is a throwaway directory removed afterwards."""

    workspace: Path
    suite: Path
    output_dir: Path
    home: Path


@dataclass(frozen=True)
class ArtifactRef:
    path: str                      # relative to the output directory
    media_type: str
    role: str = "native-report"


@dataclass(frozen=True)
class ImportedReport:
    """What an adapter read from the framework's native report. Assertions may be ``NativeAssertion`` objects or plain
    mappings; the runner validates both, and a malformed one makes the run an ERROR, never a pass."""

    assertions: Sequence[Any] = ()
    artifacts: Sequence[ArtifactRef] = ()


@runtime_checkable
class SuiteAdapter(Protocol):
    manifest: AdapterManifest

    def build_command(self, request: SuiteRunRequest, layout: RunLayout) -> CommandSpec: ...

    def import_report(self, request: SuiteRunRequest, layout: RunLayout, outcome: ProcessOutcome) -> ImportedReport: ...


@dataclass(frozen=True)
class ActionOutcome:
    observations: Sequence[InteractiveObservation] = ()
    assertions: Sequence[Any] = ()
    artifacts: Sequence[ArtifactRef] = ()


@runtime_checkable
class InteractiveAdapter(Protocol):
    manifest: AdapterManifest

    def perform(self, request: InteractiveActionRequest, layout: "InteractiveLayout") -> ActionOutcome: ...

    def abort(self) -> None: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class InteractiveLayout:
    output_dir: Path
