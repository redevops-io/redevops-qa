# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Errors of the runner. ``code`` is a stable identifier; the message never carries content that came from a page, a bundle or a child process."""
from __future__ import annotations


class RunnerError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class PlanError(RunnerError):
    """A plan or lock was refused before anything ran (exit status 2)."""


class EnvironmentFault(RunnerError):
    """The environment cannot provide what the run needs (a dependency, a browser, a port). Never a verdict."""
