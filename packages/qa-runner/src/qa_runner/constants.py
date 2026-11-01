# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Names, versions, exit codes and closed vocabularies of the runner. Nothing here reads a clock, a host or an environment variable."""
from __future__ import annotations

import re

from . import __version__

RUNNER_VERSION = __version__
VERIFIER_NAME = "redevops-qa-verify"          # the id the report names as the producer of the verdicts

PLAN_SCHEMA = "redevops-qa/plan"
LOCK_SCHEMA = "redevops-qa/plan-lock"
OBSERVATIONS_SCHEMA = "redevops-qa/observations"
LANE_INPUT_SCHEMA = "redevops-qa/lane-input"
LANE_RESULT_SCHEMA = "redevops-qa/lane-result"
SCHEMA_VERSION = "1.0"

#: the engines this release can run (R0 scope: Linux x86_64, Playwright Chromium and Robot Framework; Selenium and Appium are excluded)
ENGINE_PLAYWRIGHT = "playwright-chromium"
ENGINE_ROBOT = "robot-framework"
ENGINES = (ENGINE_PLAYWRIGHT, ENGINE_ROBOT)

ORIGIN_PLACEHOLDER = "{origin}"
DEFECTS = ("none", "discount", "settings")

#: process exit codes of ``redevops-qa``: 0 only for a VERIFIED run
EXIT_VERIFIED = 0
EXIT_FAILED = 1            # at least one frozen assertion FAILED: a demonstrated product failure
EXIT_USAGE = 2             # a plan, lock or option that was refused before anything ran
EXIT_ENVIRONMENT = 3       # a lane did not run to completion (error, timeout, cancelled, unavailable): never a verdict
EXIT_INCONCLUSIVE = 4      # every lane completed but not every assertion is verified, or the engine and the verifier disagree
EXIT_REJECTED = 5          # `verify`: the evidence is not accepted (any finding: a changed, inconsistent, missing or forged file, a verdict that does not recompute, an anchor or plan digest that does not match)
EXIT_VERIFIER_UNAVAILABLE = 7   # `verify`: the verifier itself cannot run here (a pinned dependency or git is missing); nothing was verified, which says nothing about the bundle
EXIT_INTERNAL = 6          # a crash of the runner itself (never reported as a product failure)

#: what the in-process harness executor may be asked to do on behalf of a plan (anything else is denied by the action policy)
ALLOWED_ACTION_KINDS = ("navigate", "click", "fill", "check", "uncheck", "select", "press")

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")       # leaves room for ".<lane id>" inside the 64 character id pattern
LANE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,19}$")
ASSERTION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

#: bounds on what a child process may send back
MAX_CHILD_JSON_BYTES = 8 * 1024 * 1024
MAX_LOG_TAIL_BYTES = 64 * 1024
DEFAULT_LANE_DEADLINE_S = 120.0
