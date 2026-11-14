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
NOT_KEPT_SCHEMA = "redevops-qa/evidence-not-kept"
NOT_KEPT_PATH = "logs/evidence-not-kept.json"        # written only when the evidence budget kept something out: the bundle paths that are absent on purpose (``verify`` tolerates exactly these, in a lane that says so)
SCHEMA_VERSION = "1.0"
PLAN_SCHEMA_VERSION = "1.1"        # plan and lock: 1.1 made `requests` and `probes` (every assertion) and, for a Robot lane, `suite_sha256` part of the plan; 1.0 documents are refused by name

#: the engines this release can run (R0 scope: Linux x86_64, Playwright Chromium and Robot Framework; Selenium and Appium are excluded)
ENGINE_PLAYWRIGHT = "playwright-chromium"
ENGINE_ROBOT = "robot-framework"
ENGINES = (ENGINE_PLAYWRIGHT, ENGINE_ROBOT)

#: the report states, in its limitations, that egress is not enforced for a Robot lane (the lane ids are listed, so the statement is exactly as long as the plan's Robot lanes)
ROBOT_EGRESS_LIMITATION_ID = "egress-not-enforced-robot"


def robot_egress_limitation_text(lane_ids) -> str:
    return ("Network egress is NOT enforced for the Robot Framework lane(s) of this run (" + ", ".join(sorted(lane_ids)) + "): a Robot library opens its own sockets, "
            "the egress gateway is not in the path of that traffic, and the library allowlist is a guard, not a sandbox. Nothing in this report shows that those "
            "lanes' traffic was limited to the allowed origin; each such lane's egress-profile.json records not-enforced.")


#: the statement of a run whose Robot lane asks for the kernel layers (profile ``origin-only``): what limits it, and what does not. Derived from the plan alone, so ``verify`` can require the exact text
ROBOT_EGRESS_LAYERS_ID = "egress-layers-robot"


def robot_egress_layers_text(lane_ids) -> str:
    return ("Network egress of the Robot Framework lane(s) of this run (" + ", ".join(sorted(lane_ids)) + ") is limited by kernel layers on the lane's process, not by the egress gateway: "
            "a seccomp filter with a supervising thread lets TCP connect() through only to the plan's allow-list (one loopback address and port), refuses UDP, raw, IPv6, netlink and other "
            "socket kinds, listen(), connect() to a local socket path, TCP Fast Open and io_uring, and records every refusal; Landlock limits TCP connect() to the allowed port and refuses every TCP bind. "
            "Every process the lane starts inherits both, the processes the engine detaches are ended before the lane's result is written, the lane's log reaches the runner over a descriptor the engine cannot "
            "reach, and the lane does not start if the layers cannot be installed. What this does not stop: against a hostile library the allow-list is enforced at the level of the PORT, because a second "
            "thread (or process sharing memory) that changes the address of a connect() between the check and the call can reach another address on the allowed port (the audit log then shows the "
            "allowed address); files, pipes and processes reachable without a socket are not confined; a TCP simultaneous open is not excluded; a caller with CAP_SYS_PTRACE or a kernel bug defeats it; a process that signals the lane child can stop or kill the supervisor, which ends in no connection at all, not in an open network; "
            "the library allowlist is a guard, not a sandbox. Each such lane's egress-log.jsonl lists the layers that were installed and every refusal (an allowed connect is recorded up to a cap); a refused "
            "attempt ends the lane as an engine error (egress-denied), never a pass.")


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
EXIT_CORROBORATED = 8      # `run` and `verify`: an external-target run whose every assertion is verified, capped at CORROBORATED (no independent restatement backs it; never read this as VERIFIED)
EXIT_INTERNAL = 6          # a crash of the runner itself (never reported as a product failure)

#: what the in-process harness executor may be asked to do on behalf of a plan (anything else is denied by the action policy)
ALLOWED_ACTION_KINDS = ("navigate", "click", "fill", "check", "uncheck", "select", "press")

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")       # leaves room for ".<lane id>" inside the 64 character id pattern
LANE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,19}$")
ASSERTION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

#: bounds on what a child process may send back
MAX_CHILD_JSON_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_EVIDENCE_BYTES = 128 * 1024 * 1024      # what a run keeps of its lanes' output in total (half the cap of a bundle); REDEVOPS_QA_MAX_EVIDENCE_BYTES or RunOptions.max_evidence_bytes overrides it
MAX_LOG_TAIL_BYTES = 64 * 1024
DEFAULT_LANE_DEADLINE_S = 120.0


#: what a run against an external target says about itself, in these words and no others (verify requires exactly this text from the plan)
NO_RESTATEMENT_ID = "no-independent-restatement"


def no_restatement_text(origin: str) -> str:
    return ("This run's target is an external origin (" + origin + "). Nothing in this bundle restates, independently of the engines, what its assertions expect: the target's own request log and a reference check "
            "exist only for the bundled fixture app. The assertions are corroborated by the browser engine's own record, the harness run record and the egress gateway's decisions, so the run level is capped at "
            "CORROBORATED and is never VERIFIED. The platform claim is Linux x86_64 with CPython 3.12 (3.11 for the fixture-app CI); no other host is claimed.")
