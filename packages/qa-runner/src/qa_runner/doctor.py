# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``redevops-qa doctor``: what this machine can and cannot do for a run, with the remedy for everything it cannot.

It checks and reports; it never installs, downloads or changes anything. Each check is ``OK``, ``WARN`` (works, but outside what this release
claims) or ``FAIL`` (a run would not work or would not be what it says). A requested protection that cannot be provided is a ``FAIL``, never a
silent fallback: the egress gateway that every browser lane depends on must start, and the pinned dependencies must be exactly the pinned ones.
"""
from __future__ import annotations

import importlib
import importlib.metadata
import json
import platform
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import constants as K
from .deps import verified_bootstrap
from .errors import EnvironmentFault
from .procs import FixtureApp, child_env

PLAYWRIGHT_PIN = "1.64.1"
ROBOT_PIN = "7.5"
MIN_PYTHON = (3, 11)
SUPPORTED_PLATFORM = ("linux", "x86_64")


@dataclass(frozen=True)
class Check:
    name: str
    status: str                 # OK | WARN | FAIL
    detail: str
    remedy: str = ""

    def to_json(self) -> Dict[str, str]:
        return {"check": self.name, "status": self.status, "detail": self.detail, "remedy": self.remedy}


def check_python(version: Tuple[int, int] = tuple(sys.version_info[:2])) -> Check:
    if version < MIN_PYTHON:
        return Check("python", "FAIL", f"Python {version[0]}.{version[1]} is older than {MIN_PYTHON[0]}.{MIN_PYTHON[1]}",
                     f"run redevops-qa with Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer")
    return Check("python", "OK", f"Python {version[0]}.{version[1]}")


def check_platform(system: Optional[str] = None, machine: Optional[str] = None) -> Check:
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower().replace("amd64", "x86_64")
    if (system, machine) == SUPPORTED_PLATFORM:
        return Check("platform", "OK", "linux x86_64 (the platform this release's evidence is for)")
    return Check("platform", "WARN", f"{system} {machine}: this release claims Linux x86_64 only; a run here is development evidence, not release evidence",
                 "use a Linux x86_64 host for evidence you intend to rely on")


def check_pins() -> Check:
    try:
        up = verified_bootstrap()
    except EnvironmentFault as exc:
        return Check("pinned dependencies", "FAIL", f"{exc.code}: {exc.message[:300]}",
                     "fetch runtime-contracts v0.3.16 (or v0.3.15) and agent-harness v0.2.0 at the commits in pins.toml into the paths it names (or set "
                     "QA_PIN_CONTRACTS_PATH and QA_PIN_HARNESS_QA_PATH); nothing is installed from an index")
    p = up.pins
    return Check("pinned dependencies", "OK", f"runtime-contracts {p.contracts.version} ({p.contracts.commit[:12]}), agent-harness {p.harness_qa.version} "
                 f"({p.harness_qa.commit[:12]}), pin set {p.pin_set}: tree digests and vector files match pins.toml" + ("; the git commits match too" if all(
                     (d.resolved_path / ".git").exists() for d in (p.contracts, p.harness_qa)) else "; a tree that is not a git checkout is not checked against its commit"))


def _version(dist: str) -> Optional[str]:
    try:
        return importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return None


_CHROMIUM_PROBE = ("from playwright.sync_api import sync_playwright\n"
                   "with sync_playwright() as p:\n"
                   "    b = p.chromium.launch()\n"
                   "    print('chromium ' + b.version)\n"
                   "    b.close()\n")


def check_playwright(run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> Check:
    have = _version("playwright")
    if have is None:
        return Check("playwright", "FAIL", "the playwright package is not installed",
                     f"pip install playwright=={PLAYWRIGHT_PIN} in this environment (doctor never installs anything)")
    if have != PLAYWRIGHT_PIN:
        return Check("playwright", "FAIL", f"playwright {have} is installed; this release is tested with {PLAYWRIGHT_PIN}", f"pip install playwright=={PLAYWRIGHT_PIN}")
    with tempfile.TemporaryDirectory(prefix="redevops-qa-doctor-") as home:
        try:
            done = run([sys.executable, "-s", "-c", _CHROMIUM_PROBE], env=child_env(home, modules=()), cwd=home, capture_output=True, text=True, timeout=90)
        except (OSError, subprocess.SubprocessError) as exc:
            return Check("chromium", "FAIL", f"could not run the browser probe ({type(exc).__name__})", "check that the interpreter can start subprocesses")
    if done.returncode != 0 or not done.stdout.startswith("chromium "):
        return Check("chromium", "FAIL", f"playwright {have} is installed but Chromium could not be launched",
                     "install the browser build that goes with this Playwright: PLAYWRIGHT_BROWSERS_PATH=<dir> python -m playwright install chromium "
                     "(on Linux add --with-deps once as root), and give redevops-qa the same PLAYWRIGHT_BROWSERS_PATH")
    return Check("chromium", "OK", f"playwright {have}, {done.stdout.strip()} launches headless")


def check_robot() -> Check:
    have = _version("robotframework")
    if have is None:
        return Check("robot framework", "FAIL", "robotframework is not installed", f"pip install robotframework=={ROBOT_PIN} in this environment")
    if have != ROBOT_PIN:
        return Check("robot framework", "FAIL", f"robotframework {have} is installed; this release is tested with {ROBOT_PIN}", f"pip install robotframework=={ROBOT_PIN}")
    return Check("robot framework", "OK", f"robotframework {have}")


def check_fixture_app() -> Check:
    with tempfile.TemporaryDirectory(prefix="redevops-qa-doctor-") as home:
        app = FixtureApp("none", home + "/requests.jsonl", home=home)
        try:
            origin = app.start(timeout_s=20)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(origin + "/health", timeout=5) as resp:
                ok = resp.status == 200 and json.loads(resp.read(4096).decode("utf-8")).get("status") == "ok"
        except EnvironmentFault as exc:
            return Check("fixture app", "FAIL", f"{exc.code}", "check that qa-fixture-app is importable and that loopback sockets can be opened")
        except Exception as exc:
            return Check("fixture app", "FAIL", f"the fixture app started but /health did not answer ({type(exc).__name__})", "check that loopback connections are not blocked")
        finally:
            app.stop()
    return Check("fixture app", "OK" if ok else "FAIL", "starts on loopback and answers /health" if ok else "answered /health with something other than ok",
                 "" if ok else "reinstall qa-fixture-app from this checkout")


def check_egress_gateway() -> Check:
    """Fails closed: the gateway must start AND the browser launch configuration must be available and complete. Nothing is sent here; whether Chromium obeys the configuration is shown by the
    egress tests against a hostile page, not by this check."""
    from .egress import launch_config_problems
    try:
        from qa_egress import GatewayServer, build_launch_config
        from qa_egress.resolver import SystemResolver
        up = verified_bootstrap()
        policy = up.harness.egress.EgressPolicy.from_config({"private": [{"host": "127.0.0.1", "networks": ["127.0.0.1/32"], "schemes": ["http"], "ports": [1],
                                                                        "label": "doctor"}]})
        with GatewayServer(policy, SystemResolver()) as gw:
            try:
                fields = build_launch_config("127.0.0.1", gw.port).profile_fields()
            except Exception as exc:
                return Check("egress gateway", "FAIL", f"the gateway started but the browser launch configuration is unavailable ({type(exc).__name__}); a browser lane would have no "
                             "protected way out and the run refuses to continue without it", "check that qa-egress is importable and unmodified; reinstall it from this checkout")
            problems = launch_config_problems(fields, gw.port)
    except Exception as exc:
        return Check("egress gateway", "FAIL", f"the egress gateway could not start ({type(exc).__name__}); a browser lane would have no protected way out and "
                     "the run refuses to continue without it", "check that qa-egress is importable, the pins verify and a loopback port can be bound")
    if problems:
        return Check("egress gateway", "FAIL", "the browser launch configuration does not make the gateway the only way out (" + "; ".join(problems) + "); the run refuses to continue without it",
                     "reinstall qa-egress from this checkout")
    return Check("egress gateway", "OK", "binds on loopback and builds the launch configuration whose flags force browser traffic through it (loopback is not bypassed); no traffic was sent "
                 "here: enforcement is shown by the browser tests, not by this check. Egress is not enforced for a Robot lane")


def check_workdir() -> Check:
    try:
        with tempfile.TemporaryDirectory(prefix="redevops-qa-doctor-") as d:
            open(d + "/probe", "xb").close()
    except OSError as exc:
        return Check("temporary directory", "FAIL", f"cannot write to the temporary directory ({type(exc).__name__})", "set TMPDIR to a writable directory")
    return Check("temporary directory", "OK", "writable")


def run_doctor(engines: Sequence[str] = (K.ENGINE_PLAYWRIGHT,), *, include: Optional[Sequence[Callable[[], Check]]] = None) -> List[Check]:
    checks: List[Callable[[], Check]] = [check_python, check_platform, check_workdir, check_pins]
    if K.ENGINE_PLAYWRIGHT in engines:
        checks.append(check_playwright)
    if K.ENGINE_ROBOT in engines:
        checks.append(check_robot)
    checks += [check_fixture_app, check_egress_gateway]
    return [c() for c in (include if include is not None else checks)]


def render(checks: Sequence[Check]) -> str:
    lines = []
    for c in checks:
        lines.append(f"[{c.status:^4}] {c.name}: {c.detail}")
        if c.remedy and c.status != "OK":
            lines.append(f"       to fix: {c.remedy}")
    failed = [c for c in checks if c.status == "FAIL"]
    lines.append("doctor: " + ("all required checks passed" if not failed else f"{len(failed)} check(s) failed; a run would not be what it says. Nothing was installed."))
    return "\n".join(lines) + "\n"
