# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``redevops-qa doctor``: what this machine can and cannot do for a run, with the remedy for everything it cannot.

It checks and reports; it never installs, downloads or changes anything. Each check is ``OK``, ``WARN`` (works, but outside what this release
claims) or ``FAIL`` (a run would not work or would not be what it says). A requested protection that cannot be provided is a ``FAIL``, never a
silent fallback: the egress gateway that every browser lane depends on must start, and the pinned dependencies must be exactly the pinned ones.
"""
from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import browser_pin
from . import constants as K
from .deps import verified_bootstrap
from .errors import EnvironmentFault
from .procs import CHILD_MODULES, FixtureApp, child_env

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


PINNED_FILES = "pinned-files.json"           # beside pins.toml in a bundle install: the sha256 of every file of the pinned trees as shipped
_SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache"}
_SKIP_SUFFIXES = {".pyc", ".pyo"}


def _share(prefix: Optional[str]) -> Path:
    return Path(prefix or sys.prefix) / "share" / "redevops-qa"


def effective_lane_paths() -> List[Tuple[str, str, bool]]:
    """The paths a run will put on the command line of its Robot lane, derived from the same things the run derives them from: the interpreter that starts the lane child, the Robot guard
    script (``lane_robot.GUARD``), and the working directory ``make_workdir`` creates under the temporary directory (``tempfile.gettempdir()``, which honours ``TMPDIR``), below which the
    Robot lane's workspace and output directory lie (``lane_robot``: ``workdir/lanes/<lane>/workspace/suite`` and ``.../output``). The evidence directory and ``HOME`` are not on any command
    line (the lane children get a ``HOME`` of their own under that working directory), so they are not listed; a path that the code starts to hand to a lane belongs here.
    Each entry is ``(what, path, resolved)``. The interpreter and the guard script are tested as the command line gives them (``sys.executable`` as it is, and ``GUARD``, which the lane module
    has already made a real path): the adapter kit does not follow a link there, and a venv's ``bin/python`` is a link to the interpreter it was made from, which may live under ``/root`` while
    the installation does not. The working directory and the paths below it are tested as given and by their real path as well (a ``TMPDIR`` that is a link into a refused place)."""
    try:
        from .lane_robot import GUARD
    except ImportError:                          # the Robot packages are not installed: doctor says so in its own check
        GUARD = str(Path(__file__).resolve().with_name("robot_guard.py"))
    workdir = Path(tempfile.gettempdir()) / "redevops-qa-<random>"
    lane = workdir / "lanes" / "robot"
    return [("the interpreter", sys.executable, False), ("the Robot guard script", GUARD, False), ("the temporary working directory of a run (from TMPDIR)", str(workdir), True),
            ("the Robot lane's workspace", str(lane / "workspace" / "suite"), True), ("the Robot lane's output directory", str(lane / "output"), True)]


def path_rule(path: str) -> str:
    """The rule of ``qa_adapter_kit.paths`` that refuses ``path`` ('' when none does), read from the kit's own constants."""
    from qa_adapter_kit.paths import DENIED_COMPONENTS, DENIED_NAMES, DENIED_PREFIXES
    norm = os.path.normpath(path)
    for prefix in DENIED_PREFIXES:
        if norm == prefix or norm.startswith(prefix + "/"):
            return f"the prefix {prefix} is on the refused list"
    parts = [x for x in norm.split("/") if x]
    for part in parts:
        if part in DENIED_COMPONENTS:
            return f"a path component named {part} is on the refused list"
    last = parts[-1] if parts else ""
    for name in DENIED_NAMES:
        if last == name or last.startswith(name + "."):
            return f"a file named {name} is on the refused list"
    return ""


def check_path_policy(paths: Optional[Sequence[Tuple]] = None, is_denied: Optional[Callable[[str], bool]] = None, *, robot: bool = True) -> Check:
    """The adapter kit refuses a command whose arguments name a prohibited path (``/root``, ``/etc``, a ``.config`` component, ...). A run whose Robot lane command line would name one ends
    INCONCLUSIVE (``PROHIBITED_PATH``) when the Robot lane starts; this names the path and the rule before ``demo`` runs, and ``run`` and ``demo`` make the same check themselves before
    they start anything. The rule is the adapter kit's own (``qa_adapter_kit.paths.is_denied``); it is not relaxed or special-cased here. Only the Robot lane has such a command line: with
    ``robot=False`` (a plan without a Robot lane, ``doctor --engines`` without it) nothing is checked, and the detail says so.
    ``paths`` are ``(what, path)`` (tested as given) or ``(what, path, resolved)`` (also by the real path when ``resolved``)."""
    from qa_adapter_kit.paths import DENIED_COMPONENTS as kit_components, DENIED_PREFIXES as kit_prefixes
    if not robot:
        return Check("adapter path policy", "OK", "not checked: no Robot lane in this run, and only the Robot lane's command line carries the interpreter, the guard script and the working directory")
    if is_denied is None:
        from qa_adapter_kit.paths import is_denied as kit_is_denied
        is_denied = kit_is_denied
    if paths is None:
        paths = effective_lane_paths()
    bad = []
    for item in paths:
        what, path = item[0], item[1]
        resolved = bool(item[2]) if len(item) > 2 else False
        given = os.path.normpath(path)
        if is_denied(given):
            bad.append(f"{what} is {given} ({path_rule(given) or 'refused'})")
        elif resolved and is_denied(os.path.realpath(path)):
            real = os.path.realpath(path)
            bad.append(f"{what} is {given}, whose real path {real} is refused ({path_rule(real) or 'refused'})")
    if bad:
        return Check("adapter path policy", "FAIL", "; ".join(bad) + ": the adapter path policy refuses these paths, so the Robot lane of a run would end INCONCLUSIVE (PROHIBITED_PATH)",
                     "install into a directory the policy accepts (as root, not under /root: for example /opt/redevops-qa) and set TMPDIR to such a directory; the interpreter and the guard script "
                     "are tested by the path the installation gives them (a link from the virtual environment to a Python kept elsewhere is not followed), the working directory of a run "
                     "also by its real path; the refused places are " + ", ".join(kit_prefixes) + " and any path with a component such as " + ", ".join(sorted(kit_components)[:4])
                     + " (the list of qa_adapter_kit.paths, which is not relaxed)")
    return Check("adapter path policy", "OK", "the interpreter, the Robot guard script and the working directory of a run (TMPDIR) are paths the adapter path policy accepts; HOME and the evidence directory are not on a lane command line")


def check_first_party_modules(prefix: Optional[str] = None, locate: Callable = importlib.util.find_spec) -> Check:
    """In a bundle install every first-party package must be imported from the installation itself. A stale checkout on PYTHONPATH (or anything else that comes first on the
    import path) that shadows an installed package is a failure here, not a silent replacement. Outside a bundle install (a checkout, a development environment) there is
    nothing to compare with and the check says so."""
    root = Path(prefix or sys.prefix)
    if not (_share(prefix) / "pins.toml").is_file():
        return Check("installed packages", "OK", "not a bundle install (no share/redevops-qa/pins.toml under this Python's prefix): the packages are imported from their source directories")
    stray = []
    for name in CHILD_MODULES:
        spec = locate(name)
        where = [str(Path(p).resolve()) for p in (spec.submodule_search_locations or [])] if spec is not None else []
        if not where or not all(w == str(root.resolve()) or w.startswith(str(root.resolve()) + os.sep) for w in where):
            stray.append(f"{name} ({where[0] if where else 'not found'})")
    if stray:
        return Check("installed packages", "FAIL", "first-party packages are imported from outside the installation: " + ", ".join(stray[:5]),
                     "unset PYTHONPATH (the bin/redevops-qa launcher does: it runs python -E -s) and run the launcher of the installation; remove a stray copy that shadows an installed package")
    return Check("installed packages", "OK", f"all {len(CHILD_MODULES)} first-party packages are imported from {root}")


def check_pinned_files(prefix: Optional[str] = None) -> Check:
    """In a bundle install, every file of the pinned trees (LICENSE and pyproject.toml included, not only the distribution directories and the vector files the pin digest covers) is
    the one the bundle shipped, and no file was added. Not covered: bytecode (__pycache__, *.pyc: skipped, as in the pin digest), anything outside the pinned trees (the first-party
    wheels were checked by pip against requirements.lock when they were installed, and are not re-checked here), and a change made together with pinned-files.json itself."""
    share = _share(prefix)
    manifest = share / PINNED_FILES
    if not manifest.is_file():
        return Check("pinned files", "OK", "not a bundle install (no pinned-files.json beside pins.toml): the pin check above covers the pinned trees")
    try:
        listed = json.loads(manifest.read_text(encoding="utf-8"))["files"]
    except (OSError, ValueError, KeyError):
        return Check("pinned files", "FAIL", "pinned-files.json cannot be read", "reinstall the bundle into a new directory")
    base = share / ".pinned"
    actual = {}
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix not in _SKIP_SUFFIXES:
                actual[".pinned/" + p.relative_to(base).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    changed = sorted(k for k in set(listed) & set(actual) if listed[k] != actual[k])
    added, missing = sorted(set(actual) - set(listed)), sorted(set(listed) - set(actual))
    if changed or added or missing:
        parts = [f"changed {changed[:3]}" if changed else "", f"added {added[:3]}" if added else "", f"missing {missing[:3]}" if missing else ""]
        return Check("pinned files", "FAIL", "the pinned trees differ from what the bundle shipped: " + "; ".join(p for p in parts if p), "reinstall the bundle into a new directory")
    return Check("pinned files", "OK", f"{len(actual)} files of the pinned trees are the ones the bundle shipped (LICENSE and pyproject.toml included); bytecode and files outside the pinned trees are not covered")


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


def browsers_directory(env: Optional[Dict[str, str]] = None) -> Path:
    """The directory Playwright will look for its browsers in: ``PLAYWRIGHT_BROWSERS_PATH`` if set (the launcher of a bundle install sets it to ``<prefix>/browsers``), else
    ``$XDG_CACHE_HOME/ms-playwright`` or ``~/.cache/ms-playwright`` on Linux. ``0`` (browsers inside the package) is returned as the package's ``.local-browsers`` directory."""
    env = os.environ if env is None else env
    given = env.get("PLAYWRIGHT_BROWSERS_PATH")
    if given == "0":
        spec = importlib.util.find_spec("playwright")
        return Path(spec.origin).parent / "driver" / "package" / ".local-browsers" if spec and spec.origin else Path(".local-browsers")
    if given:
        return Path(given)
    return Path(env.get("XDG_CACHE_HOME") or (Path(env.get("HOME") or Path.home()) / ".cache")) / "ms-playwright"


def _playwright_registry() -> Optional[Path]:
    spec = importlib.util.find_spec("playwright")
    if spec is None or not spec.origin:
        return None
    return Path(spec.origin).parent / "driver" / "package" / "browsers.json"


def check_browser_pin(prefix: Optional[str] = None, browsers: Optional[Path] = None, registry: Optional[Path] = None, playwright_version: Optional[str] = None) -> Check:
    """In a bundle install, the browser Playwright will launch is exactly the one ``browser.lock.json`` pins: the revision the installed Playwright expects is the pinned one, and every
    directory and file of the three Chromium install directories has the pinned mode, size and sha256, with nothing added and nothing missing. A missing browser says so ('not installed':
    the browser step was not run); a tree that differs is a FAIL and the browser is not launched. Not covered: the operating system libraries Chromium loads (apt, ``--with-deps``),
    anything outside the install directories, and any change made after this check. Outside a bundle install there is no lock to compare with and the check says it did not run."""
    lock_path = _share(prefix) / browser_pin.LOCK_NAME
    install_json = Path(prefix or sys.prefix).parent / "INSTALL.json"           # written by install.sh beside the virtual environment: this is a bundle installation
    bundle_install = os.path.lexists(install_json)
    if not lock_path.is_file():
        if bundle_install:
            return Check("browser build", "FAIL", f"this is a bundle installation ({install_json.parent}) but {lock_path} is missing or is not a file: the browser cannot be checked against its pin, "
                         "and a browser that is not checked is not started", "reinstall the bundle into a new directory")
        return Check("browser build", "WARN", f"not checked: no share/redevops-qa/{browser_pin.LOCK_NAME} under this Python's prefix, so this is not a bundle install (a source checkout or a development "
                     "environment). The browser pin applies to bundle installs only: the Chromium that a run here launches is not compared with anything")
    try:
        lock = browser_pin.load_lock(lock_path)
    except browser_pin.LockError as exc:
        return Check("browser build", "FAIL", f"{browser_pin.LOCK_NAME} cannot be used: {exc}", "reinstall the bundle into a new directory")
    if bundle_install:
        try:
            recorded = json.loads(install_json.read_text(encoding="utf-8")).get("browser_lock_sha256")
        except (OSError, ValueError, AttributeError):
            recorded = None
        if recorded is not None and recorded != lock.digest:
            return Check("browser build", "FAIL", f"{lock_path} is not the browser pin install.sh recorded in INSTALL.json (sha256 {lock.digest}, recorded {recorded}): the pin was changed after the install",
                         "reinstall the bundle into a new directory")
    have = playwright_version if playwright_version is not None else _version("playwright")
    if have != lock.playwright_version:
        return Check("browser build", "FAIL", f"the browser pin is for playwright {lock.playwright_version}; this environment has {have or 'no playwright'}", "reinstall the bundle into a new directory")
    reg = registry if registry is not None else _playwright_registry()
    try:
        reg_digest = hashlib.sha256(reg.read_bytes()).hexdigest() if reg is not None else None
    except OSError:
        reg_digest = None
    if reg_digest != lock.browsers_json_sha256:
        return Check("browser build", "FAIL", f"the browser revision the installed Playwright expects (its browsers.json, sha256 {reg_digest or 'unreadable'}) is not the pinned one "
                     f"(revision {lock.revision}, sha256 {lock.browsers_json_sha256})", "reinstall the bundle into a new directory")
    if browsers is None and bundle_install and not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        return Check("browser build", "FAIL", "PLAYWRIGHT_BROWSERS_PATH is not set: the lane children of a run get a temporary HOME and would look for the browser there, not in the directory this check "
                     "would read, so no browser could be launched from the one that is checked", f"run through the launcher {install_json.parent}/bin/redevops-qa, which sets PLAYWRIGHT_BROWSERS_PATH to "
                     f"{install_json.parent}/browsers")
    where = browsers if browsers is not None else browsers_directory()
    problems = browser_pin.verify_tree(where, lock)
    absent = [p for p in problems if p.code == "NOT_INSTALLED"]
    if len(absent) == len(lock.archives):
        return Check("browser build", "FAIL", f"not installed: none of {', '.join(lock.dirs())} is in {where} (the browser step has not been run, or Playwright looks somewhere else: "
                     "the launcher bin/redevops-qa sets PLAYWRIGHT_BROWSERS_PATH to <installation>/browsers)",
                     "run the browser step from the bundle directory: ./install-browser.sh --prefix <the installation directory> (add --with-deps once per machine)")
    if problems:
        return Check("browser build", "FAIL", f"the browser in {where} is not the pinned build: " + browser_pin.summarise(problems, 4),
                     f"do not use this browser: remove {where}/{{{','.join(lock.dirs())}}} and run ./install-browser.sh --prefix <the installation directory> again (it downloads the pinned archives "
                     "and checks them before unpacking); the browser lane is not started against this tree")
    return Check("browser build", "OK", f"Chromium {lock.browser_version} (Playwright revision {lock.revision}) in {where}: {len(lock.files)} files in {len(lock.archives)} install directories have the pinned "
                 f"mode, size and sha256 and nothing else is there (pin {lock.digest[:12]}). Not covered: the operating system libraries it loads, anything outside those directories, and changes after this check")


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
    checks: List[Callable[[], Check]] = [check_python, check_platform, check_workdir, lambda: check_path_policy(robot=K.ENGINE_ROBOT in engines), check_first_party_modules, check_pins, check_pinned_files]
    if K.ENGINE_PLAYWRIGHT in engines:
        # The browser is checked against the pin first and is only launched if that check did not fail: launching a tree that differs from the pin would run the changed files.
        verdict: Dict[str, Check] = {}

        def browser_build() -> Check:
            verdict["pin"] = check_browser_pin()
            return verdict["pin"]

        def launch() -> Check:
            if verdict["pin"].status == "FAIL":
                return Check("chromium", "FAIL", "not launched: the browser build check above failed, and a browser that is not the pinned one is not started", verdict["pin"].remedy)
            return check_playwright()
        checks += [browser_build, launch]
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
