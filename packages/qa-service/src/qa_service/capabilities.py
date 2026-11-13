# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""What this installation can run, measured once at start and reported as data: a plan is either available or ``unavailable`` with a machine-readable code, a reason and a remedy.

The rules, in the order they are applied (the first that fails is the answer):

1. ``ARCHITECTURE_UNSUPPORTED``: the lanes are supported on linux/x86_64 only (README, ``redevops-qa doctor``); on any other platform no plan that runs a lane is offered, whatever is installed.
2. ``LANE_ENGINE_MISSING``: a Python package a plan's lane needs (``playwright`` for the browser lane, ``robot`` for the Robot lane) is not installed (the arm64 image carries the evidence commands only).
3. ``BROWSER_UNAVAILABLE``: the pinned Chromium of a bundle installation is missing or is not the pinned build (``doctor``'s "browser build" check failed).
4. ``ROBOT_EGRESS_LAYERS_UNAVAILABLE``: the kernel layers that limit a Robot lane's egress (Landlock network rules and seccomp user notification) were measured not to work here; applies to the plans whose
   Robot lane asks for them (``demo``, ``robot``), never to ``robot-not-enforced`` or ``browser``.
5. ``PLAN_FILE_MISSING``: the plan file of the image is not where the service was told it is.

The measurement is the runner's own (``qa_runner.netfence.probe`` and ``qa_runner.doctor.check_browser_pin``), run in a throwaway interpreter so that nothing of the runner is loaded into this process."""
from __future__ import annotations

import importlib.util
import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

PROBE_TIMEOUT_S = 60

#: plan -> (command, plan file, packages its lanes need, needs the Robot egress layers)
PLANS: Dict[str, Tuple[str, Optional[str], Tuple[str, ...], bool, bool]] = {
    # name: (command, plan file, packages, needs browser, needs robot layers)
    "demo": ("demo", None, ("playwright", "robot"), True, True),
    "browser": ("run", "golden-plan.json", ("playwright",), True, False),
    "robot": ("run", "robot-plan.json", ("robot",), False, True),
    "robot-not-enforced": ("run", "robot-plan-not-enforced.json", ("robot",), False, False),
}

REMEDIES = {
    "ARCHITECTURE_UNSUPPORTED": "run the linux/amd64 image on a linux/x86_64 host; this image can still verify, report on and inspect evidence made elsewhere",
    "LANE_ENGINE_MISSING": "use the linux/amd64 image, which carries Playwright with the pinned Chromium and Robot Framework",
    "BROWSER_UNAVAILABLE": "reinstall the image; the browser must be the pinned build (`redevops-qa doctor` names the difference)",
    "ROBOT_EGRESS_LAYERS_UNAVAILABLE": "use a native linux/x86_64 host with Linux 6.7 or later and Landlock enabled, with Docker's default seccomp profile; or use the browser plan, or robot-not-enforced "
                                       "(no limit on that lane's traffic, and its report says so)",
    "PLAN_FILE_MISSING": "set QA_SERVICE_PLANS_DIR to the directory that holds the shipped plan files",
}


@dataclass
class Facts:
    system: str = "linux"
    machine: str = "x86_64"
    missing_packages: Tuple[str, ...] = ()
    browser: Dict[str, str] = field(default_factory=lambda: {"status": "OK", "message": ""})
    robot_layers: Dict[str, Any] = field(default_factory=lambda: {"ok": True})

    def as_dict(self) -> Dict[str, Any]:
        return {"system": self.system, "machine": self.machine, "missing_packages": list(self.missing_packages), "browser": dict(self.browser),
                "robot_layers": {k: v for k, v in self.robot_layers.items() if k in ("ok", "reason", "message")}}


def _have(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


PROBE_CODE = r"""
import json
out = {}
try:
    from qa_runner import doctor, netfence
    c = doctor.check_browser_pin()
    out["browser"] = {"status": c.status, "message": c.detail[:300]}
    r = netfence.probe()
    out["robot_layers"] = {"ok": r.get("ok") is True, "reason": str(r.get("reason", ""))[:80], "message": str(r.get("message", ""))[:300]}
except Exception as exc:
    out["error"] = type(exc).__name__
print(json.dumps(out))
"""


def run_probe() -> Dict[str, Any]:
    """The runner's own measurements, in a throwaway interpreter; ``{}`` when the runner is not installed or the measurement does not finish."""
    if not _have("qa_runner"):
        return {}
    try:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("TMPDIR", "/tmp"), "LANG": "C.UTF-8"}          # nothing of the service's environment (the token is in it) goes along
        for key in ("PLAYWRIGHT_BROWSERS_PATH", "REDEVOPS_QA_PINS", "TMPDIR"):
            if key in os.environ:
                env[key] = os.environ[key]
        done = subprocess.run([sys.executable, "-I", "-c", PROBE_CODE], capture_output=True, text=True, timeout=PROBE_TIMEOUT_S, stdin=subprocess.DEVNULL, env=env, check=False)
        return json.loads(done.stdout.strip().splitlines()[-1]) if done.stdout.strip() else {}
    except (subprocess.TimeoutExpired, ValueError, OSError):
        return {}


def collect(probe: Callable[[], Dict[str, Any]] = run_probe) -> Facts:
    facts = Facts(system=platform.system().lower(), machine=platform.machine().lower().replace("amd64", "x86_64"))
    facts.missing_packages = tuple(sorted({p for _, (_, _, pk, _, _) in PLANS.items() for p in pk if not _have(p)}))
    measurable = (facts.system, facts.machine) == ("linux", "x86_64") and not facts.missing_packages
    measured = probe() if measurable else {}
    if measured.get("browser"):
        facts.browser = measured["browser"]
    facts.robot_layers = measured.get("robot_layers") or {"ok": False, "reason": "not-measured",
                                                          "message": "the runner's measurement did not complete" if measurable else "not measured on this installation"}
    return facts


def unavailable(plan: str, facts: Facts, plans_dir: Optional[Any]) -> Optional[Dict[str, str]]:
    """``None`` when the plan can start here, else ``{"code", "reason", "remedy"}``."""
    command, plan_file, packages, needs_browser, needs_layers = PLANS[plan]

    def no(code: str, reason: str) -> Dict[str, str]:
        return {"code": code, "reason": reason, "remedy": REMEDIES[code]}

    if (facts.system, facts.machine) != ("linux", "x86_64"):
        return no("ARCHITECTURE_UNSUPPORTED", f"this host is {facts.system} {facts.machine}; the lanes are supported on linux x86_64 only")
    missing = [p for p in packages if p in facts.missing_packages]
    if missing:
        return no("LANE_ENGINE_MISSING", "the Python package(s) " + ", ".join(missing) + " of this plan's lanes are not installed in this image")
    if needs_browser and facts.browser.get("status") == "FAIL":
        return no("BROWSER_UNAVAILABLE", "the browser is not the pinned build: " + str(facts.browser.get("message", ""))[:200])
    if needs_layers and not facts.robot_layers.get("ok"):
        return no("ROBOT_EGRESS_LAYERS_UNAVAILABLE", "the kernel layers that limit a Robot lane's egress cannot be provided here (" + str(facts.robot_layers.get("reason", "unknown"))[:60]
                  + ": " + str(facts.robot_layers.get("message", ""))[:200] + ")")
    if plan_file is not None and (plans_dir is None or not (plans_dir / plan_file).is_file()):
        return no("PLAN_FILE_MISSING", "the plan file " + plan_file + " is not installed")
    return None
