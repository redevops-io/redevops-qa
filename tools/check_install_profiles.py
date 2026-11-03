#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Check qa-install-profiles.json: schema, steps, pins, status, evidence, freshness and the generated document.

Offline (no network, no secret) except the explicit ``--verify-ci`` and ``--cross-check`` modes. What it enforces:

* the file validates against ``schemas/qa-install-profiles.schema.json``;
* every command is an argument vector of a closed shape: the only executables are ``git``, the profile's Python and the virtual environment's Python,
  every package is an exact pin the profile lists or a package directory of this repository, no shell, no download tool, no invented registry package;
* the pins agree with the capability manifest, the package metadata and the CI tooling pins; the dependency release tags agree with ``pins.toml``;
* the evidence files named by the smoke steps are the ones the profile declares, each has a check step, and manual steps are never counted;
* a profile or host is ``verified`` only if a named CI job in ``tests.yml`` runs that exact profile (``tools/run_install_profile.py --profile <id>``) on
  the matching runner, with the stable channel, no skip, no condition, and a recorded run; ``verified`` needs engines that are backed by a real engine
  in the capability manifest; a planned target must not have its files in the repository;
* the pinned source commit and the head commit of every recorded run are ancestors of main (a recorded run's head may instead be an ancestor of the commit
  under test, but only when the pin in this file as committed at that head equals the record's ``source_commit`` and, with ``--verify-ci``, the cited job's log
  also confirmed the commit the run installed and the passed counts); the pin at every recorded head must equal ``source_commit`` (read with ``git show``: no
  log, no network, the clone needs the full history); a recorded run states the pin it installed from (``source_commit``, which must be the profile's pinned
  commit) separately from its own head commit;
* with ``--verify-ci`` (read-only API, a token for the log) every recorded run, its job and the job's log are re-checked: the run's head and whole-run
  conclusion, the job's success, name and day, the line ``checkout verified: HEAD is the pinned commit <sha>`` with ``<sha>`` equal to ``source_commit``, and the
  passed counts of the log equal to the counts in the summary, each suite also shown as ``OK N tests, 0 skipped, 0 failed``; a log that cannot be read fails,
  except that a log that is gone (HTTP 404 or 410) is tolerated for a run whose head is on main;
* ``docs/QA_INSTALL_PROFILES.md`` equals the document generated from the JSON.

Usage: ``python tools/check_install_profiles.py [--root DIR] [--main-ref REF] [--no-freshness] [--write-docs] [--verify-ci] [--cross-check]``.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check_capabilities as caps  # noqa: E402
import qa_install_config as gen  # noqa: E402
import qa_jsonschema  # noqa: E402

PROFILES = "qa-install-profiles.json"
SCHEMA = "schemas/qa-install-profiles.schema.json"
DOCS = "docs/QA_INSTALL_PROFILES.md"
GENERATED_NOTICE = "<!-- Generated from qa-install-profiles.json by tools/check_install_profiles.py --write-docs. Do not edit by hand. -->"
VENV_PY = "{venv_dir}/bin/python"
# The only code strings a step may pass to ``python -c``; both take their paths and module names as arguments, never by interpolation.
CODE_ASSERT = ("import importlib,os,sys; root=os.path.realpath(sys.argv[1]); "
               "bad=[m for m in sys.argv[2:] if not os.path.realpath(importlib.import_module(m).__file__).startswith(root+os.sep)]; "
               "sys.exit(('not imported from the virtual environment: '+', '.join(bad)) if bad else 0)")
CODE_REMOVE = ("import os,shutil,sys; p=sys.argv[1]; ok=os.path.isfile(os.path.join(p,'pyvenv.cfg')); "
               "ok or sys.exit('refusing to remove a directory that is not a virtual environment: '+p); shutil.rmtree(p)")
CLONE_URL = "https://github.com/redevops-io/redevops-qa.git"
# The one code string a bundle profile's first step may pass to ``python -I -c``: the archive must have the digest its .tar.sha256 file holds. Paths come in as arguments.
CODE_ARCHIVE_DIGEST = ("import hashlib,sys; a,b=sys.argv[1:3]; want=open(b,encoding='utf-8').read().split()[0]; got=hashlib.sha256(open(a,'rb').read()).hexdigest(); "
                       "sys.exit(0 if got==want else 'the archive does not have the digest in '+b)")
MARKERS = {"robot_real", "browser", "appium_android"}
ENV_NAMES = {"QA_CHROME_BINARY", "QA_CHROMEDRIVER_PATH", "QA_APPIUM_URL"}
LOOPBACK_URL = "http://127.0.0.1:4723"
JOB_MARK = "NOT a required check until proven"
RUNNERS = {"ubuntu-24.04": "linux-x86_64"}
REAL_ENGINE_LEVELS = {"engine-backed-ci", "device-backed-local", "device-backed-ci"}
PLANNED_TARGET_FILES = {
    "docker-compose": re.compile(r"^(docker-compose.*\.ya?ml|compose.*\.ya?ml|Dockerfile.*)$"),
    "kubernetes-helm": re.compile(r"^(Chart\.yaml|values\.ya?ml|kustomization\.ya?ml)$"),
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


# ------------------------------------------------------------------------------------------------ steps
def step_problems(profile: Dict[str, Any], phase: str, step: Dict[str, Any]) -> List[str]:
    """A step is one of a few exact shapes; anything else is a finding."""
    at = f"profile {profile['id']} {phase} step {step['id']}"
    argv, env = step["argv"], step.get("env", {})
    pins = [f"{p['name']}=={p['version']}" for p in profile["pip_pins"]]
    pkgs = ["{checkout_dir}/" + p for p in profile["packages"]]
    py = profile["python"]["executable"]
    out: List[str] = []
    declared = set(profile["params"]) | {"source_commit"}
    for token in [*argv, *env.values()]:
        for name in gen.PLACEHOLDER.findall(token):
            if name not in declared:
                out.append(f"{at}: placeholder {{{name}}} is not a parameter of the profile")
    if set(env) - ENV_NAMES:
        out.append(f"{at}: environment names {sorted(set(env) - ENV_NAMES)} are not allowed")
    for name, value in env.items():
        ok_placeholder = re.fullmatch(r"\{([a-z_]+)\}", value) and value[1:-1] in profile["params"] and profile["params"][value[1:-1]]["kind"] == "abs-path"
        if not (ok_placeholder or value == LOOPBACK_URL):
            out.append(f"{at}: environment value for {name} must be an absolute-path parameter or {LOOPBACK_URL}")
    if step.get("manual") and phase not in ("smoke", "check"):
        out.append(f"{at}: only smoke and check steps may be manual")
    ok = False
    if phase == "source":
        ok = argv in (["git", "clone", CLONE_URL, "{checkout_dir}"], ["git", "-C", "{checkout_dir}", "checkout", "--detach", "{source_commit}"])
    elif phase == "install":
        base = [VENV_PY, "-m", "pip", "install", "--disable-pip-version-check"]
        ok = (argv == [py, "-m", "venv", "{venv_dir}"] or argv == base + pins or (argv[:6] == base + ["--no-deps"] and sorted(argv[6:]) == sorted(pkgs) and bool(pkgs))
              or (argv[:5] == [VENV_PY, "-I", "-c", CODE_ASSERT, "{venv_dir}"] and len(argv) > 5 and all(re.fullmatch(r"[a-z_][a-z0-9_]*", m) for m in argv[5:])))
        if argv == base + pins and not pins:
            ok = False
    elif phase == "smoke":
        head = [VENV_PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-c", "{checkout_dir}/pyproject.toml", "-o", "pythonpath="]
        if argv[:len(head)] == head and len(argv) >= len(head) + 2:
            rest = argv[len(head):]
            m = re.fullmatch(r"--junitxml=\{evidence_dir\}/([A-Za-z0-9._-]+\.xml)", rest[0])
            tail = rest[1:]
            if tail[:1] == ["-m"] and len(tail) >= 2 and tail[1] in MARKERS:
                tail = tail[2:]
            ok = bool(m) and len(tail) == 1 and any(tail[0] == "{checkout_dir}/" + p + "/tests" or tail[0].startswith("{checkout_dir}/" + p + "/tests/") for p in profile["packages"]) \
                and ".." not in tail[0]
    elif phase == "check":
        ok = len(argv) == 3 and argv[:2] == [VENV_PY, "{checkout_dir}/tools/check_junit.py"] and bool(re.fullmatch(r"\{evidence_dir\}/[A-Za-z0-9._-]+\.xml", argv[2]))
    elif phase == "uninstall":
        ok = argv == [py, "-c", CODE_REMOVE, "{venv_dir}"]
    if not ok:
        out.append(f"{at}: the command is not one of the allowed shapes: {gen.display(argv)[:160]}")
    return out


def junit_of(step: Dict[str, Any]) -> Optional[str]:
    for a in step["argv"]:
        m = re.fullmatch(r"--junitxml=\{evidence_dir\}/(.+)", a)
        if m:
            return m.group(1)
    if step["argv"][1:2] == ["{checkout_dir}/tools/check_junit.py"] or (len(step["argv"]) == 3 and step["argv"][1].endswith("check_junit.py")):
        return step["argv"][2].split("/", 1)[1]
    return None


# ------------------------------------------------------------------------------------------------ bundle profiles
def bundle_name(root: Path) -> str:
    """The name of the archive the repository's builder writes (version of the runner, the one Python tag and platform of the bundle)."""
    sys.path.insert(0, str(HERE))
    try:
        import build_bundle as bb  # noqa: PLC0415
    finally:
        sys.path.pop(0)
    return f"redevops-qa-bundle-{bb.runner_version(root)}-{bb.TARGET['python_tag']}-{bb.TARGET['platform']}"


def expected_bundle_steps(name: str, python: str) -> Dict[str, List[List[str]]]:
    """Every step of a bundle profile, exactly. A bundle profile has no free-form commands: what a user is told to run is what CI runs, and it is this."""
    q = "{install_dir}/bin/redevops-qa"
    return {
        "source": [[python, "-I", "-c", CODE_ARCHIVE_DIGEST, "{bundle_dir}/" + name + ".tar", "{bundle_dir}/" + name + ".tar.sha256"], ["tar", "xf", "{bundle_dir}/" + name + ".tar"]],
        "install": [[name + "/install.sh", "--prefix", "{install_dir}", "--python", python], [name + "/install-browser.sh", "--prefix", "{install_dir}", "--with-deps"]],
        "smoke": [[q, "doctor"], [q, "demo", "--out", "{evidence_dir}", "--run-id", "profile-demo"]],
        "check": [[q, "verify", "{evidence_dir}/profile-demo"]],
        "uninstall": [[name + "/uninstall.sh", "--prefix", "{install_dir}"]],
    }


def keeps_evidence(step: Dict[str, Any]) -> bool:
    """The one condition a profile job may carry: an artifact upload that runs ``always()``, so the evidence of a failed run is kept.
    A profile step (anything that runs the profile) is never conditional, and an upload does not change whether the job fails.
    Exactly the text ``always()`` qualifies (no ``&&``, no ``${{ }}``, no other status function), and a step that runs anything or tolerates its own
    failure never does."""
    if step.get("continue-on-error") is not None or "run" in step or "shell" in step:
        return False
    return str(step.get("uses", "")).startswith("actions/upload-artifact@") and str(step.get("if", "")).strip() == "always()"


def bundle_problems(profile: Dict[str, Any], root: Path, workflow: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    at = f"profile {profile['id']}"
    sys.path.insert(0, str(HERE))
    try:
        import build_bundle as bb  # noqa: PLC0415
    finally:
        sys.path.pop(0)
    if profile["python"]["version"] != bb.TARGET["python"]:
        out.append(f"{at}: the bundle is for Python {bb.TARGET['python']}, the profile says {profile['python']['version']}")
    if sorted(profile["engines"]) != ["playwright", "robotframework"]:
        out.append(f"{at}: a bundle profile covers exactly the engines of the bundle (playwright, robotframework)")
    if profile.get("verifier") is not True:
        out.append(f"{at}: a bundle profile installs and runs the verifier (verifier: true)")
    if profile["pip_pins"] or profile["packages"]:
        out.append(f"{at}: a bundle profile pins nothing itself: the pins are the bundle's lock (pip_pins and packages are empty)")
    if profile["evidence"]["files"] or profile["evidence"]["manual_files"]:
        out.append(f"{at}: a bundle profile's evidence is the evidence bundle of the demo, not JUnit files")
    want_params = {"bundle_dir": ("abs-path", True), "install_dir": ("abs-path", True), "evidence_dir": ("dir-path", False)}
    got_params = {n: (s["kind"], s["required"]) for n, s in profile["params"].items()}
    if got_params != want_params:
        out.append(f"{at}: the parameters must be exactly {want_params}")
    name = bundle_name(root)
    want = expected_bundle_steps(name, profile["python"]["executable"])
    for phase in gen.PHASES:
        got = [s["argv"] for s in profile["steps"][phase]]
        if got != want[phase]:
            out.append(f"{at}: the {phase} steps must be exactly {[gen.display(a)[:80] for a in want[phase]]}")
        for s in profile["steps"][phase]:
            if s.get("env") or s.get("manual"):
                out.append(f"{at} {phase} step {s['id']}: no environment and no manual step in a bundle profile")
    for h in profile["hosts"]:
        if h["os_arch"] != "linux-x86_64" and h["status"] != "planned":
            out.append(f"{at} host {h['os_arch']}: the bundle is for linux-x86_64 only; another host can only be planned")
    if not any(h["os_arch"] == "linux-x86_64" for h in profile["hosts"]):
        out.append(f"{at}: the profile needs a linux-x86_64 host")
    # CI runs every step, verbatim, from the bundle a job of the same workflow built
    for h in profile["hosts"]:
        if h["status"] == "planned":
            continue
        hat = f"{at} host {h['os_arch']}"
        job = workflow["jobs"].get(f"profile-{profile['id']}")
        if job is None:
            out.append(f"{hat}: the workflow has no job profile-{profile['id']} that runs the profile")
            continue
        text = caps._job_text(job)
        if "tools/run_install_profile.py" not in text or f"--profile {profile['id']}" not in text or f"--host {h['os_arch']}" not in text:
            out.append(f"{hat}: the job does not run tools/run_install_profile.py --profile {profile['id']} --host {h['os_arch']}")
        channel = "stable" if h["status"] == "verified" else "experimental"
        if f"--channel {channel}" not in text:
            out.append(f"{hat}: a {h['status']} host is run on --channel {channel}")
        for phase in ("source", "install", "smoke", "check", "uninstall"):
            if phase not in text:
                out.append(f"{hat}: the job does not run the {phase} phase")
        if "source,install,smoke,check" not in text or "--phases uninstall" not in text:
            out.append(f"{hat}: the job must run the phases source,install,smoke,check and then, in its own step, uninstall")
        if job.get("runs-on") != "ubuntu-24.04" or RUNNERS.get(job.get("runs-on")) != h["os_arch"]:
            out.append(f"{hat}: the job runs on {job.get('runs-on')}")
        if job.get("needs") != "bundle" or not any(str(s.get("with", {}).get("name")) == "qa-bundle-current" for s in job["steps"]):
            out.append(f"{hat}: the job must start from the bundle the bundle job kept (needs: bundle, artifact qa-bundle-current)")
        if {"if", "continue-on-error", "strategy"} & set(job) or [s for s in job["steps"] if "if" in s or "continue-on-error" in s]:
            out.append(f"{hat}: the job must have no condition, no continue-on-error and no matrix")
        if not any(str(s.get("with", {}).get("python-version")) == profile["python"]["version"] for s in job["steps"]):
            out.append(f"{hat}: the job does not set up Python {profile['python']['version']}")
        if JOB_MARK not in str(job.get("name", "")):
            out.append(f"{hat}: the job name must say it is {JOB_MARK}")
    return out


# ------------------------------------------------------------------------------------------------ the profiles
def _pins_toml_tags(root: Path) -> Dict[str, List[str]]:
    import tomllib
    data = tomllib.loads((root / "pins.toml").read_text(encoding="utf-8"))
    tags: Dict[str, set] = {"runtime-contracts": set(), "agent-harness": set()}
    for s in data["sets"].values():
        tags["runtime-contracts"].add(s["contracts"]["tag"])
        tags["agent-harness"].add(s["harness_qa"]["tag"])
    return {k: sorted(v) for k, v in tags.items()}


def semantic_problems(profiles: Dict[str, Any], capabilities: Dict[str, Any], root: Path) -> List[str]:
    import yaml
    out: List[str] = []
    cap = {e["engine"]: e for e in capabilities["engines"]}
    workflow = yaml.safe_load((root / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8"))
    src = profiles["source"]
    if src["repository"] != capabilities["repository"]:
        out.append("source: repository differs from the capability manifest")
    if src["url"] != CLONE_URL or src["url"] != f"https://github.com/{src['repository']}.git":
        out.append("source: url must be the repository's own clone url")
    if src["dependency_release_tags"] != _pins_toml_tags(root):
        out.append(f"source: dependency_release_tags differ from pins.toml ({_pins_toml_tags(root)})")
    for tname, target in profiles["targets"].items():
        if target["status"] == "planned" and tname in PLANNED_TARGET_FILES:
            hits = [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and ".git" not in p.relative_to(root).parts
                    and ".pinned" not in p.relative_to(root).parts and PLANNED_TARGET_FILES[tname].match(p.name)]
            if hits:
                out.append(f"target {tname} is planned but the repository now has {hits[:3]}; test it, then offer it")
    if profiles["verifier"]["supported"] != any(p.get("verifier") and p["status"] != "planned" for p in profiles["profiles"]):
        out.append("verifier: supported must be true exactly when a profile that is not planned has verifier: true")
    ids, sets = set(), {}
    for p in profiles["profiles"]:
        at = f"profile {p['id']}"
        if p.get("verifier") and p.get("kind") != "bundle":
            out.append(f"{at}: only a bundle profile installs the verifier")
        if p["id"] in ids:
            out.append(f"{at}: duplicate id")
        ids.add(p["id"])
        for e in p["engines"]:
            if e not in cap:
                out.append(f"{at}: engine {e} is not in the capability manifest")
        key = (p["target"], tuple(sorted(p["engines"])))
        if key in sets:
            out.append(f"{at}: same target and engines as {sets[key]}")
        sets[key] = p["id"]
        # status rules
        host_status = [h["status"] for h in p["hosts"]]
        if p["status"] == "verified" and "verified" not in host_status:
            out.append(f"{at}: verified needs at least one verified host")
        if p["status"] == "experimental" and "verified" in host_status:
            out.append(f"{at}: a verified host makes the profile verified")
        if p["status"] == "planned" and (p["hosts"] or any(p["steps"].values())):
            out.append(f"{at}: a planned profile has no hosts and no steps")
        seen_os = set()
        for h in p["hosts"]:
            if h["os_arch"] in seen_os:
                out.append(f"{at}: host {h['os_arch']} listed twice")
            seen_os.add(h["os_arch"])
        if p["status"] == "planned":
            continue
        # engines and levels
        if p["status"] == "verified":
            for e in p["engines"]:
                if cap.get(e, {}).get("test_level") not in REAL_ENGINE_LEVELS:
                    out.append(f"{at}: verified, but engine {e} has test level {cap.get(e, {}).get('test_level')} in the capability manifest")
        if p["python"]["executable"] != "python" + p["python"]["version"]:
            out.append(f"{at}: python executable must be python{p['python']['version']}")
        if p.get("kind") == "bundle":
            for name, spec in p["params"].items():
                if name not in gen.PARAM_FIELDS:
                    out.append(f"{at}: parameter {name} is not a generator field")
                if spec["default"] is not None and not gen.valid_path(spec["default"], spec["kind"]):
                    out.append(f"{at}: default of {name} is not a valid {spec['kind']}")
                if spec["required"] == (spec["default"] is not None):
                    out.append(f"{at}: parameter {name} is required exactly when it has no default")
            out += bundle_problems(p, root, workflow)
            for h in p["hosts"]:
                if h["status"] == "verified":
                    out.append(f"{at} host {h['os_arch']}: a bundle profile is verified only once a run on main is recorded and this checker learns to check it; not supported yet")
            continue
        # pins against the capability manifest and the package metadata
        pinned = {x["name"].lower(): x["version"] for x in p["pip_pins"]}
        for e in p["engines"]:
            for d in cap.get(e, {}).get("dependencies", []):
                if d["kind"] == "pip" and d["provided_by"] == "install" and d["pin"] and re.match(r"^[0-9]", d["pin"]):
                    if pinned.get(d["name"].lower()) != d["pin"]:
                        out.append(f"{at}: pip pin for {d['name']} must be {d['pin']} (the capability manifest)")
        for name, version in pinned.items():
            if name == "pytest" and version.split(".")[0] not in ("8", "9"):
                out.append(f"{at}: pytest {version} is outside the range CI uses (>=8,<10)")
            if name == "pyyaml" and version.split(".")[0] != "6":
                out.append(f"{at}: pyyaml {version} is outside the range CI uses (>=6,<7)")
        want_pkgs = sorted({pk for e in p["engines"] for pk in cap.get(e, {}).get("install_method", {}).get("packages", [])})
        if sorted(p["packages"]) != want_pkgs:
            out.append(f"{at}: packages must be {want_pkgs} (the capability manifest's install packages)")
        for pk in p["packages"]:
            if not (root / pk / "pyproject.toml").is_file():
                out.append(f"{at}: package {pk} has no pyproject.toml")
        for name, spec in p["params"].items():
            if name not in gen.PARAM_FIELDS:
                out.append(f"{at}: parameter {name} is not a generator field")
            if spec["default"] is not None and not gen.valid_path(spec["default"], spec["kind"]):
                out.append(f"{at}: default of {name} is not a valid {spec['kind']}")
            if spec["required"] == (spec["default"] is not None):
                out.append(f"{at}: parameter {name} is required exactly when it has no default")
        for need in ("venv_dir", "evidence_dir", "checkout_dir"):
            if need not in p["params"]:
                out.append(f"{at}: missing parameter {need}")
        # steps
        files, manual_files, checked, checked_manual = [], [], [], []
        for phase in gen.PHASES:
            ids_in_phase = set()
            for s in p["steps"][phase]:
                out += step_problems(p, phase, s)
                if s["id"] in ids_in_phase:
                    out.append(f"{at}: duplicate step id {s['id']} in {phase}")
                ids_in_phase.add(s["id"])
                j = junit_of(s)
                if phase == "smoke" and j:
                    (manual_files if s.get("manual") else files).append(j)
                if phase == "check" and j:
                    (checked_manual if s.get("manual") else checked).append(j)
        if sorted(files) != sorted(p["evidence"]["files"]) or sorted(manual_files) != sorted(p["evidence"]["manual_files"]):
            out.append(f"{at}: the smoke steps write {sorted(files)} and manual {sorted(manual_files)}, the evidence declares {p['evidence']['files']} and {p['evidence']['manual_files']}")
        if sorted(checked) != sorted(files) or sorted(checked_manual) != sorted(manual_files):
            out.append(f"{at}: every evidence file needs exactly one check step (and a manual one for a manual file)")
        if not any(not s.get("manual") for s in p["steps"]["smoke"]):
            out.append(f"{at}: needs a smoke step that is not manual")
        if not p["steps"]["install"] or not p["steps"]["source"] or not p["steps"]["uninstall"]:
            out.append(f"{at}: needs source, install and uninstall steps")
        if not any(CODE_ASSERT in s["argv"] for s in p["steps"]["install"]):
            out.append(f"{at}: needs the step that checks the packages are imported from the virtual environment")
        # hosts
        for h in p["hosts"]:
            hat = f"{at} host {h['os_arch']}"
            vb = h["verified_by"]
            if h["status"] != "verified":
                continue
            job = workflow["jobs"].get(vb["job_key"])
            if job is None:
                out.append(f"{hat}: workflow has no job {vb['job_key']!r}")
                continue
            text = caps._job_text(job)
            if not str(job.get("name", "")).startswith(vb["job_name"]):
                out.append(f"{hat}: job {vb['job_key']!r} is not named {vb['job_name']!r}")
            if JOB_MARK not in str(job.get("name", "")):
                out.append(f"{hat}: the job name must say it is {JOB_MARK}")
            if "tools/run_install_profile.py" not in text or f"--profile {p['id']}" not in text:
                out.append(f"{hat}: the job does not run tools/run_install_profile.py --profile {p['id']}")
            if "--channel stable" not in text or f"--host {h['os_arch']}" not in text:
                out.append(f"{hat}: the job must run the stable channel on --host {h['os_arch']}")
            if RUNNERS.get(job.get("runs-on")) != h["os_arch"]:
                out.append(f"{hat}: the job runs on {job.get('runs-on')}, which is not {h['os_arch']}")
            if {"if", "continue-on-error", "strategy"} & set(job) or [s for s in job["steps"] if "continue-on-error" in s or ("if" in s and not keeps_evidence(s))]:
                out.append(f"{hat}: the job must have no condition, no continue-on-error and no matrix")
            if not any(str(s.get("with", {}).get("python-version")) == p["python"]["version"] for s in job["steps"]):
                out.append(f"{hat}: the job does not set up Python {p['python']['version']}")
            pinned_checkout = [s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout@") and s.get("with", {}).get("path") == ".profile-src"
                               and s["with"].get("ref") == "${{ steps.profile.outputs.commit }}" and s["with"].get("persist-credentials") is False]
            reads_pin = [s for s in job["steps"] if s.get("id") == "profile" and "['source']['pinned_commit']" in str(s.get("run", ""))]
            if not pinned_checkout or not reads_pin:
                out.append(f"{hat}: the job must check out the pinned commit")
            if vb["source_commit"] != src["pinned_commit"]:
                out.append(f"{hat}: source_commit must be the pinned commit {src['pinned_commit']}")
            expected = f"https://github.com/{src['repository']}/actions/runs/{vb['run_id']}"
            if vb["run_url"] != expected or vb["url"] != expected + f"/job/{vb['job_id']}":
                out.append(f"{hat}: run_url and url must be built from the run and job ids")
    if re.search(r"(?<!not )open[ -]source|private (repo|development)", json.dumps(profiles), re.IGNORECASE):
        out.append("wording: no 'open source' (except 'not open source') and no 'private repository'")
    return out


def pin_at_head_report(profiles: Dict[str, Any], root: Path) -> Tuple[List[str], Set[Tuple[str, str]]]:
    """Log-independent: the job reads its pin from the file of its own checkout, so ``pinned_commit`` in ``qa-install-profiles.json`` as committed at the
    recorded run's head_sha must equal the record's ``source_commit``. Needs the commit in the clone (the install-profiles job fetches the full history); a commit
    or file that cannot be read is a finding (fail closed). Returns the findings and the (profile, host) pairs that passed."""
    out: List[str] = []
    ok: Set[Tuple[str, str]] = set()
    for p in profiles["profiles"]:
        for h in p["hosts"]:
            vb = h["verified_by"]
            if not vb:
                continue
            at = f"profile {p['id']} host {h['os_arch']}"
            code, text = caps._git(root, "show", f"{vb['head_sha']}:{PROFILES}")
            if code != 0:
                out.append(f"{at}: cannot read {PROFILES} at the recorded head {vb['head_sha'][:12]} (is the full history fetched?), so the pin that run installed cannot be checked")
                continue
            try:
                pinned = json.loads(text)["source"]["pinned_commit"]
            except (ValueError, KeyError, TypeError):
                out.append(f"{at}: {PROFILES} at the recorded head {vb['head_sha'][:12]} has no readable source.pinned_commit")
                continue
            if pinned != vb["source_commit"]:
                out.append(f"{at}: the pinned commit at the recorded head {vb['head_sha'][:12]} is {pinned}, the record says the run installed {vb['source_commit']}")
            else:
                ok.add((p["id"], h["os_arch"]))
    return out, ok


def freshness_problems(profiles: Dict[str, Any], root: Path, main_ref: Optional[str] = None, head_ok: FrozenSet[Tuple[str, str]] = frozenset()) -> List[str]:
    """The pinned source commit and the head commit of every recorded run must be ancestors of main.

    They are different commits and the data says so: a run's head_sha is the run, its source_commit is the pin it installed from. One exception, for the
    head of a recorded run only: it may instead be an ancestor of the commit under test (HEAD), which is the case while the change that records a run of its
    own branch is still unmerged (a merge commit then puts that head into main's history). That exception applies only to the (profile id, host) pairs in
    ``head_ok``, which ``verify_ci_report`` fills only after the cited job's log confirmed what the run installed and how many tests passed."""
    ref = caps.resolve_main_ref(root, main_ref, "main")
    if ref is None:
        return ["freshness: cannot resolve the main branch; fetch it (full history) before checking"]
    shas = {"source pinned_commit": (profiles["source"]["pinned_commit"], None)}
    for p in profiles["profiles"]:
        for h in p["hosts"]:
            if h["verified_by"]:
                shas[f"profile {p['id']} host {h['os_arch']} head_sha"] = (h["verified_by"]["head_sha"], (p["id"], h["os_arch"]))
    out = []
    for what, (sha, key) in shas.items():
        if caps._git(root, "cat-file", "-e", f"{sha}^{{commit}}")[0] != 0:
            out.append(f"freshness: {what} {sha[:12]} is not a commit of this repository (is the history complete?)")
        elif caps._git(root, "merge-base", "--is-ancestor", sha, ref)[0] != 0:
            if key is not None and key in head_ok and caps._git(root, "merge-base", "--is-ancestor", sha, "HEAD")[0] == 0:
                continue
            hint = " (it is an ancestor of HEAD, which is accepted only when the pin at that commit is the recorded source_commit and, with --verify-ci, the cited job's log confirms the run)" if key is not None and caps._git(root, "merge-base", "--is-ancestor", sha, "HEAD")[0] == 0 else ""
            out.append(f"freshness: {what} {sha[:12]} is not an ancestor of {ref}{hint}")
    return out


# ------------------------------------------------------------------------------------------------ generated document
def _fill(argv: List[str], profile: Dict[str, Any], commit: str) -> List[str]:
    values = {n: s["default"] for n, s in profile["params"].items() if s["default"] is not None}
    values["source_commit"] = commit

    def one(m):
        return values.get(m.group(1), m.group(0))
    return [gen.PLACEHOLDER.sub(one, a) for a in argv]


def render_docs(profiles: Dict[str, Any]) -> str:
    L: List[str] = [GENERATED_NOTICE, "", "# ReDevOps QA: install profiles", ""]
    src = profiles["source"]
    L += ["This page is generated from [`qa-install-profiles.json`](../qa-install-profiles.json), the data the installer configurator is built from. "
          f"Every profile but `local-python-qa` installs from a clone of {src['url'].removesuffix('.git')} at the pinned commit `{src['pinned_commit']}`; {src['note']} "
          "The profile `local-python-qa` installs from a bundle archive instead (see its section).", "",
          "A profile is **verified** only when a CI job runs that exact profile, step by step, on the host named; **experimental** means the steps are written and "
          "partly or not at all run for that host; **planned** means nothing is offered yet and the reason is given.", "",
          "## Targets", "", "| Target | Status | Reason |", "|---|---|---|"]
    for name in gen.TARGETS:
        t = profiles["targets"][name]
        L.append(f"| {name} | {t['status']} | {caps._cell(t['disabled_reason'] or '')} |")
    v = profiles["verifier"]
    L += ["", ("Re-verification in a separate process: offered by " + ", ".join(f"`{p['id']}`" for p in profiles["profiles"] if p.get("verifier") and p["status"] != "planned") + " only. " if v["supported"]
               else "Re-verification in a separate process: not offered. ") + v["reason"], "", "## Profiles", "",
          "| Profile | Engines | Status | Hosts |", "|---|---|---|---|"]
    for p in profiles["profiles"]:
        hosts = "; ".join(f"{h['os_arch']} ({h['status']})" for h in p["hosts"]) or "none"
        L.append(f"| [{p['id']}](#{p['id']}) | {', '.join(p['engines'])} | {p['status']} | {hosts} |")
    for p in profiles["profiles"]:
        L += ["", f"## {p['id']}", "", f"{p['title']}. Status: **{p['status']}**."]
        if p["status"] == "planned":
            L += ["", f"Not offered: {p['disabled_reason']}"]
            continue
        L += ["", f"Python {p['python']['version']} (`{p['python']['executable']}`); pinned pip packages: " + (", ".join(f"`{x['name']}=={x['version']}`" for x in p["pip_pins"]) if p["pip_pins"] else "none of its own (every wheel is pinned by hash in the bundle's requirements.lock)") + ".",
              "", "Prerequisites:", ""] + [f"* {x}" for x in p["prerequisites"]]
        L += ["", "Hosts:", "", "| Host | Status | Prerequisites | Verified by |", "|---|---|---|---|"]
        for h in p["hosts"]:
            vb = h["verified_by"]
            by = (f"[run {vb['run_id']}]({vb['run_url']}) (whole run green, head `{vb['head_sha'][:12]}`), [job {vb['job_id']}]({vb['url']}), installed from the pinned commit "
                  f"`{vb['source_commit'][:12]}`, {vb['completed_on']}: {caps._cell(vb['summary'])}") if vb else (caps._cell(h["note"]) or "not run")
            L.append(f"| {h['os_arch']} | {h['status']} | {caps._cell(' '.join(h['prerequisites']))} | {by} |")
        L += ["", "Parameters:", ""] + [f"* `{n}`: {s['description']}" + (f" (default `{s['default']}`)" if s["default"] else " (required)") for n, s in sorted(p["params"].items())]
        for phase, title in (("source", "Get the source"), ("install", "Install"), ("smoke", "Smoke test"), ("check", "Check the evidence"), ("uninstall", "Uninstall")):
            L += ["", f"### {title}", "", "```text"]
            for s in p["steps"][phase]:
                L.append(f"# {s['title']}" + (" (manual: not run by CI)" if s.get("manual") else ""))
                L.append(gen.display(_fill(s["argv"], p, src["pinned_commit"]), {k: v for k, v in s.get("env", {}).items()}))
            L.append("```")
        L += ["", f"Evidence: {p['evidence']['description']}" + (" Files: " + ", ".join(f"`{f}`" for f in p["evidence"]["files"] + p["evidence"]["manual_files"]) + "." if p["evidence"]["files"] + p["evidence"]["manual_files"] else ""),
              "", f"Uninstall: {p['uninstall_note']}", "", "Limitations:", ""] + [f"* {x}" for x in p["limitations"]]
    return "\n".join(L).rstrip("\n") + "\n"


def docs_problems(profiles: Dict[str, Any], root: Path) -> List[str]:
    current = caps.read(root, DOCS)
    if current is None:
        return [f"docs: {DOCS} is missing (run: python tools/check_install_profiles.py --write-docs)"]
    if current != render_docs(profiles):
        return [f"docs: {DOCS} differs from the document generated from {PROFILES} (run: python tools/check_install_profiles.py --write-docs)"]
    return []


# ------------------------------------------------------------------------------------------------ opt-in network checks
CHECKOUT_LINE = re.compile(r"checkout verified: HEAD is the pinned commit ([0-9a-f]{40}), clean tree")
PASSED_LINE = re.compile(r"^\S+Z (\d+) passed(?:, \d+ [a-z ]+)* in [0-9.]+s", re.M)
OK_LINE = re.compile(r"^\S+Z OK (\d+) tests, 0 skipped, 0 failed\s*$", re.M)
SUMMARY_COUNTS = re.compile(r"(\d+(?: \+ \d+)*) tests passed")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 - the redirect is followed by hand, without the credential
        return None


LOG_REDIRECT_PREFIXES = ("https://",)       # the log is fetched from the address the API redirects to; nothing else is opened
LOG_MAX_BYTES = 20_000_000


def _read_bounded(response: Any) -> str:
    data = response.read(LOG_MAX_BYTES + 1)
    if len(data) > LOG_MAX_BYTES:
        raise OSError(f"the log is larger than {LOG_MAX_BYTES} bytes")
    return data.decode("utf-8", "replace")


def api_get_log(url: str) -> str:
    """The text of a job log through the read-only API. The API answers with a redirect to a short-lived address; it is followed by hand, only to an https
    address, without the credential (which goes to the first request only), and the body is bounded."""
    import os
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    credential = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if credential:
        request.add_header("Authorization", "Bearer " + credential)
    try:
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=30) as response:
            return _read_bounded(response)
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location") if exc.code in (301, 302, 303, 307, 308) else None
        if not location:
            raise
    if not location.startswith(LOG_REDIRECT_PREFIXES):
        raise OSError("the log address is not an https address")
    with urllib.request.build_opener(_NoRedirect).open(urllib.request.Request(location), timeout=60) as response:     # noqa: S310 - https only, checked above
        return _read_bounded(response)


def log_problems(at: str, vb: Dict[str, Any], text: str) -> List[str]:
    """What the cited job's log says it installed and how many tests passed must equal the record (the record says it; the log is the evidence)."""
    out: List[str] = []
    installed = CHECKOUT_LINE.findall(text)
    if not installed:
        out.append(f"{at}: the log of job {vb['job_id']} has no 'checkout verified: HEAD is the pinned commit <sha>' line, so what the run installed cannot be confirmed")
    elif set(installed) != {vb["source_commit"]}:
        out.append(f"{at}: job {vb['job_id']} installed {', '.join(sorted(set(installed)))}, the record says {vb['source_commit']}")
    stated = SUMMARY_COUNTS.search(vb["summary"])
    if not stated:
        out.append(f"{at}: the summary does not state the passed counts as 'N + N + N tests passed'")
    else:
        recorded = [int(x) for x in stated.group(1).split(" + ")]
        logged = [int(x) for x in PASSED_LINE.findall(text)]
        if logged != recorded:
            out.append(f"{at}: the log of job {vb['job_id']} shows {' + '.join(map(str, logged)) or 'no'} passed tests, the record says {' + '.join(map(str, recorded))}")
        clean = [int(x) for x in OK_LINE.findall(text)]
        if clean != recorded:
            out.append(f"{at}: the log of job {vb['job_id']} shows {' + '.join(map(str, clean)) or 'no'} tests checked as 'OK N tests, 0 skipped, 0 failed', the record says {' + '.join(map(str, recorded))} with 0 skipped and 0 failed")
    return out


def verify_ci_report(profiles: Dict[str, Any], repo: str, fetch: Callable[[str], Any] = caps._api_get, fetch_log: Optional[Callable[[str], str]] = None,
                     head_on_main: Callable[[str], bool] = lambda sha: True) -> Tuple[List[str], Set[Tuple[str, str]]]:
    """Re-check every recorded run against the read-only API: the run (head, whole-run conclusion), the job (success, name, day) and the job's log (the commit
    it installed and the passed counts). Returns the findings and the (profile, host) pairs whose log confirmed the record.

    A log that cannot be read is a finding, with one exception: a log that is gone (HTTP 404 or 410, the retention of logs has run out) is tolerated for a run whose
    head is on main (the record was checked when it was made, and the pin it installed is checked without the log by ``pin_at_head_report``). A missing or
    insufficient credential (401, 403), a server error, a network error or a timeout is never tolerated."""
    out: List[str] = []
    confirmed: Set[Tuple[str, str]] = set()
    for p in profiles["profiles"]:
        for h in p["hosts"]:
            vb = h["verified_by"]
            if not vb:
                continue
            at = f"profile {p['id']} host {h['os_arch']}"
            try:
                run = fetch(f"https://api.github.com/repos/{repo}/actions/runs/{vb['run_id']}")
                jobs = fetch(f"https://api.github.com/repos/{repo}/actions/runs/{vb['run_id']}/jobs?per_page=100")
            except Exception as exc:  # noqa: BLE001
                out.append(f"{at}: cannot read run {vb['run_id']} ({type(exc).__name__})")
                continue
            if run.get("head_sha") != vb["head_sha"]:
                out.append(f"{at}: run {vb['run_id']} head is {run.get('head_sha')}, not {vb['head_sha']}")
            if run.get("conclusion") != vb["run_conclusion"]:
                out.append(f"{at}: run {vb['run_id']} as a whole concluded {run.get('conclusion')}, not {vb['run_conclusion']} (a visitor following the link must not see a red run)")
            job = next((j for j in jobs.get("jobs", []) if j.get("id") == vb["job_id"]), None)
            if job is None:
                out.append(f"{at}: run {vb['run_id']} has no job {vb['job_id']}")
                continue
            if job.get("conclusion") != "success":
                out.append(f"{at}: job {vb['job_id']} concluded {job.get('conclusion')}")
            if not str(job.get("name", "")).startswith(vb["job_name"]):
                out.append(f"{at}: job {vb['job_id']} is named {job.get('name')!r}")
            if str(job.get("completed_at", ""))[:10] != vb["completed_on"]:
                out.append(f"{at}: job {vb['job_id']} completed on {str(job.get('completed_at', ''))[:10]}")
            text = None
            if fetch_log is not None:
                try:
                    text = fetch_log(f"https://api.github.com/repos/{repo}/actions/jobs/{vb['job_id']}/logs")
                except Exception as exc:  # noqa: BLE001
                    text = None
                    gone = isinstance(exc, urllib.error.HTTPError) and exc.code in (404, 410)
                    reason = type(exc).__name__ + (f" {exc.code}" if isinstance(exc, urllib.error.HTTPError) else "")
            else:
                gone, reason = None, "no log reader"
            if text is None:
                if gone is None and head_on_main(vb["head_sha"]):
                    continue                                    # no reader was given: only the run and the job were asked for
                if not (gone and head_on_main(vb["head_sha"])):
                    out.append(f"{at}: the log of job {vb['job_id']} cannot be read ({reason}), so what it installed and its counts cannot be confirmed (failing closed"
                               + ("" if not gone else ": the log is gone but the head of this run is not on main") + ")")
                continue
            found = log_problems(at, vb, text)
            out += found
            if not found:
                confirmed.add((p["id"], h["os_arch"]))
    return out, confirmed


def verify_ci_problems(profiles: Dict[str, Any], repo: str, fetch: Callable[[str], Any] = caps._api_get, fetch_log: Optional[Callable[[str], str]] = None,
                       head_on_main: Callable[[str], bool] = lambda sha: True) -> List[str]:
    return verify_ci_report(profiles, repo, fetch, fetch_log, head_on_main)[0]


# ------------------------------------------------------------------------------------------------ command line
def check_all(root: Path, *, main_ref: Optional[str] = None, freshness: bool = True, head_ok: Optional[FrozenSet[Tuple[str, str]]] = None) -> List[str]:
    profiles = load_json(root / PROFILES)
    capabilities = load_json(root / caps.MANIFEST)
    findings = [f"schema: {m}" for m in qa_jsonschema.validate(profiles, load_json(root / SCHEMA))]
    if findings:
        return findings
    findings += semantic_problems(profiles, capabilities, root)
    findings += docs_problems(profiles, root)
    if freshness:
        pin_findings, pin_ok = pin_at_head_report(profiles, root)
        findings += pin_findings
        # The exception for a head that is only on the commit under test needs the pin-at-head check; with --verify-ci it needs the cited log as well.
        findings += freshness_problems(profiles, root, main_ref, frozenset(pin_ok) if head_ok is None else frozenset(pin_ok) & head_ok)
    return findings


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=str(HERE.parent))
    ap.add_argument("--main-ref", default=None)
    ap.add_argument("--no-freshness", action="store_true")
    ap.add_argument("--write-docs", action="store_true")
    ap.add_argument("--verify-ci", action="store_true")
    ap.add_argument("--cross-check", action="store_true")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    if args.write_docs:
        (root / DOCS).parent.mkdir(parents=True, exist_ok=True)
        (root / DOCS).write_text(render_docs(load_json(root / PROFILES)), encoding="utf-8")
        print(f"wrote {DOCS}")
        return 0
    profiles = load_json(root / PROFILES)
    ci_findings: List[str] = []
    head_ok: Optional[FrozenSet[Tuple[str, str]]] = None
    if args.verify_ci:
        ref = caps.resolve_main_ref(root, args.main_ref, "main")
        on_main = (lambda sha: caps._git(root, "merge-base", "--is-ancestor", sha, ref)[0] == 0) if ref else (lambda sha: False)
        ci_findings, confirmed = verify_ci_report(profiles, load_json(root / caps.MANIFEST)["repository"], fetch=caps._api_get, fetch_log=api_get_log, head_on_main=on_main)
        head_ok = frozenset(confirmed)
    findings = check_all(root, main_ref=args.main_ref, freshness=not args.no_freshness, head_ok=head_ok) + ci_findings
    if args.cross_check:
        findings += caps.cross_check_problems(load_json(root / SCHEMA), profiles)
    for f in findings:
        print(f"FAIL {f}")
    if findings:
        return 1
    print("OK " + PROFILES + (" (freshness skipped)" if args.no_freshness else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
