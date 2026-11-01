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
* the pinned source commit and the head commit of every recorded run are ancestors of main; a recorded run states the pin it installed from (``source_commit``,
  which must be the profile's pinned commit) separately from its own head commit;
* ``docs/QA_INSTALL_PROFILES.md`` equals the document generated from the JSON.

Usage: ``python tools/check_install_profiles.py [--root DIR] [--main-ref REF] [--no-freshness] [--write-docs] [--verify-ci] [--cross-check]``.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    ids, sets = set(), {}
    for p in profiles["profiles"]:
        at = f"profile {p['id']}"
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
            if {"if", "continue-on-error", "strategy"} & set(job) or [s for s in job["steps"] if "if" in s or "continue-on-error" in s]:
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


def freshness_problems(profiles: Dict[str, Any], root: Path, main_ref: Optional[str] = None) -> List[str]:
    ref = caps.resolve_main_ref(root, main_ref, "main")
    if ref is None:
        return ["freshness: cannot resolve the main branch; fetch it (full history) before checking"]
    # Both the pinned source commit (what the profile installs from) and the head commit of every recorded run (what supplied the workflow and the tools)
    # must be ancestors of main. They are different commits and the data says so: a run's head_sha is the run, its source_commit is the pin it installed from.
    shas = {"source pinned_commit": (profiles["source"]["pinned_commit"], ref)}
    for p in profiles["profiles"]:
        for h in p["hosts"]:
            if h["verified_by"]:
                shas[f"profile {p['id']} host {h['os_arch']} head_sha"] = (h["verified_by"]["head_sha"], ref)
    out = []
    for what, (sha, against) in shas.items():
        if caps._git(root, "cat-file", "-e", f"{sha}^{{commit}}")[0] != 0:
            out.append(f"freshness: {what} {sha[:12]} is not a commit of this repository (is the history complete?)")
        elif caps._git(root, "merge-base", "--is-ancestor", sha, against)[0] != 0:
            out.append(f"freshness: {what} {sha[:12]} is not an ancestor of {against}")
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
          f"Every profile installs from a clone of {src['url'].removesuffix('.git')} at the pinned commit `{src['pinned_commit']}`; {src['note']}", "",
          "A profile is **verified** only when a CI job runs that exact profile, step by step, on the host named; **experimental** means the steps are written and "
          "partly or not at all run for that host; **planned** means nothing is offered yet and the reason is given.", "",
          "## Targets", "", "| Target | Status | Reason |", "|---|---|---|"]
    for name in gen.TARGETS:
        t = profiles["targets"][name]
        L.append(f"| {name} | {t['status']} | {caps._cell(t['disabled_reason'] or '')} |")
    L += ["", f"Independent verifier: not offered. {profiles['verifier']['reason']}", "", "## Profiles", "",
          "| Profile | Engines | Status | Hosts |", "|---|---|---|---|"]
    for p in profiles["profiles"]:
        hosts = "; ".join(f"{h['os_arch']} ({h['status']})" for h in p["hosts"]) or "none"
        L.append(f"| [{p['id']}](#{p['id']}) | {', '.join(p['engines'])} | {p['status']} | {hosts} |")
    for p in profiles["profiles"]:
        L += ["", f"## {p['id']}", "", f"{p['title']}. Status: **{p['status']}**."]
        if p["status"] == "planned":
            L += ["", f"Not offered: {p['disabled_reason']}"]
            continue
        L += ["", f"Python {p['python']['version']} (`{p['python']['executable']}`); pinned pip packages: " + ", ".join(f"`{x['name']}=={x['version']}`" for x in p["pip_pins"]) + ".",
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
        L += ["", f"Evidence: {p['evidence']['description']} Files: " + ", ".join(f"`{f}`" for f in p["evidence"]["files"] + p["evidence"]["manual_files"]) + ".",
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
def verify_ci_problems(profiles: Dict[str, Any], repo: str, fetch=caps._api_get) -> List[str]:
    out: List[str] = []
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
            else:
                if job.get("conclusion") != "success":
                    out.append(f"{at}: job {vb['job_id']} concluded {job.get('conclusion')}")
                if not str(job.get("name", "")).startswith(vb["job_name"]):
                    out.append(f"{at}: job {vb['job_id']} is named {job.get('name')!r}")
                if str(job.get("completed_at", ""))[:10] != vb["completed_on"]:
                    out.append(f"{at}: job {vb['job_id']} completed on {str(job.get('completed_at', ''))[:10]}")
    return out


# ------------------------------------------------------------------------------------------------ command line
def check_all(root: Path, *, main_ref: Optional[str] = None, freshness: bool = True) -> List[str]:
    profiles = load_json(root / PROFILES)
    capabilities = load_json(root / caps.MANIFEST)
    findings = [f"schema: {m}" for m in qa_jsonschema.validate(profiles, load_json(root / SCHEMA))]
    if findings:
        return findings
    findings += semantic_problems(profiles, capabilities, root)
    findings += docs_problems(profiles, root)
    if freshness:
        findings += freshness_problems(profiles, root, main_ref)
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
    findings = check_all(root, main_ref=args.main_ref, freshness=not args.no_freshness)
    profiles = load_json(root / PROFILES)
    if args.verify_ci:
        findings += verify_ci_problems(profiles, load_json(root / caps.MANIFEST)["repository"])
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
