#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Check qa-capabilities.json: schema, evidence, agreement with the repository and with the adapters' own manifests, freshness, generated document.

What it checks (offline, no network, no secret, except the explicit ``--verify-ci`` and ``--cross-check`` modes):

* the manifest validates against ``schemas/qa-capabilities.schema.json``;
* every pin matches the file it names (package metadata, workflows, pins.toml, the licence matrix) and every licence fact matches the matrix;
* every evidence reference resolves: a repository path exists, a CI job names a workflow job that exists in this repository's workflow files and, for
  a real-engine claim, installs the pinned engine, and a local run names a document that mentions the day it was observed;
* each ``test_level`` is supported by its evidence (no level without the kind of evidence it needs) and the entry's level is the strongest one
  reached anywhere;
* the manifest and the adapters' manifests in code agree on adapter ids, adapter versions, engine versions and execution modes;
* freshness: every ``last_verified_sha`` (and every CI evidence head commit) is an ancestor of the main branch; with ``--verify-ci`` every cited run
  is also green as a whole, not only the cited job;
* ``docs/QA_CAPABILITIES.md`` equals the document generated from the JSON.

Usage: ``python tools/check_capabilities.py [--root DIR] [--main-ref REF] [--no-freshness] [--write-docs] [--verify-ci] [--cross-check]``.
Exit status 1 on any finding.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import qa_jsonschema  # noqa: E402

MANIFEST = "qa-capabilities.json"
SCHEMA = "schemas/qa-capabilities.schema.json"
DOCS = "docs/QA_CAPABILITIES.md"
LEVEL_ORDER = ["none", "offline-fake", "engine-backed-ci", "device-backed-local", "device-backed-ci"]
GENERATED_NOTICE = "<!-- Generated from qa-capabilities.json by tools/check_capabilities.py --write-docs. Do not edit by hand. -->"
PYTHON_PACKAGE_SRC = {"qa-adapter-kit": "qa_adapter_kit", "qa-selenium": "qa_selenium", "qa-robot": "qa_robot", "qa-appium": "qa_appium"}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read(root: Path, rel: str) -> Optional[str]:
    path = root / rel
    return path.read_text(encoding="utf-8") if path.is_file() else None


# ------------------------------------------------------------------------------------------------ schema
def schema_problems(manifest: Any, schema: Dict[str, Any]) -> List[str]:
    return [f"schema: {m}" for m in qa_jsonschema.validate(manifest, schema)]


# ------------------------------------------------------------------------------------------------ repository facts
def _workflow_jobs(root: Path, workflow: str) -> Dict[str, Dict[str, Any]]:
    import yaml
    text = read(root, f".github/workflows/{workflow}")
    if text is None:
        return {}
    return (yaml.safe_load(text) or {}).get("jobs", {}) or {}


def _job_text(job: Dict[str, Any]) -> str:
    return "\n".join(f"{s.get('run', '')} {s.get('uses', '')} {s.get('with', '')}" for s in job.get("steps", []))


def _pyproject_extras(root: Path, package_path: str) -> Optional[Dict[str, Any]]:
    import tomllib
    text = read(root, f"{package_path}/pyproject.toml")
    return tomllib.loads(text) if text is not None else None


def level_rank(level: str) -> int:
    return LEVEL_ORDER.index(level)


def semantic_problems(manifest: Dict[str, Any], root: Path) -> List[str]:
    import yaml
    out: List[str] = []
    matrix = yaml.safe_load((root / "third_party" / "adapter-license-matrix.yaml").read_text(encoding="utf-8"))
    components = {c["id"]: c for c in matrix["components"]}
    repo = manifest["repository"]
    seen_engines, seen_adapters, seen_jobs, run_shas = set(), set(), set(), {}
    for entry in manifest["engines"]:
        eid = entry["engine"]
        at = f"engine {eid}"
        if eid in seen_engines:
            out.append(f"{at}: duplicate engine id")
        seen_engines.add(eid)
        for adapter in entry["adapter_ids"]:
            if adapter in seen_adapters:
                out.append(f"{at}: adapter id {adapter} listed by two engines")
            seen_adapters.add(adapter)
        # install method
        extras_found = set()
        for pkg in entry["install_method"]["packages"]:
            meta = _pyproject_extras(root, pkg)
            if meta is None:
                out.append(f"{at}: install package {pkg} has no pyproject.toml")
                continue
            extras_found |= set(meta.get("project", {}).get("optional-dependencies", {}))
        for extra in entry["install_method"]["extras"]:
            if extra not in extras_found:
                out.append(f"{at}: extra {extra!r} is declared by none of the install packages")
        # dependencies
        for dep in entry["dependencies"]:
            name = f"{at}: dependency {dep['name']}"
            if dep["pin"] is None:
                continue
            text = read(root, dep["pin_source"])
            if text is None:
                out.append(f"{name}: pin_source {dep['pin_source']} does not exist")
                continue
            if dep["pin_literal"] not in text:
                out.append(f"{name}: {dep['pin_literal']!r} is not in {dep['pin_source']}")
            if dep["kind"] in ("pip", "npm"):
                sep = "==" if dep["kind"] == "pip" else "@"
                if not dep["pin_literal"].startswith(dep["name"]):
                    out.append(f"{name}: pin_literal must start with the package name")
                if re.match(r"^[0-9]", dep["pin"]) and dep["kind"] == "pip" and dep["pin_literal"] != f"{dep['name']}=={dep['pin']}":
                    out.append(f"{name}: an exact pip pin must read {dep['name']}=={dep['pin']}")
            if dep["kind"] == "driver" and dep["name"].startswith("appium") and dep["pin_literal"] != dep["pin"] and not dep["pin_literal"].endswith("@" + dep["pin"]):
                out.append(f"{name}: pin_literal must end with the pinned version")
        # evidence
        evidence: Dict[str, Dict[str, Any]] = {}
        for ev in entry["evidence"]:
            if ev["id"] in evidence:
                out.append(f"{at}: duplicate evidence id {ev['id']}")
            evidence[ev["id"]] = ev
            ref = f"{at}: evidence {ev['id']}"
            if ev["kind"] == "repo-path":
                if not (root / ev["path"]).exists():
                    out.append(f"{ref}: path {ev['path']} does not exist")
            elif ev["kind"] == "local-run":
                text = read(root, ev["path"])
                if text is None:
                    out.append(f"{ref}: path {ev['path']} does not exist")
                elif ev["observed_on"] not in text:
                    out.append(f"{ref}: {ev['path']} does not mention the day it was observed ({ev['observed_on']})")
            else:
                jobs = _workflow_jobs(root, ev["workflow"])
                job = jobs.get(ev["job_key"])
                if job is None:
                    out.append(f"{ref}: workflow {ev['workflow']} has no job {ev['job_key']!r}")
                elif not str(job.get("name", "")).startswith(ev["job_name"]):
                    out.append(f"{ref}: job {ev['job_key']!r} is not named {ev['job_name']!r}")
                expected = f"https://github.com/{repo}/actions/runs/{ev['run_id']}/job/{ev['job_id']}"
                if ev["url"] != expected:
                    out.append(f"{ref}: url must be {expected}")
                if ev["run_url"] != f"https://github.com/{repo}/actions/runs/{ev['run_id']}":
                    out.append(f"{ref}: run_url must be https://github.com/{repo}/actions/runs/{ev['run_id']}")
                if run_shas.setdefault(ev["run_id"], ev["head_sha"]) != ev["head_sha"]:
                    out.append(f"{ref}: run {ev['run_id']} is cited with two different head commits")
                if ev["job_id"] in seen_jobs:
                    out.append(f"{ref}: job id {ev['job_id']} is cited twice")
                seen_jobs.add(ev["job_id"])
        # levels
        engine_literals = [d["pin_literal"] for d in entry["dependencies"] if d["kind"] in ("pip", "npm", "driver") and d["pin"] and d["pin_literal"]
                           and d["pin_source"] and d["name"] != "pytest"]
        reached = []
        for env in entry["os_arch"]:
            where = f"{at}: os_arch {env['os_arch']}"
            refs = []
            for ev_id in env["evidence"]:
                if ev_id not in evidence:
                    out.append(f"{where}: evidence {ev_id} is not defined in this entry")
                else:
                    refs.append(evidence[ev_id])
            reached.append(env["test_level"])
            ci_jobs = [e for e in refs if e["kind"] == "ci-job"]
            locals_ = [e for e in refs if e["kind"] == "local-run"]
            level = env["test_level"]
            if level == "none":
                out.append(f"{where}: an environment cannot be verified at level none")
            elif level == "offline-fake" and not ci_jobs:
                out.append(f"{where}: offline-fake needs a CI job as evidence")
            elif level == "engine-backed-ci":
                backed = [e for e in ci_jobs if e["workflow"] == "tests.yml" and any(lit in _job_text(_workflow_jobs(root, e["workflow"]).get(e["job_key"], {}))
                                                                                     for lit in engine_literals)]
                if not backed:
                    out.append(f"{where}: engine-backed-ci needs a CI job that installs the pinned engine ({engine_literals})")
            elif level == "device-backed-local" and not locals_:
                out.append(f"{where}: device-backed-local needs a recorded local run")
            elif level == "device-backed-ci" and not [e for e in ci_jobs if e["workflow"] == "appium-android.yml"]:
                out.append(f"{where}: device-backed-ci needs a run of the device workflow")
        top = max(reached, key=level_rank) if reached else "none"
        if entry["test_level"] != top:
            out.append(f"{at}: test_level {entry['test_level']} but the strongest verified environment is {top}")
        # top-level sha and date follow the evidence that backs the entry's level
        if reached:
            strongest = [env for env in entry["os_arch"] if env["test_level"] == top]
            backing = [evidence[i] for env in strongest for i in env["evidence"] if i in evidence]
            if top == "device-backed-local":
                ok = [e for e in backing if e["kind"] == "local-run" and e["recorded_in_sha"] == entry["last_verified_sha"]
                      and e["observed_on"] == entry["last_verified_date"]]
                if not ok or entry["last_verified_sha_basis"] != "documented-in":
                    out.append(f"{at}: last_verified_sha/date must be the recorded_in_sha/observed_on of the local run (basis documented-in)")
            else:
                ok = [e for e in backing if e["kind"] == "ci-job" and e["head_sha"] == entry["last_verified_sha"]
                      and e["completed_on"] == entry["last_verified_date"]]
                if not ok or entry["last_verified_sha_basis"] != "ci-head":
                    out.append(f"{at}: last_verified_sha/date must be the head_sha/completed_on of a CI job that backs the entry's level (basis ci-head)")
        # licence
        for i, comp in enumerate(entry["license"]["components"]):
            cid = comp["matrix_component"]
            m = components.get(cid)
            if m is None:
                out.append(f"{at}: licence component {cid} is not in the licence matrix")
                continue
            if m["spdx"] != comp["spdx"]:
                out.append(f"{at}: {cid} spdx {comp['spdx']} but the matrix says {m['spdx']}")
            if m["redistribution"]["status"] != comp["redistribution"]:
                out.append(f"{at}: {cid} redistribution {comp['redistribution']} but the matrix says {m['redistribution']['status']}")
            if i == 0 and m.get("pinned_release") != entry["runtime_version"]:
                out.append(f"{at}: runtime_version {entry['runtime_version']} but the matrix pins {cid} at {m.get('pinned_release')}")
        # docs and example
        if not (root / entry["docs_url"]).is_file():
            out.append(f"{at}: docs_url {entry['docs_url']} does not exist")
        if entry["example_id"] is not None and entry["example_id"] not in manifest["examples"]:
            out.append(f"{at}: example_id {entry['example_id']} is not in examples")
    for ex_id, ex in manifest["examples"].items():
        if not (root / ex["path"]).is_file():
            out.append(f"example {ex_id}: path {ex['path']} does not exist")
    text = json.dumps(manifest)
    if re.search(r"(?<!not )open[ -]source", text, re.IGNORECASE):
        out.append("wording: the licence is 'source-available under the family licence'; never 'open source' (except in 'not open source')")
    return out


# ------------------------------------------------------------------------------------------------ the adapters' own manifests
def _constants(path: Path, names: Iterable[str]) -> Dict[str, str]:
    found: Dict[str, str] = {}
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in names:
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                found[node.targets[0].id] = node.value.value
    return found


def code_manifests(root: Path) -> Dict[str, Dict[str, Any]]:
    """What the adapters declare in code, keyed by adapter id: ``{adapter_version, mode, engine_version}``.

    The kit-based adapters are instantiated through their own manifest functions. ``qa-playwright`` is read from its module constants by parsing the
    source (importing it needs the pinned harness tree, which this check does not require)."""
    added = []
    for pkg in ("qa-adapter-kit", "qa-selenium", "qa-robot", "qa-appium"):
        src = str(root / "packages" / pkg / "src")
        if src not in sys.path:
            sys.path.insert(0, src)
            added.append(src)
    try:
        from qa_appium import android as ap_android, ios as ap_ios
        from qa_appium.adapter import interactive_manifest as appium_manifest
        from qa_robot.suite import suite_manifest as robot_suite
        from qa_selenium.adapter import interactive_manifest as selenium_interactive
        from qa_selenium.suite import suite_manifest as selenium_suite
        found: Dict[str, Dict[str, Any]] = {}
        for m in (selenium_interactive(), selenium_suite("/usr/bin/python3"), robot_suite("/usr/bin/python3"),
                  appium_manifest(ap_android.ADAPTER_ID), appium_manifest(ap_ios.ADAPTER_ID)):
            found[m.adapter_id] = {"adapter_version": m.adapter_version, "mode": m.adapter_class.value, "engine_version": m.framework.pinned_release,
                                   "engine_name": m.framework.name}
    finally:
        for src in added:
            sys.path.remove(src)
    pw = _constants(root / "packages" / "qa-playwright" / "src" / "qa_playwright" / "adapter.py", {"ADAPTER_ID", "ADAPTER_VERSION"})
    pw_extra = (_pyproject_extras(root, "packages/qa-playwright") or {}).get("project", {}).get("optional-dependencies", {}).get("browser", [])
    pw_pin = next((s.split("==", 1)[1] for s in pw_extra if s.startswith("playwright==")), None)
    found[pw["ADAPTER_ID"]] = {"adapter_version": pw["ADAPTER_VERSION"], "mode": "interactive", "engine_version": pw_pin, "engine_name": "playwright"}
    return found


def code_agreement_problems(manifest: Dict[str, Any], root: Path) -> List[str]:
    out: List[str] = []
    code = code_manifests(root)
    listed = set()
    for entry in manifest["engines"]:
        at = f"engine {entry['engine']}"
        modes = set()
        for adapter in entry["adapter_ids"]:
            listed.add(adapter)
            c = code.get(adapter)
            if c is None:
                out.append(f"{at}: adapter {adapter} is not declared in code")
                continue
            if c["adapter_version"] != entry["adapter_version"]:
                out.append(f"{at}: adapter {adapter} is version {c['adapter_version']} in code, {entry['adapter_version']} in the manifest")
            if c["engine_version"] != entry["runtime_version"]:
                out.append(f"{at}: adapter {adapter} pins engine version {c['engine_version']} in code, {entry['runtime_version']} in the manifest")
            modes.add(c["mode"])
        if modes != set(entry["execution_modes"]):
            out.append(f"{at}: execution modes are {sorted(modes)} in code, {sorted(entry['execution_modes'])} in the manifest")
    for adapter in sorted(set(code) - listed):
        out.append(f"adapter {adapter} is declared in code but is in no manifest entry")
    return out


# ------------------------------------------------------------------------------------------------ freshness
def _git(root: Path, *args: str) -> Tuple[int, str]:
    proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def resolve_main_ref(root: Path, wanted: Optional[str], main_branch: str) -> Optional[str]:
    for ref in ([wanted] if wanted else [f"origin/{main_branch}", main_branch]):
        if _git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")[0] == 0:
            return ref
    return None


def freshness_problems(manifest: Dict[str, Any], root: Path, main_ref: Optional[str] = None) -> List[str]:
    """Every commit the manifest relies on must be an ancestor of the main branch. A main ref that cannot be resolved is a finding, never a skip."""
    ref = resolve_main_ref(root, main_ref, manifest["main_branch"])
    if ref is None:
        return [f"freshness: cannot resolve the main branch ({main_ref or 'origin/' + manifest['main_branch']}); fetch it (full history) before checking"]
    out: List[str] = []
    for entry in manifest["engines"]:
        shas = {"last_verified_sha": entry["last_verified_sha"]}
        for ev in entry["evidence"]:
            for key in ("head_sha", "recorded_in_sha"):
                if key in ev:
                    shas[f"evidence {ev['id']} {key}"] = ev[key]
        for what, sha in shas.items():
            if sha is None:
                continue
            if _git(root, "cat-file", "-e", f"{sha}^{{commit}}")[0] != 0:
                out.append(f"freshness: engine {entry['engine']} {what} {sha[:12]} is not a commit of this repository (is the history complete?)")
            elif _git(root, "merge-base", "--is-ancestor", sha, ref)[0] != 0:
                out.append(f"freshness: engine {entry['engine']} {what} {sha[:12]} is not an ancestor of {ref}")
    return out


# ------------------------------------------------------------------------------------------------ generated document
def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _code(text: Any) -> str:
    return "`" + str(text).replace("`", "'") + "`"


def evidence_link(ev: Dict[str, Any]) -> str:
    if ev["kind"] == "ci-job":
        return f"[CI run {ev['run_id']}]({ev['run_url']}) (whole run green), [job {ev['job_id']}]({ev['url']}) ({_cell(ev['job_name'])}; {_cell(ev['tests'])})"
    return f"[{_cell(ev['path'])}]({_relative_from_docs(ev['path'])})"


def _relative_from_docs(path: str) -> str:
    return "../" + path


def render_docs(manifest: Dict[str, Any]) -> str:
    lines: List[str] = [GENERATED_NOTICE, "", "# ReDevOps QA: engine capability matrix", ""]
    dist = manifest["distribution"]
    lines += [
        "This page is generated from [`qa-capabilities.json`](../qa-capabilities.json), which is checked in CI against its schema, the repository's pins, the "
        "adapters' own manifests and the CI history. Every claim below points to evidence in this repository or to a named CI job. "
        f"Licence: {dist['licence_wording']}. {dist['note']}",
        "",
        "## What the test levels mean",
        "",
        "A test level says what kind of evidence stands behind an engine entry. It is not a readiness grade, and the order below is by closeness to a real "
        "device, not by how easily anyone can repeat the run.",
        "",
        "| Test level | What it means | What it does not mean |",
        "|---|---|---|",
    ]
    for level in LEVEL_ORDER:
        m = manifest["test_levels"][level]
        lines.append(f"| {_code(level)} | {_cell(m['meaning'])} | {_cell(m['does_not_mean'])} |")
    lines += ["", "## Matrix", "",
              "| Engine | Adapter | Engine version | Modes | Test level | Verified on | Last verified |",
              "|---|---|---|---|---|---|---|"]
    for e in manifest["engines"]:
        verified = "; ".join(f"{v['os_arch']} ({v['test_level']})" for v in e["os_arch"]) or "nowhere"
        when = f"{e['last_verified_date']} at `{e['last_verified_sha'][:12]}`" if e["last_verified_sha"] else "never"
        lines.append(f"| {_cell(e['display_name'])} | {_cell(', '.join(e['adapter_ids']))} {e['adapter_version']} | {e['runtime_version']} | "
                     f"{_cell(', '.join(e['execution_modes']))} | {_code(e['test_level'])} | {_cell(verified)} | {when} |")
    lines += ["", "Each `Last verified` commit is an ancestor of the main branch; for a local run it is the commit that records the run, because the tested tree "
              "is not recorded.", ""]
    lines += ["## Appium caveats", ""]
    lines += ["### Android", ""] + [f"* {c}" for c in manifest["caveats"]["appium_android"]]
    lines += ["", "### iOS", ""] + [f"* {c}" for c in manifest["caveats"]["appium_ios"]]
    lines += ["", "### Both", ""] + [f"* {c}" for c in manifest["caveats"]["appium_general"]]
    lines += ["", "## Engines", ""]
    for e in manifest["engines"]:
        lines += [f"### {e['display_name']}", "", f"* Engine id: {_code(e['engine'])}; adapters: {', '.join(_code(a) for a in e['adapter_ids'])}; "
                  f"adapter version {e['adapter_version']}; engine version {e['runtime_version']}.",
                  f"* Test level: {_code(e['test_level'])}. Scope: {e['test_level_scope']}.",
                  f"* {e['summary']}",
                  f"* Execution modes: {', '.join(e['execution_modes'])}.",
                  f"* Install: {e['install_method']['method']} of {', '.join(_code(p) for p in e['install_method']['packages'])}"
                  + (f" with extras {', '.join(_code(x) for x in e['install_method']['extras'])}" if e["install_method"]["extras"] else "")
                  + f". {e['install_method']['note']}",
                  f"* Documentation: [{e['docs_url']}]({_relative_from_docs(e['docs_url'])})."
                  + (f" Example: {_code(e['example_id'])} ([{manifest['examples'][e['example_id']]['path']}]({_relative_from_docs(manifest['examples'][e['example_id']]['path'])}))."
                     if e["example_id"] else " No example exists."), ""]
        lines += ["Verified on:", ""]
        if e["os_arch"]:
            lines += ["| Host | Environment | Level | Scope |", "|---|---|---|---|"]
            for v in e["os_arch"]:
                lines.append(f"| {v['os_arch']} | {_cell(v['environment'])} | {_code(v['test_level'])} | {_cell(v['scope'])} |")
        else:
            lines.append("Nowhere: no run exists.")
        lines += ["", "Dependencies:", "", "| Dependency | Kind | Pin | Provided by | Note |", "|---|---|---|---|---|"]
        for d in e["dependencies"]:
            lines.append(f"| {_cell(d['name'])} | {d['kind']} | {_cell(d['pin_literal'] if d['pin_literal'] else 'not pinned here')} | {d['provided_by']} | {_cell(d['note'])} |")
        lines += ["", "Evidence:", ""]
        for ev in e["evidence"]:
            if ev["kind"] == "local-run":
                lines.append(f"* {evidence_link(ev)}: local run observed on {ev['observed_on']}, {_cell(ev['environment'])}; {ev['runs']} run(s); {_cell(ev['result'])}. {_cell(ev['claim'])}.")
            elif ev["kind"] == "ci-job":
                lines.append(f"* {evidence_link(ev)}: {_cell(ev['claim'])}. Head commit `{ev['head_sha'][:12]}`, completed {ev['completed_on']}.")
            else:
                lines.append(f"* {evidence_link(ev)}: {_cell(ev['claim'])}.")
        lines += ["", "Limitations:", ""] + [f"* {x}" for x in e["limitations"]]
        comps = "; ".join(f"{c['matrix_component']} {c['spdx']} ({c['redistribution']})" for c in e["license"]["components"])
        lines += ["", f"Licences: the adapter is {e['license']['adapter_wording']} ({e['license']['adapter_spdx']}). Components: {comps}. Technical triage in "
                  "[third_party](../third_party/README.md), not legal advice.", ""]
    return "\n".join(lines).rstrip("\n") + "\n"


def docs_problems(manifest: Dict[str, Any], root: Path) -> List[str]:
    current = read(root, DOCS)
    if current is None:
        return [f"docs: {DOCS} is missing (run: python tools/check_capabilities.py --write-docs)"]
    if current != render_docs(manifest):
        return [f"docs: {DOCS} differs from the document generated from {MANIFEST} (run: python tools/check_capabilities.py --write-docs)"]
    return []


# ------------------------------------------------------------------------------------------------ opt-in network checks
def _api_get(url: str) -> Any:
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    credential = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if credential:
        request.add_header("Authorization", "Bearer " + credential)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def verify_ci_problems(manifest: Dict[str, Any], fetch: Callable[[str], Any] = _api_get) -> List[str]:
    """Re-check every CI evidence item against the GitHub API (explicit, network): run head commit, run and job conclusion, job name."""
    out: List[str] = []
    repo = manifest["repository"]
    cache: Dict[int, Any] = {}
    for entry in manifest["engines"]:
        for ev in entry["evidence"]:
            if ev["kind"] != "ci-job":
                continue
            at = f"engine {entry['engine']} evidence {ev['id']}"
            try:
                if ev["run_id"] not in cache:
                    run = fetch(f"https://api.github.com/repos/{repo}/actions/runs/{ev['run_id']}")
                    jobs = fetch(f"https://api.github.com/repos/{repo}/actions/runs/{ev['run_id']}/jobs?per_page=100")
                    cache[ev["run_id"]] = (run, jobs)
                run, jobs = cache[ev["run_id"]]
            except Exception as exc:  # noqa: BLE001 - any API failure is a finding
                out.append(f"{at}: cannot read run {ev['run_id']} ({type(exc).__name__})")
                continue
            if run.get("head_sha") != ev["head_sha"]:
                out.append(f"{at}: run {ev['run_id']} head is {run.get('head_sha')}, not {ev['head_sha']}")
            if run.get("conclusion") != ev["run_conclusion"]:
                out.append(f"{at}: run {ev['run_id']} as a whole concluded {run.get('conclusion')}, not {ev['run_conclusion']} (a visitor following the link must not see a red run)")
            job = next((j for j in jobs.get("jobs", []) if j.get("id") == ev["job_id"]), None)
            if job is None:
                out.append(f"{at}: run {ev['run_id']} has no job {ev['job_id']}")
                continue
            if job.get("conclusion") != ev["conclusion"]:
                out.append(f"{at}: job {ev['job_id']} concluded {job.get('conclusion')}, not {ev['conclusion']}")
            if not str(job.get("name", "")).startswith(ev["job_name"]):
                out.append(f"{at}: job {ev['job_id']} is named {job.get('name')!r}")
            if str(job.get("completed_at", ""))[:10] != ev["completed_on"]:
                out.append(f"{at}: job {ev['job_id']} completed on {str(job.get('completed_at', ''))[:10]}, not {ev['completed_on']}")
    return out


def cross_check_problems(schema: Dict[str, Any], instance: Any) -> List[str]:
    """Differential check against the full ``jsonschema`` package (installed by the dedicated CI step; a missing package is a finding)."""
    try:
        import jsonschema
    except ImportError:
        return ["cross-check: the jsonschema package is not installed"]
    jsonschema.Draft202012Validator.check_schema(schema)
    full = jsonschema.Draft202012Validator(schema)
    out: List[str] = []
    for label, doc in [("the manifest", instance)] + list(qa_jsonschema.mutations(instance)):
        mine = not qa_jsonschema.validate(doc, schema)
        theirs = full.is_valid(doc)
        if mine != theirs:
            out.append(f"cross-check: {label}: the strict validator says {'valid' if mine else 'invalid'}, jsonschema says {'valid' if theirs else 'invalid'}")
            if len(out) >= 10:
                break
    return out


# ------------------------------------------------------------------------------------------------ command line
def check_all(root: Path, *, main_ref: Optional[str] = None, freshness: bool = True) -> List[str]:
    manifest = load_json(root / MANIFEST)
    schema = load_json(root / SCHEMA)
    findings = schema_problems(manifest, schema)
    if findings:
        return findings
    findings += semantic_problems(manifest, root)
    findings += code_agreement_problems(manifest, root)
    findings += docs_problems(manifest, root)
    if freshness:
        findings += freshness_problems(manifest, root, main_ref)
    return findings


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=str(HERE.parent))
    ap.add_argument("--main-ref", default=None, help="the ref freshness is checked against (default origin/main, then main)")
    ap.add_argument("--no-freshness", action="store_true", help="skip the ancestor check (a clone without the main branch); never used in CI")
    ap.add_argument("--write-docs", action="store_true", help=f"regenerate {DOCS} from {MANIFEST}")
    ap.add_argument("--verify-ci", action="store_true", help="re-check every CI evidence item against the GitHub API (network)")
    ap.add_argument("--cross-check", action="store_true", help="compare the strict validator with the full jsonschema package (needs it installed)")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    if args.write_docs:
        (root / DOCS).parent.mkdir(parents=True, exist_ok=True)
        (root / DOCS).write_text(render_docs(load_json(root / MANIFEST)), encoding="utf-8")
        print(f"wrote {DOCS}")
        return 0
    findings = check_all(root, main_ref=args.main_ref, freshness=not args.no_freshness)
    if args.verify_ci:
        findings += verify_ci_problems(load_json(root / MANIFEST))
    if args.cross_check:
        findings += cross_check_problems(load_json(root / SCHEMA), load_json(root / MANIFEST))
    for f in findings:
        print(f"FAIL {f}")
    if findings:
        return 1
    print("OK " + MANIFEST + (" (freshness skipped)" if args.no_freshness else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
