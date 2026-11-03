#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The install configuration generator: a pure, deterministic function from a selection to a validated configuration.

``generate(selection, capabilities, profiles)`` takes plain data (the parsed ``qa-capabilities.json`` and ``qa-install-profiles.json``) and returns
plain data. It reads no file, no environment variable and no clock, runs no command, and never interpolates unvalidated text: every value a user
supplies is checked against a closed vocabulary or a strict pattern first, and every command is an argument vector taken from a profile with only the
placeholders the profile declares replaced. It accepts no secret: any field that is not in the allowed set is refused, and a field whose name looks
like a credential is refused by name.

It is written to be ported line for line to the static installer page; ``tests/vectors/install-config-vectors.json`` is its specification
(selection in, expected output out). Output shape::

    {"ok": bool, "errors": [{"code", "field", "message"}], "warnings": [{"code", "message"}], "config": null | {...}}

``code`` and ``field`` are the contract; ``message`` is for people. Standard library only.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional

SELECTION_FIELDS = ("engines", "target", "host", "verifier", "channel")
PARAM_FIELDS = ("venv_dir", "evidence_dir", "checkout_dir", "chrome_binary", "chromedriver_path", "bundle_dir", "install_dir")
REQUIRED_FIELDS = SELECTION_FIELDS
TARGETS = ("local-python", "docker-compose", "kubernetes-helm")
HOSTS = ("linux-x86_64", "linux-arm64", "macos-arm64", "macos-x86_64", "windows-x86_64", "windows-wsl-x86_64")
CHANNELS = ("stable", "experimental")
PHASES = ("source", "install", "smoke", "check", "uninstall")
SECRET_NAME = re.compile(r"secret|token|passw|credential|api[_-]?key|private[_-]?key|auth", re.IGNORECASE)
SAFE_ARG = re.compile(r"[A-Za-z0-9_@%+=:,./-]+")
PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")
SEGMENT = re.compile(r"[A-Za-z0-9._-]+")
STATUS_RANK = {"planned": 0, "experimental": 1, "verified": 2}
MANIFEST_SCHEMA = "redevops-qa/install-manifest/1"


# ------------------------------------------------------------------------------------------------ small pure helpers
def quote_arg(arg: str) -> str:
    """POSIX shell quoting of one argument: left alone when it only has safe characters, else single-quoted with ``'`` written as ``'"'"'``."""
    if arg and SAFE_ARG.fullmatch(arg):
        return arg
    return "'" + arg.replace("'", "'\"'\"'") + "'"


def display(argv: List[str], env: Optional[Dict[str, str]] = None) -> str:
    """The step as one line for people to read and copy: environment assignments first (sorted by name), then the quoted argument vector."""
    prefix = [f"{name}={quote_arg(value)}" for name, value in sorted((env or {}).items())]
    return " ".join(prefix + [quote_arg(a) for a in argv])


def canonical_json(value: Any) -> str:
    """Sorted keys, no whitespace, non-ASCII escaped: the form the manifest digest is computed over."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def valid_path(value: Any, kind: str) -> bool:
    """``dir-path``: a relative or absolute POSIX path of plain segments (letters, digits, ``.``, ``_``, ``-``), at most 256 characters, no segment made
    only of dots, no empty segment, no leading ``-`` (it would be read as an option). ``abs-path``: the same, and absolute."""
    if not isinstance(value, str) or not 1 <= len(value) <= 256 or value.startswith("-"):
        return False            # a leading '-' would be read as an option by the command the path is an argument of
    absolute = value.startswith("/")
    if kind == "abs-path" and not absolute:
        return False
    segments = (value[1:] if absolute else value).split("/")
    return bool(segments) and all(SEGMENT.fullmatch(s) and not set(s) <= {"."} for s in segments)


def _err(errors: List[Dict[str, str]], code: str, field: str, message: str) -> None:
    errors.append({"code": code, "field": field, "message": message})


def _warn(warnings: List[Dict[str, str]], code: str, message: str) -> None:
    warnings.append({"code": code, "message": message})


def _result(errors, warnings, config=None) -> Dict[str, Any]:
    return {"ok": not errors, "errors": errors, "warnings": warnings, "config": config if not errors else None}


def substitute(text: str, values: Dict[str, str]) -> str:
    """Replace ``{name}`` placeholders. A placeholder with no value is a programming error in the profile (the profile check refuses it) and raises."""
    def one(match):
        name = match.group(1)
        if name not in values:
            raise KeyError(name)
        return values[name]
    return PLACEHOLDER.sub(one, text)


# ------------------------------------------------------------------------------------------------ the generator
def _check_shape(selection: Any, errors: List[Dict[str, str]], engine_ids: List[str]) -> None:
    if not isinstance(selection, dict):
        _err(errors, "INVALID_SELECTION", "", "the selection must be an object")
        return
    for key in sorted(selection):
        if key in SELECTION_FIELDS or key in PARAM_FIELDS:
            continue
        if SECRET_NAME.search(key):
            _err(errors, "SECRETS_NOT_ACCEPTED", key, "this generator accepts no secret, token or credential of any kind")
        else:
            _err(errors, "UNKNOWN_FIELD", key, "not a field of the selection")
    for key in REQUIRED_FIELDS:
        if key not in selection:
            _err(errors, "MISSING_FIELD", key, "required")
    engines = selection.get("engines")
    if "engines" in selection:
        if not isinstance(engines, list) or not all(isinstance(e, str) for e in engines):
            _err(errors, "INVALID_TYPE", "engines", "a list of engine ids")
        elif not engines:
            _err(errors, "NO_ENGINES", "engines", "select at least one engine")
        else:
            if len(set(engines)) != len(engines):
                _err(errors, "DUPLICATE_ENGINE", "engines", "an engine is listed twice")
            for e in sorted(set(engines)):
                if e not in engine_ids:
                    _err(errors, "UNKNOWN_ENGINE", "engines", f"unknown engine {e[:40]!r}; the engines are {', '.join(engine_ids)}")
    if "target" in selection and (not isinstance(selection["target"], str) or selection["target"] not in TARGETS):
        _err(errors, "UNKNOWN_TARGET", "target", f"the targets are {', '.join(TARGETS)}")
    if "host" in selection and (not isinstance(selection["host"], str) or selection["host"] not in HOSTS):
        _err(errors, "UNKNOWN_HOST", "host", f"the hosts are {', '.join(HOSTS)}")
    if "verifier" in selection and not isinstance(selection["verifier"], bool):
        _err(errors, "INVALID_TYPE", "verifier", "true or false")
    if "channel" in selection and (not isinstance(selection["channel"], str) or selection["channel"] not in CHANNELS):
        _err(errors, "UNKNOWN_CHANNEL", "channel", f"the channels are {', '.join(CHANNELS)}")
    for key in PARAM_FIELDS:
        if key in selection and not isinstance(selection[key], str):
            _err(errors, "INVALID_TYPE", key, "a string")


def generate(selection: Any, capabilities: Dict[str, Any], profiles: Dict[str, Any]) -> Dict[str, Any]:
    errors: List[Dict[str, str]] = []
    warnings: List[Dict[str, str]] = []
    engine_ids = [e["engine"] for e in capabilities["engines"]]
    # stage 1: the shape of the selection (every problem is reported)
    _check_shape(selection, errors, engine_ids)
    if errors:
        return _result(errors, warnings)
    engines = sorted(selection["engines"])
    target, host, channel = selection["target"], selection["host"], selection["channel"]
    # stage 2: refusals that do not depend on a profile (every problem is reported)
    if selection["verifier"] and not any(p.get("verifier") and p["status"] != "planned" and p["target"] == target and sorted(p["engines"]) == engines for p in profiles["profiles"]):
        _err(errors, "VERIFIER_UNAVAILABLE", "verifier", profiles["verifier"]["reason"])
    tinfo = profiles["targets"][target]
    if tinfo["status"] != "available":
        _err(errors, "TARGET_NOT_AVAILABLE", "target", tinfo["disabled_reason"])
    if "appium-ios" in engines and not host.startswith("macos-"):
        _err(errors, "IOS_NEEDS_MACOS", "host", "iOS automation needs macOS with Xcode, WebDriverAgent and a supported simulator or device; a Linux, Windows or container "
                                                   "host is not an iOS solution")
    if errors:
        return _result(errors, warnings)
    # stage 3: the profile (the first problem is reported)
    on_target = [p for p in profiles["profiles"] if p["target"] == target]
    matching = [p for p in on_target if sorted(p["engines"]) == engines]
    if not matching:
        offered = sorted({", ".join(sorted(p["engines"])) for p in on_target})
        _err(errors, "NO_PROFILE_FOR_ENGINES", "engines", "no profile covers exactly this set of engines; combinations are not tested. Engine sets with a profile: "
                                                         + "; ".join(offered))
        return _result(errors, warnings)
    profile = matching[0]
    if profile["status"] == "planned":
        _err(errors, "PROFILE_PLANNED", "engines", profile["disabled_reason"])
        return _result(errors, warnings)
    host_entry = next((h for h in profile["hosts"] if h["os_arch"] == host), None)
    if host_entry is None or host_entry["status"] == "planned":
        reason = host_entry["disabled_reason"] if host_entry else "no step list was written or run for this host"
        _err(errors, "HOST_NOT_SUPPORTED", "host", f"{reason}. Hosts with a profile: " + ", ".join(h["os_arch"] for h in profile["hosts"] if h["status"] != "planned"))
        return _result(errors, warnings)
    status = min(profile["status"], host_entry["status"], key=lambda s: STATUS_RANK[s])
    if status != "verified" and channel != "experimental":
        _err(errors, "NEEDS_EXPERIMENTAL_CHANNEL", "channel", f"this profile on this host is {status}, not verified; select the experimental channel to use it")
        return _result(errors, warnings)
    # parameters: the ones the profile declares, validated; anything else is refused
    values: Dict[str, str] = {}
    for name, spec in sorted(profile["params"].items()):
        if name in selection:
            if not valid_path(selection[name], spec["kind"]):
                _err(errors, "INVALID_PARAM", name, f"must be a {'absolute ' if spec['kind'] == 'abs-path' else ''}POSIX path of letters, digits, '.', '_', '-' and '/', at most 256 characters, not starting with '-'")
            else:
                values[name] = selection[name]
        elif spec["required"]:
            _err(errors, "MISSING_PARAM", name, "required by this profile: " + spec["description"])
        else:
            values[name] = spec["default"]
    for name in PARAM_FIELDS:
        if name in selection and name not in profile["params"]:
            _err(errors, "UNEXPECTED_PARAM", name, "this profile has no such parameter")
    if errors:
        return _result(errors, warnings)
    values["source_commit"] = profiles["source"]["pinned_commit"]
    # warnings
    bundle = profile.get("kind") == "bundle"
    if bundle:
        _warn(warnings, "SOURCE_IS_A_BUNDLE_ARCHIVE", "no bundle is published: build the archive from a checkout of the repository with tools/build_bundle.py or take the archive of a workflow run, and compare its "
                                                         "sha256 with a value you obtained from somewhere its producer does not control; the digest file next to it is only as good as where you got it")
    else:
        _warn(warnings, "SOURCE_IS_A_CHECKOUT", "there is no release tag and no package-registry package: the install is a clone of the repository at the pinned commit")
    if status != "verified" and bundle:
        _warn(warnings, "EXPERIMENTAL_PROFILE", f"this profile on this host is {status}: CI runs its steps from the bundle a job of the same workflow builds, and no run on the main branch is recorded for it yet")
    elif status != "verified":
        _warn(warnings, "EXPERIMENTAL_PROFILE", f"this profile on this host is {status}: its steps were not run end to end in CI for this host")
    if host_entry["status"] != "verified" and profile["status"] == "verified":
        _warn(warnings, "HOST_NOT_VERIFIED", f"the profile is verified on {', '.join(h['os_arch'] for h in profile['hosts'] if h['status'] == 'verified')} only")
    if "appium-android" in engines:
        _warn(warnings, "DEVICE_NOT_BUNDLED", "no device, emulator, Android SDK or Appium server is bundled or installed by these steps; a real session needs a "
                                              "device worker the operator provides")
    if profile.get("verifier"):
        _warn(warnings, "VERIFIER_INCLUDED", "this profile installs and runs `redevops-qa verify`, which recomputes the verdicts from a run's evidence bundle in a separate process; it is not an independent "
                                             "implementation of the harness, the chain inside a bundle is unkeyed (only an anchor obtained elsewhere helps), and a verified run does not show that the application is correct")
    else:
        _warn(warnings, "NATIVE_RESULT_IS_NOT_A_VERDICT", "the engine's own pass or fail is not an independent verdict; no verifier is installed")
    # the configuration
    steps = {}
    for phase in PHASES:
        steps[phase] = []
        for step in profile["steps"][phase]:
            argv = [substitute(a, values) for a in step["argv"]]
            env = {k: substitute(v, values) for k, v in sorted(step.get("env", {}).items())}
            steps[phase].append({"id": step["id"], "title": step["title"], "argv": argv, "env": env, "manual": step.get("manual", False),
                                 "display": display(argv, env)})
    cap_by_engine = {e["engine"]: e for e in capabilities["engines"]}
    manifest = {
        "schema": MANIFEST_SCHEMA, "profile": profile["id"], "profile_status": profile["status"], "host_status": host_entry["status"], "target": target,
        "host": host, "channel": channel, "verifier": {"enabled": bool(profile.get("verifier"))},
        "source": ({"repository": profiles["source"]["repository"], "commit": None, "kind": "bundle-archive"} if bundle
                   else {"repository": profiles["source"]["repository"], "commit": profiles["source"]["pinned_commit"]}),
        "engines": [{"engine": e, "adapter_version": cap_by_engine[e]["adapter_version"], "engine_version": cap_by_engine[e]["runtime_version"],
                     "test_level": cap_by_engine[e]["test_level"]} for e in engines],
        "pins": {"python": profile["python"]["version"], "pip": [f"{p['name']}=={p['version']}" for p in profile["pip_pins"]]},
        "params": {k: values[k] for k in sorted(values) if k != "source_commit"},
    }
    config = {
        "profile": profile["id"], "title": profile["title"], "status": status, "target": target, "host": host, "channel": channel,
        "prerequisites": list(profile["prerequisites"]) + list(host_entry["prerequisites"]),
        "steps": steps,
        "evidence": {"directory": values["evidence_dir"], "files": list(profile["evidence"]["files"]), "description": profile["evidence"]["description"]},
        "uninstall_note": profile["uninstall_note"],
        "limitations": list(profile["limitations"]),
        "manifest": manifest, "manifest_digest": digest(manifest),
    }
    return _result(errors, warnings, config)


# ------------------------------------------------------------------------------------------------ vectors and a small command line
def _vector_expected(result: Dict[str, Any]) -> Dict[str, Any]:
    return {"ok": result["ok"], "errors": [{"code": e["code"], "field": e["field"]} for e in result["errors"]],
            "warnings": [w["code"] for w in result["warnings"]], "config": result["config"]}


def update_vectors(vectors: Dict[str, Any], capabilities: Dict[str, Any], profiles: Dict[str, Any]) -> Dict[str, Any]:
    """Recompute every ``expected`` from the selections, the helper vectors included. The result is reviewed in the diff; tests also assert the key
    outcomes independently so that a wrong regeneration cannot pass silently."""
    out = json.loads(json.dumps(vectors))
    for v in out["vectors"]:
        v["expected"] = _vector_expected(generate(v["selection"], capabilities, profiles))
    for q in out["quote_vectors"]:
        q["quoted"] = quote_arg(q["arg"])
    for c in out["canonical_json_vectors"]:
        c["canonical"] = canonical_json(c["value"])
        c["digest"] = digest(c["value"])
    return out


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import sys
    from pathlib import Path
    ap = argparse.ArgumentParser(description="Generate an install configuration from a selection (JSON on stdin or --selection FILE).")
    ap.add_argument("--capabilities", default="qa-capabilities.json")
    ap.add_argument("--profiles", default="qa-install-profiles.json")
    ap.add_argument("--selection", default="-")
    ap.add_argument("--update-vectors", metavar="FILE", help="rewrite the expected outputs of a vectors file in place")
    args = ap.parse_args(argv)
    capabilities = json.loads(Path(args.capabilities).read_text(encoding="utf-8"))
    profiles = json.loads(Path(args.profiles).read_text(encoding="utf-8"))
    if args.update_vectors:
        path = Path(args.update_vectors)
        path.write_text(json.dumps(update_vectors(json.loads(path.read_text(encoding="utf-8")), capabilities, profiles), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return 0
    raw = sys.stdin.read() if args.selection == "-" else Path(args.selection).read_text(encoding="utf-8")
    result = generate(json.loads(raw), capabilities, profiles)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
