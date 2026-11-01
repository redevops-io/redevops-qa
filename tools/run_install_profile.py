#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Run the documented steps of one install profile, exactly as the configurator would print them.

The steps are not written here: they come out of ``qa_install_config.generate`` for the profile's own engines, the stated host and channel, so what CI
runs is the configuration a visitor would be given. Each step runs as an argument vector (no shell) in a scrubbed environment (a throwaway HOME, the
current PATH, a fixed locale). The source phase is the clone and the checkout of the pinned commit; a CI job that already has that commit checked out
passes ``--phases install,smoke,check`` and this tool then verifies that the checkout is exactly the pinned commit with a clean tree. Manual steps are
printed and never run. Any non-zero exit, a missing evidence file or a venv that is still there after the uninstall phase fails the run.

Usage: ``python tools/run_install_profile.py --profile ID --host OS_ARCH --channel stable|experimental --work DIR --checkout DIR [--phases ...] [--param name=value]``.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import qa_install_config as gen  # noqa: E402


def selection_for(profile: Dict, args, params: Dict[str, str]) -> Dict:
    sel = {"engines": profile["engines"], "target": profile["target"], "host": args.host, "verifier": False, "channel": args.channel,
           "venv_dir": str(Path(args.work) / "venv"), "evidence_dir": str(Path(args.work) / "evidence"), "checkout_dir": str(Path(args.checkout))}
    sel.update(params)
    return sel


def run(argv: List[str], env: Dict[str, str], cwd: str) -> int:
    return subprocess.run(argv, env=env, cwd=cwd).returncode


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--profile", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--channel", required=True, choices=gen.CHANNELS)
    ap.add_argument("--work", required=True, help="directory the steps run in; the venv and the evidence go here")
    ap.add_argument("--checkout", required=True, help="where the repository is (or will be cloned) at the pinned commit")
    ap.add_argument("--phases", default="install,smoke,check")
    ap.add_argument("--param", action="append", default=[], help="name=value for a parameter the profile declares")
    ap.add_argument("--profiles-file", default=str(HERE.parent / "qa-install-profiles.json"))
    ap.add_argument("--capabilities-file", default=str(HERE.parent / "qa-capabilities.json"))
    args = ap.parse_args(argv)
    profiles = json.loads(Path(args.profiles_file).read_text(encoding="utf-8"))
    capabilities = json.loads(Path(args.capabilities_file).read_text(encoding="utf-8"))
    profile = next((p for p in profiles["profiles"] if p["id"] == args.profile), None)
    if profile is None:
        print(f"FAIL unknown profile {args.profile}")
        return 2
    params = dict(p.split("=", 1) for p in args.param)
    result = gen.generate(selection_for(profile, args, params), capabilities, profiles)
    for w in result["warnings"]:
        print(f"warning {w['code']}: {w['message']}")
    if not result["ok"]:
        for e in result["errors"]:
            print(f"FAIL {e['code']} ({e['field']}): {e['message']}")
        return 2
    config = result["config"]
    phases = [p for p in args.phases.split(",") if p]
    if any(p not in gen.PHASES for p in phases):
        print(f"FAIL phases must be among {', '.join(gen.PHASES)}")
        return 2
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    home = tempfile.mkdtemp(prefix="home-", dir=str(work))
    base_env = {"HOME": home, "PATH": os.environ["PATH"], "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
    checkout = Path(args.checkout)
    commit = config["manifest"]["source"]["commit"]
    if "source" not in phases:
        head = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True, text=True)
        dirty = subprocess.run(["git", "-C", str(checkout), "status", "--porcelain"], capture_output=True, text=True)
        if head.returncode != 0 or head.stdout.strip() != commit:
            print(f"FAIL the checkout at {checkout} is not at the pinned commit {commit}")
            return 1
        if dirty.stdout.strip():
            print("FAIL the checkout has local changes")
            return 1
        print(f"checkout verified: HEAD is the pinned commit {commit}, clean tree")
    for phase in phases:
        print(f"== {phase}")
        for step in config["steps"][phase]:
            print(f"+ [{step['id']}] {step['title']}\n  {step['display']}", flush=True)
            if step["manual"]:
                print("  (manual step: printed, not run)")
                continue
            code = run(step["argv"], {**base_env, **step["env"]}, str(work))
            if code != 0:
                print(f"FAIL step {step['id']} exited {code}")
                return 1
        if phase == "smoke":
            missing = [f for f in config["evidence"]["files"] if not (Path(config["evidence"]["directory"]) / f).is_file()]
            if missing:
                print(f"FAIL evidence files missing: {missing}")
                return 1
    if "uninstall" in phases and Path(config["manifest"]["params"]["venv_dir"]).exists():
        print("FAIL the virtual environment is still there after the uninstall phase")
        return 1
    print(f"OK profile {args.profile} on {args.host}: phases {', '.join(phases)}")
    print(f"manifest digest {config['manifest_digest']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
