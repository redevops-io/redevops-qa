#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The developer checkout step the README documents (audit item P1-5): fetch the exact upstream commits that
``pins.toml`` pins into the ``.pinned/`` source paths, and verify them the way CI does.

    python tools/fetch_pins.py                 # every pin set in pins.toml
    python tools/fetch_pins.py --pin-set c4    # just one

For each set the tool reads (repo, commit, path) from the bridge's own pins module — nothing is hard-coded here
either — clones or updates the tree, detaches at the pinned commit, and then runs the same verification CI runs:
``python -m redevops_qa_bridge.pins --verify-trees --require-git`` (HEAD equals the pin, the tree is clean, the
distribution digest matches, every vector file matches). A tree that verifies is imported from its path by the
test conftests (``redevops_qa_bridge.deps.prepare_paths``); nothing is installed from it. The fetch is plain
``git`` over HTTPS: no token, no secret, no credential of any kind.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BRIDGE_SRC = ROOT / "packages" / "qa-bridge" / "src"


def _run(argv: list[str], what: str, env: "dict | None" = None) -> str:
    proc = subprocess.run(argv, cwd=ROOT, env=env, text=True, capture_output=True)
    if proc.returncode:
        sys.exit(f"fetch_pins: {what} failed (exit {proc.returncode}):\n{proc.stderr.strip() or proc.stdout.strip()}")
    return proc.stdout


def _bridge_env(pin_set: str) -> "dict[str, str]":
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(BRIDGE_SRC)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    env["REDEVOPS_QA_PIN_SET"] = pin_set
    return env


def _fields(pin_set: str) -> "dict[str, str]":
    out = _run([sys.executable, "-m", "redevops_qa_bridge.pins", "--github-output"],
               f"read the pins of set {pin_set!r}", _bridge_env(pin_set))
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def _fetch(kind: str, repo: str, commit: str, rel_path: str) -> None:
    target = ROOT / rel_path
    url = f"https://github.com/{repo}"
    if (target / ".git").is_dir():
        _run(["git", "-C", str(target), "fetch", "--all", "--tags"], f"update {rel_path} from {url}")
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", url, str(target)], f"clone {url} into {rel_path}")
    _run(["git", "-C", str(target), "checkout", "--quiet", "--detach", commit],
         f"detach {rel_path} at {commit} (if the commit is unreachable — a force-pushed upstream — delete {rel_path} and rerun)")
    print(f"fetch_pins: {kind}: {repo} at {commit} -> {rel_path}")


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description="fetch and verify the pinned upstream trees named by pins.toml")
    parser.add_argument("--pin-set", action="append", dest="sets", metavar="NAME",
                        help="a pin set to fetch; repeatable. Default: every set declared in pins.toml.")
    args = parser.parse_args(argv)
    pins = tomllib.loads((ROOT / "pins.toml").read_text(encoding="utf-8"))
    all_sets = list(pins["sets"])
    sets = args.sets or all_sets
    unknown = [s for s in sets if s not in all_sets]
    if unknown:
        sys.exit(f"fetch_pins: pins.toml has no set(s) {unknown}; it has {all_sets}")
    for pin_set in sets:
        fields = _fields(pin_set)
        for kind in ("contracts", "harness_qa"):
            _fetch(kind, fields[f"{kind}_repo"], fields[f"{kind}_commit"], fields[f"{kind}_path"])
        _run([sys.executable, "-m", "redevops_qa_bridge.pins", "--verify-trees", "--require-git"],
             f"verify the fetched trees of pin set {pin_set!r}", _bridge_env(pin_set))
        print(f"fetch_pins: pin set {pin_set!r} verified (HEAD, clean tree, distribution digest, vector digests)")
    print("fetch_pins: the checkout is ready — run pytest (the conftests put these trees on sys.path)")
    return 0


if __name__ == "__main__":
    sys.exit(main())