#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Check what the public CI demo produced against what its seeded defect must produce, and what a second, separate verification says about the kept bundle.

    python -I tools/check_demo_outcome.py run    --defect none|discount|settings --exit-code N --output demo.out --evidence-root DIR --anchor-out FILE
    python -I tools/check_demo_outcome.py verify --defect none|discount|settings --exit-code N --result verify.json

``run``: the demo's exit status, the outcome in the bundle's report.json (VERIFIED or FAILED), which lane failed (the Robot lane for ``discount``, the Playwright lane for
``settings``, none for ``none``) and that every other assertion was verified, and the manifest digest the demo printed (the value to publish as the anchor) against the sha256 of the
bundle's bundle-manifest.json. It prints the anchor and writes it, with the plan digest and the run id, to ``--anchor-out``.
``verify``: the JSON that ``redevops-qa verify --json`` printed in the second job: the bundle accepted, no finding, the supplied anchor and plan digest matched, every verdict
recomputed and in agreement with the report, the outcome the same as the demo's, and the exit status the demo's.

Standard library only, so it can run in a clean interpreter away from the checkout. Exit status 0 when everything holds, 1 with the reasons on standard error, 2 for a usage error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Sequence

EXPECT = {
    "none": {"exit": 0, "outcome": "VERIFIED", "reason": "ALL_ASSERTIONS_VERIFIED", "failed_lane": None, "native": {"browser": "NATIVE_PASS", "robot": "NATIVE_PASS"}},
    "discount": {"exit": 1, "outcome": "FAILED", "reason": "ASSERTION_FAILED", "failed_lane": "robot", "native": {"browser": "NATIVE_PASS", "robot": "NATIVE_FAIL"}},
    "settings": {"exit": 1, "outcome": "FAILED", "reason": "ASSERTION_FAILED", "failed_lane": "browser", "native": {"browser": "NATIVE_FAIL", "robot": "NATIVE_PASS"}},
}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _lane_states(report: dict) -> Dict[str, List[str]]:
    states: Dict[str, List[str]] = {}
    for r in report["accounting"]["results"]:
        states.setdefault(r["lane_id"], []).append(r["verdict"]["state"])
    return states


def check_run(defect: str, exit_code: int, output: str, evidence_root: Path) -> "tuple[List[str], dict]":
    want = EXPECT[defect]
    problems: List[str] = []
    if exit_code != want["exit"]:
        problems.append(f"the demo exited {exit_code}, expected {want['exit']}")
    bundles = sorted(p for p in evidence_root.iterdir() if p.is_dir()) if evidence_root.is_dir() else []
    if len(bundles) != 1:
        return problems + [f"expected one bundle directory under {evidence_root.name}, found {len(bundles)}"], {}
    bundle = bundles[0]
    try:
        report = json.loads((bundle / "report.json").read_text(encoding="utf-8"))
        manifest_bytes = (bundle / "bundle-manifest.json").read_bytes()
    except (OSError, ValueError) as exc:
        return problems + [f"the bundle cannot be read ({type(exc).__name__})"], {}
    verdict = report["verdict"]
    if verdict["outcome"] != want["outcome"] or verdict["reason_code"] != want["reason"]:
        problems.append(f"the outcome is {verdict['outcome']} ({verdict['reason_code']}), expected {want['outcome']} ({want['reason']})")
    states = _lane_states(report)
    if sorted(states) != ["browser", "robot"]:
        problems.append(f"expected the lanes browser and robot, found {sorted(states)}")
    acc = report["accounting"]
    if acc["unaccounted"] != 0 or acc["inconclusive"] != 0 or acc["frozen"] != acc["verified"] + acc["failed"]:
        problems.append(f"the accounting is not closed: {({k: acc[k] for k in ('frozen', 'verified', 'failed', 'inconclusive', 'unaccounted')})}")
    for lane, lane_states in sorted(states.items()):
        if lane == want["failed_lane"]:
            if "FAILED" not in lane_states or set(lane_states) - {"FAILED", "VERIFIED"}:
                problems.append(f"lane {lane} should have a failed assertion and nothing unaccounted, has {lane_states}")
        elif set(lane_states) != {"VERIFIED"}:
            problems.append(f"lane {lane} should be all verified, has {lane_states}")
    natives = {l["lane_id"]: l["native"]["status"] for l in report["lanes"]}
    if natives != want["native"]:
        problems.append(f"the engines reported {natives}, expected {want['native']}")
    printed = re.findall(r"manifest digest: (sha256:[0-9a-f]{64})", output)
    plan = re.findall(r"plan digest: (sha256:[0-9a-f]{64})", output)
    real = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    if len(printed) != 1:
        problems.append(f"the demo printed {len(printed)} manifest digests, expected one")
    elif printed[0] != real:
        problems.append(f"the printed manifest digest {printed[0]} is not the sha256 of bundle-manifest.json ({real})")
    if len(plan) != 1 or plan[0] != report["plan_digest"]:
        problems.append("the printed plan digest is not the report's")
    if "ACCEPTED as internally consistent" not in output:
        problems.append("the demo's own re-verification in a fresh process did not accept the bundle")
    if "no external anchor" not in output:
        problems.append("the demo no longer says that it carries no external anchor")
    return problems, {"defect": defect, "run_id": report["run_id"], "anchor": real, "plan_digest": report["plan_digest"], "bundle": bundle.name}


def check_verify(defect: str, exit_code: int, result: dict) -> List[str]:
    want = EXPECT[defect]
    problems: List[str] = []
    if exit_code != want["exit"] or result.get("exit_code") != want["exit"]:
        problems.append(f"verify exited {exit_code} (reports {result.get('exit_code')}), expected {want['exit']}")
    if result.get("accepted") is not True or result.get("findings"):
        problems.append(f"the bundle was not accepted: findings {result.get('findings')}")
    anchor, plan = result.get("anchor", {}), result.get("plan", {})
    if anchor.get("state") != "matches-supplied-value" or anchor.get("matches_supplied_value") is not True:
        problems.append(f"the supplied anchor did not match: {anchor.get('state')}")
    if plan.get("state") != "verified" or plan.get("matches_supplied_value") is not True:
        problems.append(f"the supplied plan digest did not match: {plan.get('state')}")
    if result.get("recomputed_assertions") != 4 or result.get("agreeing_assertions") != 4:
        problems.append(f"expected 4 of 4 verdicts recomputed and agreeing, got {result.get('agreeing_assertions')} of {result.get('recomputed_assertions')}")
    if (result.get("run_outcome") or {}).get("outcome") != want["outcome"]:
        problems.append(f"the recomputed outcome is {(result.get('run_outcome') or {}).get('outcome')}, expected {want['outcome']}")
    if result.get("engine_verifier_disagreements"):
        problems.append("an engine and the verifier disagree")
    return problems


def main(argv: Sequence[str] = ()) -> int:
    p = argparse.ArgumentParser(prog="check_demo_outcome.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run")
    r.add_argument("--defect", choices=sorted(EXPECT), required=True)
    r.add_argument("--exit-code", type=int, required=True)
    r.add_argument("--output", required=True)
    r.add_argument("--evidence-root", required=True)
    r.add_argument("--anchor-out", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--defect", choices=sorted(EXPECT), required=True)
    v.add_argument("--exit-code", type=int, required=True)
    v.add_argument("--result", required=True)
    args = p.parse_args(list(argv) if argv else sys.argv[1:])
    if args.command == "run":
        problems, info = check_run(args.defect, args.exit_code, Path(args.output).read_text(encoding="utf-8", errors="replace"), Path(args.evidence_root))
        if not problems:
            out = Path(args.anchor_out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("".join(f"{k}={info[k]}\n" for k in ("defect", "run_id", "anchor", "plan_digest", "bundle")), encoding="utf-8")
            print(f"ANCHOR defect={info['defect']} run_id={info['run_id']} {info['anchor']}")
            print(f"PLAN DIGEST {info['plan_digest']}")
    else:
        try:
            result = json.loads(Path(args.result).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"cannot read the verify result ({type(exc).__name__})", file=sys.stderr)
            return 1
        problems = check_verify(args.defect, args.exit_code, result)
    for problem in problems:
        print(f"FAIL {args.defect}: {problem}", file=sys.stderr)
    if not problems:
        print(f"OK {args.command} {args.defect}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
