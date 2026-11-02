# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Tools for the product-level tamper suite: load a REAL bundle (written by ``redevops-qa demo``), change it the way an attacker with this repository's own tools would, and
verify the result with the product's ``verify``.

``rechain`` is the forger's last step (every file digest and size in the manifest recomputed). ``forge_consistently`` is the strongest forger: it hands edited lane files to this
package's own bundle builder, so the report, the verdicts, the digests, the manifest and the evidence-set digest all agree with each other."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Tuple

from qa_evidence.build import read_files, write_archive
from qa_evidence.canon import dumps_canonical, loads_strict, sha256_bytes
from qa_evidence.constants import MANIFEST_NAME

GOLDEN = Path(__file__).resolve().parent / "golden"
Files = Dict[str, bytes]


def golden(defect: str) -> Files:
    return read_files(str(GOLDEN / f"bundle-{defect}.tar"))


def load(files: Mapping[str, bytes], path: str):
    return json.loads(files[path].decode("utf-8"))


def put(files: Files, path: str, doc) -> None:
    files[path] = dumps_canonical(doc)


def rechain(files: Mapping[str, bytes]) -> Files:
    """Recompute the digest and size of every file the manifest lists (what a forger does after editing a file)."""
    files = dict(files)
    man = load(files, MANIFEST_NAME)
    for entry in man["files"]:
        if entry["path"] in files:
            entry["digest"] = sha256_bytes(files[entry["path"]])
            entry["size"] = len(files[entry["path"]])
    put(files, MANIFEST_NAME, man)
    return files


def edit_json(files: Mapping[str, bytes], path: str, fn: Callable) -> Files:
    out = dict(files)
    doc = load(out, path)
    fn(doc)
    put(out, path, doc)
    return out


def manifest_digest(files: Mapping[str, bytes]) -> str:
    return sha256_bytes(files[MANIFEST_NAME])


def verify_files_in(tmp_path: Path, files: Mapping[str, bytes], name: str = "b.tar", **kw):
    """Write ``files`` as the canonical archive and run the product's ``verify`` over it, in this process (the separate-process form is tested apart)."""
    from qa_runner.verify import verify_location
    target = tmp_path / name
    if target.exists():
        target.unlink()
    write_archive(dict(files), str(target))
    return verify_location(str(target), **kw)


def codes(v) -> List[str]:
    return sorted({f.code for f in v.findings})


# ---- the strongest forger -------------------------------------------------------------------------------------------------------------
def lane_outcomes_from(up, files: Mapping[str, bytes]):
    """Rebuild this package's ``LaneOutcome`` for every lane from the files of a bundle (so a forger can edit a file and hand the lanes to the real builder)."""
    from qa_runner.bundle import LaneOutcome
    report = load(files, "report.json")
    outcomes = {}
    for lane in report["lanes"]:
        lid, nat = lane["lane_id"], lane["native"]
        prefix = f"lanes/{lid}/native/"
        native = {p[len(prefix):]: d for p, d in files.items() if p.startswith(prefix)}
        other = {}
        for entry in load(files, MANIFEST_NAME)["files"]:
            p = entry["path"]
            if p.startswith(f"lanes/{lid}/") and not p.startswith(prefix):
                other[p] = (files[p], entry["role"])
            if p in (f"logs/{lid}.stdout.txt", f"logs/{lid}.stderr.txt"):
                other[p] = (files[p], entry["role"])
        harness = {}
        try:
            for item in load(files, prefix + "lane-result.json").get("harness_verdicts", []):
                harness[item["assertion_id"]] = item["verdict"]
        except KeyError:
            pass
        outcomes[lid] = LaneOutcome(lane_id=lid, engine_name=lane["engine"]["name"], engine_version=lane["engine"]["version"], native_status=nat["status"], raw_status=nat["raw_status"],
                                    exit_code=nat["exit_code"], native_files=native, files=other, counts=nat.get("counts"), harness_verdicts=harness)
    return outcomes


def forge_consistently(up, files: Mapping[str, bytes], *, edit_lane: Callable, frozen=None, extensions: Optional[Mapping] = None, logs_extra: Optional[Mapping[str, bytes]] = None) -> Files:
    """Hand the (edited) lanes and the plan lock to the real builder: every digest, count, verdict and the manifest are recomputed, so the result is internally consistent."""
    import dataclasses
    from qa_runner.bundle import RunInputs, build_run_bundle
    from qa_runner.plan import thaw_lock
    report = load(files, "report.json")
    frozen = frozen or thaw_lock(up, load(files, "plan.lock.json"), for_verification=True)
    outcomes = lane_outcomes_from(up, files)
    outcomes = {lid: edit_lane(lid, o) for lid, o in outcomes.items()}
    logs = {p: files[p] for p in files if p.startswith("logs/") and p.count("/") == 1 and p not in [f"logs/{l}.{s}.txt" for l in outcomes for s in ("stdout", "stderr")]}
    inputs = RunInputs(frozen=frozen, run_id=report["run_id"], started_at=report["started_at"], finished_at=report["finished_at"], environment=report["environment"],
                       lanes=tuple(outcomes[l.lane_id] for l in frozen.lanes), logs={**logs, **dict(logs_extra or {})},
                       extensions={**(report.get("extensions") or {}), **dict(extensions or {})})
    return dict(build_run_bundle(up, inputs).files)
