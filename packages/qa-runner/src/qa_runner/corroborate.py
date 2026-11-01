# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""What a lane's own claims are checked against: the harness run record, the target's own request log and an independent reference check of the target.

A browser lane child reports an outcome, a run record and the values it observed. None of that is taken at its word. ``judge_lane`` asks these functions, over the files of the
bundle, before it lets a verdict stand:

* the **harness run record** passes the harness integrity check (event chain, receipt chain, manifest, seal), is sealed and not cancelled, names this run and the frozen assertion pin,
  executed the frozen spec (rebuilt from the template and the allowed origin), reached the same outcome and exit code as the lane result, and read exactly the values the observation
  file lists;
* the **target's request log** (what the application itself served during this lane's window) holds every request the plan requires of the lane and nothing the plan does not allow;
* the **reference check** (``qa_fixture_app.reference_check``: its own restatement of the seed data and the rule, plain HTTP, no code of this repository's engines) does not contradict a
  verdict the plan ties to one of its facts.

For a Robot lane the engine's own files are held against each other (the summary and the adapter result must name the very ``output.xml`` that is in the bundle and agree on every
test's status), the reviewed suite files in the bundle must be the files the plan pins, and the target must have seen the requests a reviewed library has to make.

A failure is a reason string; the caller turns it into unusable evidence for the whole lane (INCONCLUSIVE), never into a pass or a fail."""
from __future__ import annotations

import copy
import json
from typing import Any, Dict, List, Mapping, Optional, Set

from qa_evidence.canon import CanonError, loads_strict, sha256_bytes

from .deps import Upstreams
from .plan import FrozenLane, materialise_spec

BUILTIN_REQUESTS = frozenset({"GET /health", "GET /favicon.ico"})      # the runner's own health probe and the browser's icon request
REFERENCE_CHECK_PATH = "logs/reference-check.json"


def request_log_path(lane_id: str) -> str:
    return f"lanes/{lane_id}/target-requests.jsonl"


def _origin(files: Mapping[str, bytes], lane_id: str) -> Optional[str]:
    try:
        entry = loads_strict(files[f"lanes/{lane_id}/egress-profile.json"])["private"][0]
        return f"http://{entry['host']}:{entry['ports'][0]}"
    except (KeyError, IndexError, TypeError, CanonError):
        return None


def corroborate_browser(up: Upstreams, lane: FrozenLane, run_id: str, files: Mapping[str, bytes], rows: Mapping[str, Mapping[str, Any]]) -> Optional[str]:
    h = up.harness
    lid, full = lane.lane_id, f"{run_id}.{lane.lane_id}"
    try:
        result = loads_strict(files[f"lanes/{lid}/native/lane-result.json"])
        rec = loads_strict(files[f"lanes/{lid}/native/run-record.json"])
    except (KeyError, CanonError):
        return "the lane result or the harness run record is missing or unreadable"
    if not isinstance(result, dict) or not isinstance(rec, dict):
        return "the lane result or the harness run record is not an object"
    if result.get("status") != "COMPLETED" or result.get("sealed") is not True or result.get("cancelled") is not False:
        return "the lane result does not say that the run completed, was sealed and was not cancelled"
    if rec.get("sealed") is not True or rec.get("cancelled") is not False:
        return "the harness run record is not sealed or was cancelled"
    try:
        receipts = [h.records.ActionReceipt.from_json(copy.deepcopy(r)) for r in rec["receipts"]]
        links = [h.receipts.ChainLink(**l) for l in rec["receipt_links"]]
        manifest = h.records.RunManifest.from_json(copy.deepcopy(rec["manifest"]))
        found = h.integrity.verify_run_evidence(events=rec["events"], receipts=receipts, links=links, manifest=manifest)
    except Exception:
        return "the harness run record cannot be read as a harness record"
    if found.findings:
        return "the harness integrity check found " + ", ".join(sorted({f.code for f in found.findings}))
    if rec.get("run_id") != full or manifest.run_id != full:
        return "the run record belongs to another run id"
    if manifest.assertion_set_hash != lane.harness_pin:
        return "the run record was verified against another assertion set than the frozen one"
    if rec.get("classification", {}).get("outcome") != result.get("outcome") or rec.get("exit_code") != result.get("exit_code"):
        return "the run record and the lane result name different outcomes"
    origin = _origin(files, lid)
    if origin is None:
        return "the egress profile that names the allowed origin is missing"
    try:
        if manifest.spec_ref != h.records.TestSpec.from_json(materialise_spec(lane.spec_template, origin)).spec_ref():
            return "the spec the run executed is not the frozen template with the allowed origin"
    except Exception:
        return "the executed spec cannot be rebuilt from the frozen template"
    by_id = {r.assertion_id: r for r in manifest.assertion_results}
    for aid, row in rows.items():
        r = by_id.get(aid)
        if r is None or r.actual != row.get("value") or r.actual_digest != row.get("value_digest"):
            return "an observation is not what the harness run record says was read"
    return None


def corroborate_requests(lane: FrozenLane, files: Mapping[str, bytes]) -> Optional[str]:
    data = files.get(request_log_path(lane.lane_id))
    if data is None:
        return "the target's request log for this lane is missing"
    seen: Set[str] = set()
    for line in data.decode("utf-8", "replace").splitlines():
        try:
            entry = loads_strict(line.encode("utf-8"))
            seen.add(f"{entry['method']} {str(entry['target']).split('?', 1)[0]}")
        except (CanonError, KeyError, TypeError):
            return "the target's request log has a line that cannot be read"
    required, allowed = set(lane.requests["required"]), set(lane.requests["allowed"])
    if required - seen:
        return "the target never saw " + ", ".join(sorted(required - seen))
    extra = seen - required - allowed - BUILTIN_REQUESTS
    if extra:
        return "the target saw requests the plan does not allow: " + ", ".join(sorted(extra))
    return None


def probe_verdicts(lane: FrozenLane, files: Mapping[str, bytes]) -> Dict[str, str]:
    """For each assertion the plan ties to a fact of the reference check: ``missing`` (no reference check in the bundle) or ``contradicted`` (the check found that fact deviating)."""
    if not lane.probes:
        return {}
    data = files.get(REFERENCE_CHECK_PATH)
    if data is None:
        return {aid: "missing" for aid in lane.probes}
    try:
        deviating = {d["check"] for d in loads_strict(data)["deviations"]}
    except (CanonError, KeyError, TypeError):
        return {aid: "missing" for aid in lane.probes}
    return {aid: "contradicted" for aid, fact in lane.probes.items() if fact in deviating}


def _plain_json(data: bytes) -> Any:
    def refuse(_: str) -> Any:
        raise ValueError("constant")

    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(items)
    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=refuse)


def corroborate_robot(lane: FrozenLane, run_id: str, files: Mapping[str, bytes]) -> Optional[str]:
    """The Robot lane's native files against each other and against the plan: ``robot-summary.json`` and ``adapter-result.json`` name the ``output.xml`` of the bundle (by hash) and
    agree on every test's status; the suite files in the bundle are the pinned ones; the target saw the requests the plan requires."""
    lid = lane.lane_id
    base = f"lanes/{lid}/native/"
    try:
        xml, summary_raw = files[base + "output.xml"], files[base + "robot-summary.json"]
        summary, result = _plain_json(summary_raw), _plain_json(files[base + "adapter-result.json"])
    except (KeyError, ValueError, UnicodeDecodeError):
        return "the engine's report, its summary or the adapter result is missing or unreadable"
    if not isinstance(summary, dict) or not isinstance(result, dict):
        return "the engine's summary or the adapter result is not an object"
    xml_hex = sha256_bytes(xml).split(":", 1)[-1]
    if str(summary.get("raw_output_sha256", "")).split(":", 1)[-1] != xml_hex:
        return "the engine's summary names another output.xml than the one in the bundle"
    if result.get("run_id") != f"{run_id}.{lid}" or result.get("adapter_id") != "robot-suite" or result.get("status") not in ("PASS", "FAIL"):
        return "the adapter result belongs to another run or does not report a completed suite"
    arts = {a.get("path"): str(a.get("sha256", "")).split(":", 1)[-1] for a in result.get("artifacts") or [] if isinstance(a, dict)}
    if arts.get("output.xml") != xml_hex or arts.get("robot-summary.json") != sha256_bytes(summary_raw).split(":", 1)[-1]:
        return "the adapter result names other native files than the ones in the bundle"
    try:
        said = {t["native_id"]: t["status"] for t in summary["tests"]}
        ran = {t["native_id"]: t["status"] for t in result["native_assertions"]}
    except (KeyError, TypeError):
        return "the engine's summary or the adapter result lists no tests"
    if not said or said != ran:
        return "the engine's summary and the adapter result disagree on the tests and their statuses"
    if (result["status"] == "PASS") != all(v == "PASS" for v in ran.values()):
        return "the adapter result's status is not what its own tests add up to"
    prefix = f"lanes/{lid}/suite/"
    kept = {k[len(prefix):] for k in files if k.startswith(prefix)}
    if kept != set(lane.suite_files) or any(sha256_bytes(files[prefix + rel]) != digest for rel, digest in lane.suite_files.items()):
        return "the suite files in the bundle are not the files the plan pins"
    return corroborate_requests(lane, files)
