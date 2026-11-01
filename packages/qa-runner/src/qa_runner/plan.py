# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The plan (what to run), its freezing (what is fixed before anything runs) and the lock that records both.

A plan names one lane per engine; each lane carries a runtime-contracts ``qa/v1`` ``TestSpec`` whose assertions hold the expected values. ``freeze``

1. refuses any plan or lane field it does not know (security-sensitive: an unknown field would change hashes without being understood);
2. parses every spec with the **strict runtime-contracts parser first** (the harness mirror tolerates unknown spec fields, and they change the
   spec hash), then with the harness mirror, and requires both to agree on the assertion-set pin;
3. gives each assertion a digest (sha256 of its canonical JSON, expected value included) and computes the assertion lock and the plan digest with
   the conventions of ``qa_evidence`` (the plan digest of this format version is the digest of the assertion lock);
4. records everything in a lock document that is deterministic: same plan, same pins, same bytes.

The origin of the target is not part of a plan: a step value may start with ``{origin}``, replaced when the lane runs, so one frozen plan
serves every start of the fixture app (a different port every time) and the executed spec is recomputed from the template and the recorded origin.
"""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

from qa_evidence.canon import CanonError, digest_of, dumps_canonical, loads_strict, sha256_bytes
from qa_evidence.report import assertion_lock_bytes, assertion_set_digest

from . import constants as K
from .deps import Upstreams, pin_summary
from .errors import PlanError

PLAN_KEYS = {"schema", "schema_version", "plan_id", "target", "lanes"}
LANE_KEYS = {ENGINE: {"lane_id", "engine", "spec", "egress", "deadline_s", "requests", "probes"} for ENGINE in K.ENGINES}
OPTIONAL_LANE_KEYS = {"deadline_s", "probes"}
REQUEST_RE = re.compile(r"^(GET|POST) (/[A-Za-z0-9._~/-]{0,100})$")
PROBE_FACTS = ("discount-rule", "settings-persistence")
EGRESS_PROFILES = ("origin-only",)
TARGET_KINDS = ("fixture-app",)
MAX_PLAN_BYTES = 1024 * 1024


def read_json(data: bytes, what: str) -> Any:
    try:
        return loads_strict(data)
    except CanonError as exc:
        raise PlanError("NOT_STRICT_JSON", f"{what}: {exc.code}: {exc}") from None


def _only(doc: Mapping[str, Any], allowed, where: str, optional=("deadline_s",)) -> None:
    unknown = sorted(set(doc) - set(allowed))
    if unknown:
        raise PlanError("UNKNOWN_FIELD", f"{where} has unknown field(s) {[str(u)[:40] for u in unknown]}: an unknown field is refused, never ignored")
    missing = sorted(set(allowed) - set(doc) - set(optional))
    if missing:
        raise PlanError("MISSING_FIELD", f"{where} lacks {missing}")


@dataclass(frozen=True)
class FrozenLane:
    lane_id: str
    engine: str
    deadline_s: int
    egress: str
    requests: Dict[str, Any]                 # what the target's request log must show for this lane: {"required": [...], "allowed": [...]} of "METHOD /path"
    probes: Dict[str, str]                   # assertion id -> the fact of the independent reference check that must not contradict a VERIFIED verdict
    spec_template: Dict[str, Any]
    spec_digest: str                         # sha256 of the canonical JSON of the template exactly as given
    spec_contract_hash: str                  # the contracts spec hash (rcv1)
    assertions: Tuple[Dict[str, Any], ...]   # contracts-normalised assertion documents, sorted by id
    assertion_digests: Dict[str, str]
    harness_pin: str                         # the rcv1 assertion-set pin the harness executor is given

    def rows(self) -> List[Dict[str, str]]:
        return [{"assertion_id": a["assertion_id"], "lane_id": self.lane_id, "digest": self.assertion_digests[a["assertion_id"]]} for a in self.assertions]


@dataclass(frozen=True)
class FrozenPlan:
    plan: Dict[str, Any]
    plan_id: str
    lanes: Tuple[FrozenLane, ...]
    pins: Dict[str, str]
    runner_version: str

    @property
    def rows(self) -> List[Dict[str, str]]:
        return sorted((r for lane in self.lanes for r in lane.rows()), key=lambda r: (r["assertion_id"], r["lane_id"], r["digest"]))

    @property
    def plan_digest(self) -> str:
        """The digest of the assertion lock: what ``verify --plan-digest`` is compared with and what ``freeze`` prints."""
        return assertion_set_digest(self.rows)

    def lock_document(self) -> Dict[str, Any]:
        return {"schema": K.LOCK_SCHEMA, "schema_version": K.SCHEMA_VERSION, "plan_id": self.plan_id, "plan": self.plan, "plan_digest": self.plan_digest,
                "plan_sha256": digest_of(self.plan), "pins": dict(self.pins), "runner_version": self.runner_version,
                "lanes": [{"lane_id": l.lane_id, "engine": l.engine, "egress": l.egress, "requests": l.requests, "probes": l.probes, "spec_digest": l.spec_digest,
                           "spec_contract_hash": l.spec_contract_hash, "harness_pin": l.harness_pin, "assertions": [dict(a) for a in l.assertions],
                           "assertion_digests": dict(sorted(l.assertion_digests.items()))} for l in self.lanes]}

    def lock_bytes(self) -> bytes:
        return dumps_canonical(self.lock_document())

    @property
    def lock_digest(self) -> str:
        return sha256_bytes(self.lock_bytes())

    def lane(self, lane_id: str) -> FrozenLane:
        for l in self.lanes:
            if l.lane_id == lane_id:
                return l
        raise PlanError("UNKNOWN_LANE", f"no lane {lane_id!r}")

    def assertion_lock_bytes(self) -> bytes:
        return assertion_lock_bytes(self.rows)


def _parse_structure(doc: Any) -> List[Mapping[str, Any]]:
    if not isinstance(doc, dict):
        raise PlanError("PLAN_NOT_AN_OBJECT", "a plan is a JSON object")
    _only(doc, PLAN_KEYS, "the plan")
    if doc["schema"] != K.PLAN_SCHEMA or doc["schema_version"] != K.SCHEMA_VERSION:
        raise PlanError("UNSUPPORTED_PLAN_VERSION", f"this runner reads {K.PLAN_SCHEMA} {K.SCHEMA_VERSION} only")
    if not isinstance(doc["plan_id"], str) or not K.ASSERTION_ID_RE.fullmatch(doc["plan_id"]):
        raise PlanError("BAD_PLAN_ID", "plan_id must look like an identifier")
    target = doc["target"]
    if not isinstance(target, dict) or set(target) != {"kind"} or target["kind"] not in TARGET_KINDS:
        raise PlanError("BAD_TARGET", f"target must be {{\"kind\": one of {list(TARGET_KINDS)}}}")
    lanes = doc["lanes"]
    if not isinstance(lanes, list) or not 1 <= len(lanes) <= 8:
        raise PlanError("BAD_LANES", "a plan has between 1 and 8 lanes")
    seen = set()
    for lane in lanes:
        if not isinstance(lane, dict) or lane.get("engine") not in K.ENGINES:
            raise PlanError("UNSUPPORTED_ENGINE", f"lane engine must be one of {list(K.ENGINES)} (R0 scope: Playwright Chromium and Robot Framework)")
        _only(lane, LANE_KEYS[lane["engine"]], f"lane {str(lane.get('lane_id'))[:20]!r}", OPTIONAL_LANE_KEYS)
        _check_requests(lane["requests"], str(lane.get("lane_id")))
        _check_probes(lane.get("probes", {}), str(lane.get("lane_id")))
        lid = lane["lane_id"]
        if not isinstance(lid, str) or not K.LANE_ID_RE.fullmatch(lid):
            raise PlanError("BAD_LANE_ID", "a lane id is 1 to 20 characters: a lower-case letter, then lower-case letters, digits and '-'")
        if lid in seen:
            raise PlanError("DUPLICATE_LANE", f"lane id {lid!r} is used twice")
        seen.add(lid)
        if lane["egress"] not in EGRESS_PROFILES:
            raise PlanError("BAD_EGRESS_PROFILE", f"egress must be one of {list(EGRESS_PROFILES)}")
        if "deadline_s" in lane and (type(lane["deadline_s"]) is not int or not 1 <= lane["deadline_s"] <= 3600):
            raise PlanError("BAD_DEADLINE", "deadline_s is an integer between 1 and 3600")
        if not isinstance(lane["spec"], dict):
            raise PlanError("BAD_SPEC", "a lane spec is a JSON object")
    return lanes


def _check_requests(req: Any, lid: str) -> None:
    if not isinstance(req, dict) or set(req) != {"required", "allowed"}:
        raise PlanError("BAD_REQUESTS", f"lane {lid[:20]}: requests is {{\"required\": [...], \"allowed\": [...]}} of 'METHOD /path' entries")
    for key in ("required", "allowed"):
        items = req[key]
        if not isinstance(items, list) or len(items) > 64 or len(set(items)) != len(items) or not all(isinstance(i, str) and REQUEST_RE.fullmatch(i) for i in items):
            raise PlanError("BAD_REQUESTS", f"lane {lid[:20]}: requests.{key} is a list of distinct 'GET /path' or 'POST /path' entries (no query), at most 64")
    if not req["required"]:
        raise PlanError("BAD_REQUESTS", f"lane {lid[:20]}: a lane must name at least one request the target has to see")


def _check_probes(probes: Any, lid: str) -> None:
    if not isinstance(probes, dict) or not all(isinstance(k, str) and v in PROBE_FACTS for k, v in probes.items()):
        raise PlanError("BAD_PROBES", f"lane {lid[:20]}: probes maps an assertion id to one of {list(PROBE_FACTS)}")


def _contracts_spec(up: Upstreams, doc: Mapping[str, Any], lane_id: str):
    c = up.contracts
    try:
        return c.TestSpec.from_json(copy.deepcopy(dict(doc)))
    except c.QAContractError as exc:
        raise PlanError("SPEC_REJECTED", f"lane {lane_id}: the runtime-contracts parser refused the spec ({getattr(exc, 'code', 'QAContractError')}): "
                        f"{str(getattr(exc, 'detail', exc))[:300]}") from None


def freeze_plan(up: Upstreams, plan_doc: Any) -> FrozenPlan:
    lanes_in = _parse_structure(plan_doc)
    if len(json.dumps(plan_doc)) > MAX_PLAN_BYTES:
        raise PlanError("PLAN_TOO_LARGE", f"a plan is at most {MAX_PLAN_BYTES} bytes")
    h = up.harness
    frozen: List[FrozenLane] = []
    seen_ids: Dict[str, Tuple[str, str]] = {}
    for lane in lanes_in:
        lid = lane["lane_id"]
        spec = _contracts_spec(up, lane["spec"], lid)                       # strict parser first: it refuses unknown fields
        try:
            h.records.TestSpec.from_json(copy.deepcopy(lane["spec"]))        # the harness mirror must accept the same document
            assertions = sorted((a.to_json() for a in spec.assertions), key=lambda a: a["assertion_id"])
            pin = h.verifier.assertion_set_pin(tuple(h.records.AssertionSpec.from_json(copy.deepcopy(a)) for a in assertions))
        except Exception as exc:
            raise PlanError("SPEC_REJECTED_BY_HARNESS", f"lane {lid}: the harness refused a spec the contracts parser accepted ({type(exc).__name__})") from None
        if pin != spec.assertion_set_hash:
            raise PlanError("PIN_DIVERGENCE", f"lane {lid}: the contracts and the harness compute different assertion-set pins")
        for a in assertions:
            if not K.ASSERTION_ID_RE.fullmatch(a["assertion_id"]):
                raise PlanError("BAD_ASSERTION_ID", f"assertion id {a['assertion_id'][:40]!r} does not fit the evidence id pattern")
            key = a["assertion_id"].lower()                                  # the evidence format refuses ids that differ only in case: refuse them here, before anything runs
            if key in seen_ids:
                raise PlanError("DUPLICATE_ASSERTION", f"assertion id {a['assertion_id']!r} appears in lanes {seen_ids[key][1]!r} and {lid!r} (ids are compared without case): "
                                "every frozen assertion is accounted exactly once")
            seen_ids[key] = (a["assertion_id"], lid)
        unknown_probe = sorted(set(lane.get("probes", {})) - {a["assertion_id"] for a in assertions})
        if unknown_probe:
            raise PlanError("BAD_PROBES", f"lane {lid}: probes name assertions that are not in this lane: {[u[:40] for u in unknown_probe]}")
        # Everything the plan fixes about a lane besides the assertion itself is bound into the digest of every assertion of that lane, so the plan digest covers it:
        # what the target's request log must show, which independent facts may not contradict a verdict, the egress profile, the whole spec (steps included), the deadline and the plan's id and target.
        binding = {"engine": lane["engine"], "egress": lane["egress"], "requests": lane["requests"], "probes": lane.get("probes", {}),
                   "deadline_s": lane.get("deadline_s", int(K.DEFAULT_LANE_DEADLINE_S)), "spec_sha256": digest_of(lane["spec"]),
                   "plan": {"plan_id": plan_doc["plan_id"], "target": plan_doc["target"]}}
        digests = {a["assertion_id"]: digest_of({"assertion": a, "binding": binding}) for a in assertions}
        frozen.append(FrozenLane(lane_id=lid, engine=lane["engine"], deadline_s=lane.get("deadline_s", int(K.DEFAULT_LANE_DEADLINE_S)), egress=lane["egress"],
                                 requests=copy.deepcopy(lane["requests"]), probes=dict(lane.get("probes", {})), spec_template=copy.deepcopy(lane["spec"]), spec_digest=digest_of(lane["spec"]), spec_contract_hash=spec.spec_hash,
                                 assertions=tuple(assertions), assertion_digests=digests, harness_pin=pin))
    return FrozenPlan(plan=copy.deepcopy(plan_doc), plan_id=plan_doc["plan_id"], lanes=tuple(frozen), pins=pin_summary(up), runner_version=K.RUNNER_VERSION)


def thaw_lock(up: Upstreams, lock_doc: Any) -> FrozenPlan:
    """Read a lock document: re-freeze the plan it carries and require every recorded digest and pin to be what that gives (no trust in the lock's own numbers)."""
    if not isinstance(lock_doc, dict) or lock_doc.get("schema") != K.LOCK_SCHEMA:
        raise PlanError("NOT_A_LOCK", f"this is not a {K.LOCK_SCHEMA} document")
    if lock_doc.get("schema_version") != K.SCHEMA_VERSION:
        raise PlanError("UNSUPPORTED_LOCK_VERSION", f"this runner reads {K.LOCK_SCHEMA} {K.SCHEMA_VERSION} only")
    again = freeze_plan(up, lock_doc.get("plan"))
    if dumps_canonical(again.lock_document()) != dumps_canonical(lock_doc):
        raise PlanError("LOCK_MISMATCH", "the lock does not equal the freeze of the plan it carries (an edited expected value, digest, pin or tool version)")
    return again


def load_plan_or_lock(up: Upstreams, data: bytes) -> Tuple[FrozenPlan, str]:
    """``(frozen plan, "plan"|"lock")``. A lock is verified against its own plan; a plan is frozen now."""
    doc = read_json(data, "the plan")
    if isinstance(doc, dict) and doc.get("schema") == K.LOCK_SCHEMA:
        return thaw_lock(up, doc), "lock"
    return freeze_plan(up, doc), "plan"


def materialise_spec(template: Mapping[str, Any], origin: str) -> Dict[str, Any]:
    """The spec to execute: the frozen template with ``{origin}`` at the start of a step value replaced by the origin of this start of the target."""
    spec = copy.deepcopy(dict(template))
    for step in spec.get("steps", ()):
        action = step.get("action", {})
        value = action.get("value")
        if isinstance(value, str) and K.ORIGIN_PLACEHOLDER in value:
            if not value.startswith(K.ORIGIN_PLACEHOLDER) or value.count(K.ORIGIN_PLACEHOLDER) != 1:
                raise PlanError("BAD_ORIGIN_PLACEHOLDER", f"step {str(step.get('step_id'))[:20]!r}: {{origin}} may appear once, at the start of a value")
            action["value"] = origin + value[len(K.ORIGIN_PLACEHOLDER):]
    return spec
