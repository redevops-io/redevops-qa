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
COMMON_LANE_KEYS = {"lane_id", "engine", "spec", "egress", "deadline_s", "requests", "probes"}
LANE_KEYS = {K.ENGINE_PLAYWRIGHT: set(COMMON_LANE_KEYS), K.ENGINE_ROBOT: COMMON_LANE_KEYS | {"suite", "suite_sha256"}}
OPTIONAL_LANE_KEYS = {"deadline_s"}
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUEST_RE = re.compile(r"^(GET|POST) (/[A-Za-z0-9._~/-]{0,100})$")
#: what an assertion's verdict is checked against besides the engine's own record: a fact of the independent reference check of the target, or ``ui-only`` (the assertion is about what the browser shows;
#: no server-side fact applies and nothing independent backs it). EVERY assertion of a lane names one: a lane cannot reach VERIFIED on a fixture-app assertion nobody said anything about.
UI_ONLY = "ui-only"
PROBE_FACTS = ("discount-rule", "settings-persistence", UI_ONLY)
#: what each fact of the reference check may speak for (retest R2b): a fact is tied to the engine and the subject of the assertion it covers, so that an assertion cannot borrow a fact that says
#: nothing about it (an order total labelled with the settings fact would be "backed" by a check that never looks at orders).
FACT_COVERS = {
    "settings-persistence": {"engine": K.ENGINE_PLAYWRIGHT, "subject_kind": "UI_ELEMENT", "locator": {"role": "checkbox", "name": "Email notifications"},
                             "says": "a browser assertion about the state of the 'Email notifications' checkbox (the saved notification setting)"},
    "discount-rule": {"engine": K.ENGINE_ROBOT, "check_program": "evidence.robot-observations",
                      "says": "a Robot lane's assertion read by the evidence.robot-observations program (the order totals the discount rule produces)"},
}
#: what limits the traffic of an engine: the browser's traffic passes the egress gateway (``origin-only``); a Robot lane is limited by kernel layers installed on its process before the engine
#: starts (``origin-only`` again: the same allow-list, one loopback origin; the lane does not start if the layers cannot be installed), or, when the plan says ``not-enforced``, by nothing
#: (a Robot library opens its own sockets, and the report says so)
EGRESS_PROFILES = {K.ENGINE_PLAYWRIGHT: ("origin-only",), K.ENGINE_ROBOT: ("origin-only", "not-enforced")}
TARGET_KINDS = ("fixture-app", "external-origin")
EXTERNAL_TARGET_KEYS = {"kind", "origin", "declared_by", "credential_refs", "mutating"}
#: an origin is scheme + host + port and nothing else: no userinfo, path, query, fragment or trailing slash; a lower-case host (a name, an IPv4 address or a bracketed IPv6 address) and a port of 1 to 5 digits
ORIGIN_RE = re.compile(r"^(?P<scheme>https?)://(?P<host>\[[0-9a-f:.]{2,45}\]|[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)(?::(?P<port>[0-9]{1,5}))?$")
#: a credential is named, never carried: ``env:NAME`` or ``file:/absolute/path``
CREDENTIAL_REF_RE = re.compile(r"^(?:env:[A-Z][A-Z0-9_]{0,63}|file:/[A-Za-z0-9._/-]{1,200})$")
LOOPBACK_HOSTS = ("127.0.0.1", "[::1]", "localhost")
#: what a run of this release supports as an external target (design section 6.1): a loopback, read-only Edge Sentinel fixture target and nothing else
V1_ORIGIN_RE = re.compile(r"^http://127\.0\.0\.1:[0-9]{1,5}$")
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
    suite: str                               # the reviewed Robot suite a Robot lane runs ("" for other engines)
    suite_files: Dict[str, str]              # sha256 of each file of that suite
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

    @property
    def external(self) -> bool:
        return is_external(self.plan)

    def target_record(self) -> Optional[Dict[str, Any]]:
        """What the lock records about an external target: the origin, the policy digest where a policy exists (the origin-only profile, loopback http only) and the credential REFERENCES (names, never values)."""
        if not self.external:
            return None
        t = self.plan["target"]
        policy = None
        if V1_ORIGIN_RE.fullmatch(t["origin"]):
            from .egress import policy_config
            policy = digest_of(policy_config("origin-only", t["origin"]))
        return {"kind": t["kind"], "origin": t["origin"], "declared_by": t["declared_by"], "mutating": t["mutating"], "credential_refs": list(t["credential_refs"]), "egress_policy_digest": policy,
                "verification_ceiling": "CORROBORATED"}

    def lock_document(self) -> Dict[str, Any]:
        doc = self._lock_document()
        record = self.target_record()
        if record is not None:
            doc["target"] = record
        return doc

    def _lock_document(self) -> Dict[str, Any]:
        return {"schema": K.LOCK_SCHEMA, "schema_version": K.PLAN_SCHEMA_VERSION, "plan_id": self.plan_id, "plan": self.plan, "plan_digest": self.plan_digest,
                "plan_sha256": digest_of(self.plan), "pins": dict(self.pins), "runner_version": self.runner_version,
                "lanes": [{"lane_id": l.lane_id, "engine": l.engine, "egress": l.egress, "requests": l.requests, "probes": l.probes, "spec_digest": l.spec_digest,
                           "spec_contract_hash": l.spec_contract_hash, "suite": l.suite, "suite_files": dict(sorted(l.suite_files.items())), "harness_pin": l.harness_pin,
                           "assertions": [dict(a) for a in l.assertions],
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
    if doc["schema"] != K.PLAN_SCHEMA or doc["schema_version"] != K.PLAN_SCHEMA_VERSION:
        raise PlanError("UNSUPPORTED_PLAN_VERSION", f"unsupported schema_version {str(doc['schema_version'])[:20]!r}: this runner reads {K.PLAN_SCHEMA} {K.PLAN_SCHEMA_VERSION} only"
                        + (" (a plan written for an older runner: from 1.1 a lane names `requests` and a probe for every assertion; rewrite it)" if doc["schema_version"] == "1.0" else ""))
    if not isinstance(doc["plan_id"], str) or not K.ASSERTION_ID_RE.fullmatch(doc["plan_id"]):
        raise PlanError("BAD_PLAN_ID", "plan_id must look like an identifier")
    check_target(doc["target"])
    lanes = doc["lanes"]
    if not isinstance(lanes, list) or not 1 <= len(lanes) <= 8:
        raise PlanError("BAD_LANES", "a plan has between 1 and 8 lanes")
    seen = set()
    for lane in lanes:
        if not isinstance(lane, dict) or lane.get("engine") not in K.ENGINES:
            raise PlanError("UNSUPPORTED_ENGINE", f"lane engine must be one of {list(K.ENGINES)} (R0 scope: Playwright Chromium and Robot Framework)")
        _only(lane, LANE_KEYS[lane["engine"]], f"lane {str(lane.get('lane_id'))[:20]!r}", OPTIONAL_LANE_KEYS)
        _check_requests(lane["requests"], str(lane.get("lane_id")))
        _check_probes(lane["probes"], str(lane.get("lane_id")))
        lid = lane["lane_id"]
        if not isinstance(lid, str) or not K.LANE_ID_RE.fullmatch(lid):
            raise PlanError("BAD_LANE_ID", "a lane id is 1 to 20 characters: a lower-case letter, then lower-case letters, digits and '-'")
        if lid in seen:
            raise PlanError("DUPLICATE_LANE", f"lane id {lid!r} is used twice")
        seen.add(lid)
        if lane["egress"] not in EGRESS_PROFILES[lane["engine"]]:
            raise PlanError("BAD_EGRESS_PROFILE", f"a {lane['engine']} lane's egress must be one of {list(EGRESS_PROFILES[lane['engine']])}")
        if doc["target"]["kind"] == "external-origin" and lane["engine"] == K.ENGINE_ROBOT and lane["egress"] == "not-enforced":
            raise PlanError("BAD_EGRESS_FOR_TARGET", f"lane {lid[:20]}: a Robot lane with egress not-enforced cannot target an external origin: its socket is not constrained, so there is no honest verdict to print")
        if "deadline_s" in lane and (type(lane["deadline_s"]) is not int or not 1 <= lane["deadline_s"] <= 3600):
            raise PlanError("BAD_DEADLINE", "deadline_s is an integer between 1 and 3600")
        if not isinstance(lane["spec"], dict):
            raise PlanError("BAD_SPEC", "a lane spec is a JSON object")
    return lanes


def check_target(target: Any) -> None:
    """The shape of a target. ``fixture-app`` is exactly ``{"kind": "fixture-app"}``. ``external-origin`` names an origin the OPERATOR declares, credentials by reference only, and ``mutating: false``.
    A shape that is well formed is accepted here (``check``/``freeze``); what a run of this release will actually reach is ``v1_scope_problems`` (``estimate`` and ``run`` apply it). No message repeats a credential."""
    if not isinstance(target, dict) or target.get("kind") not in TARGET_KINDS:
        raise PlanError("BAD_TARGET", f"target must be {{\"kind\": one of {list(TARGET_KINDS)}}} (a fixture-app target carries nothing else; an external-origin target carries {sorted(EXTERNAL_TARGET_KEYS - {'kind'})})")
    if target["kind"] == "fixture-app":
        if set(target) != {"kind"}:
            raise PlanError("BAD_TARGET", "a fixture-app target is exactly {\"kind\": \"fixture-app\"}: it cannot carry an origin or a credential")
        return
    if set(target) != EXTERNAL_TARGET_KEYS:
        raise PlanError("BAD_TARGET", f"an external-origin target has exactly the fields {sorted(EXTERNAL_TARGET_KEYS)}")
    origin = target["origin"]
    m = ORIGIN_RE.fullmatch(origin) if isinstance(origin, str) and len(origin) <= 300 else None
    if m is None or (m.group("port") is not None and not 1 <= int(m.group("port")) <= 65535):
        raise PlanError("BAD_TARGET_ORIGIN", "target.origin must be an origin: scheme (http or https), a lower-case host and an optional port, with no userinfo, path, query, fragment or trailing slash")
    if m.group("scheme") == "http" and m.group("host") not in LOOPBACK_HOSTS:
        raise PlanError("BAD_TARGET_ORIGIN", "target.origin uses http, which is accepted for a loopback origin only; use https for any other host")
    if target["declared_by"] != "operator":
        raise PlanError("BAD_TARGET_DECLARED_BY", "target.declared_by is always \"operator\": a target is never declared by a page, a ticket or a model answer")
    refs = target["credential_refs"]
    if not isinstance(refs, list) or len(refs) > 8 or len(set(map(str, refs))) != len(refs):
        raise PlanError("CREDENTIAL_NOT_A_REFERENCE", "target.credential_refs is a list of at most 8 distinct references (env:NAME or file:/absolute/path)")
    for i, ref in enumerate(refs):
        if not isinstance(ref, str) or not CREDENTIAL_REF_RE.fullmatch(ref):
            raise PlanError("CREDENTIAL_NOT_A_REFERENCE", f"target.credential_refs[{i}] is not a reference (env:NAME or file:/absolute/path): a credential is named in a plan, never carried in it")
    if target["mutating"] is not False:
        raise PlanError("MUTATING_NOT_SUPPORTED", "target.mutating must be false: a run that may write to a real system waits on the approval design for write-bearing QA (docs/P2_1_EXTERNAL_TARGET_DESIGN.md, section 5), which does not exist yet")


def is_external(plan_doc: Mapping[str, Any]) -> bool:
    return plan_doc["target"]["kind"] == "external-origin"


def v1_scope_problems(plan_doc: Mapping[str, Any], *, system: Optional[str] = None) -> List[Dict[str, str]]:
    """Why a run of THIS release would refuse a well-formed plan: ``[{"code", "message"}]``, empty when it would not. Same words in ``estimate`` and in ``run`` (the one validator)."""
    import platform as _platform
    problems: List[Dict[str, str]] = []
    target = plan_doc["target"]
    if target["kind"] != "external-origin":
        return problems
    if (system or _platform.system()).lower() != "linux":
        problems.append({"code": "PLATFORM_UNSUPPORTED", "message": "an external-target run is supported on Linux x86_64 (CPython 3.12 or 3.11) only; this host refuses rather than degrades"})
    if not V1_ORIGIN_RE.fullmatch(target["origin"]):
        problems.append({"code": "TARGET_OUT_OF_SCOPE", "message": "this release runs against one external target: a loopback, read-only Edge Sentinel fixture target at http://127.0.0.1:<port>; "
                         "a hostname (even one that could resolve to loopback), another address, https and any other application are not supported"})
    if target["credential_refs"]:
        problems.append({"code": "CREDENTIAL_REFS_NOT_SUPPORTED", "message": "this release accepts no credential reference for a target: the loopback fixture target needs none, and resolving a reference "
                         "in the egress gateway (owner decision 1 of the design) is not built"})
    for lane in plan_doc["lanes"]:
        if lane["engine"] != K.ENGINE_PLAYWRIGHT:
            problems.append({"code": "ENGINE_NOT_SUPPORTED_FOR_TARGET", "message": f"lane {str(lane['lane_id'])[:20]}: an external target is tested by the Playwright Chromium lane only: a Robot lane's assertions need a fact of the reference check, which an external target does not have"})
    return problems


def _check_requests(req: Any, lid: str) -> None:
    for key in ("required", "allowed"):
        for item in req.get(key, []) if isinstance(req, dict) and isinstance(req.get(key), list) else []:
            if isinstance(item, str) and ".." in item.split(" ", 1)[-1].split("/"):
                raise PlanError("BAD_REQUESTS", f"lane {lid[:20]}: requests.{key} may not contain a '..' segment")
    if not isinstance(req, dict) or set(req) != {"required", "allowed"}:
        raise PlanError("BAD_REQUESTS", f"lane {lid[:20]}: requests is {{\"required\": [...], \"allowed\": [...]}} of 'METHOD /path' entries")
    for key in ("required", "allowed"):
        items = req[key]
        if not isinstance(items, list) or len(items) > 64 or len(set(items)) != len(items) or not all(isinstance(i, str) and REQUEST_RE.fullmatch(i) for i in items):
            raise PlanError("BAD_REQUESTS", f"lane {lid[:20]}: requests.{key} is a list of distinct 'GET /path' or 'POST /path' entries (no query), at most 64")
    if not req["required"]:
        raise PlanError("BAD_REQUESTS", f"lane {lid[:20]}: a lane must name at least one request the target has to see")


def _fact_covers(fact: str, lane: Mapping[str, Any], assertion: Mapping[str, Any]) -> bool:
    rule = FACT_COVERS[fact]
    if lane["engine"] != rule["engine"]:
        return False
    subject = assertion.get("subject") or {}
    if "subject_kind" in rule and subject.get("kind") != rule["subject_kind"]:
        return False
    locator = subject.get("locator") or {}
    if "locator" in rule and any(locator.get(k) != v for k, v in rule["locator"].items()):
        return False
    if "check_program" in rule and (assertion.get("check_program_ref") or {}).get("id") != rule["check_program"]:
        return False
    return True


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


def _lane_engine_rules(lane: Mapping[str, Any], spec: Any, assertions: List[Dict[str, Any]], for_verification: bool = False) -> Tuple[str, Dict[str, str]]:
    """What each kind of lane may contain. A browser lane holds PLAYWRIGHT assertions only. A Robot lane names a shipped suite, holds no steps, and its assertions are
    SCRIPT assertions that read exactly the lane's observation record with the registered, hash-pinned ``evidence.robot-observations`` program."""
    lid = lane["lane_id"]
    if lane["engine"] == K.ENGINE_PLAYWRIGHT:
        if any(a["executor"] != "PLAYWRIGHT" for a in assertions):
            raise PlanError("EXECUTOR_MISMATCH", f"lane {lid}: a browser lane holds PLAYWRIGHT assertions only")
        return "", {}
    from . import suites
    from .suites import OBSERVATIONS_PATH_FORMAT, evidence_program_ref, suite_digests
    suite = lane["suite"]
    if not isinstance(suite, str):
        raise PlanError("UNKNOWN_SUITE", f"lane {lid}: suite must be the name of a shipped suite")
    given_hashes = lane["suite_sha256"]
    if for_verification:
        # Verifying the lock of a finished run: the suite files are the ones THE PLAN pins (``suite_sha256``, part of the plan digest and bound into every assertion digest of the lane),
        # never numbers the lock merely repeats, and never what this runner ships now (an older run used older files). Which files make a suite is the code's; their digests are the plan's.
        names = set(suites.SUITES[suite]["files"]) if suite in suites.SUITES else None
        if names is None:
            raise PlanError("UNKNOWN_SUITE", f"lane {lid}: no suite named {str(suite)[:40]!r} is known to this runner")
        if not isinstance(given_hashes, dict) or set(given_hashes) != names or not all(isinstance(v, str) and SHA256_RE.fullmatch(v) for v in given_hashes.values()):
            raise PlanError("SUITE_PINS_MALFORMED", f"lane {lid}: the plan must pin exactly the files {sorted(names)} of suite {suite!r} by sha256")
        hashes = dict(given_hashes)
    else:
        hashes = suite_digests(suite)                               # refuses an unknown suite
        if not isinstance(given_hashes, dict) or given_hashes != hashes:
            raise PlanError("SUITE_MISMATCH", f"lane {lid}: the plan pins the files of suite {suite!r} as {json.dumps(given_hashes, sort_keys=True)[:300]}, "
                            f"the files this runner ships hash as {json.dumps(hashes, sort_keys=True)}: a suite or library that is not the reviewed one is refused before anything runs")
    if any(v == UI_ONLY for v in lane["probes"].values()):
        raise PlanError("BAD_PROBES", f"lane {lid}: a Robot lane's assertions are about what the target's API says: each needs a fact of the reference check, not {UI_ONLY!r}")
    if spec.steps:
        raise PlanError("ROBOT_LANE_HAS_STEPS", f"lane {lid}: a Robot lane's spec carries assertions only; the suite is the engine's work")
    ref = evidence_program_ref()
    for a in assertions:
        if a["executor"] != "SCRIPT":
            raise PlanError("EXECUTOR_MISMATCH", f"lane {lid}: a Robot lane holds SCRIPT assertions only")
        given = a.get("check_program_ref") or {}
        if given.get("id") != ref["id"] or given.get("version") != ref["version"]:
            raise PlanError("PROGRAM_NOT_REGISTERED", f"lane {lid}: assertion {a['assertion_id']} must use {ref['id']}@{ref['version']}")
        if given.get("program_hash") != ref["program_hash"]:
            raise PlanError("PROGRAM_HASH_MISMATCH", f"lane {lid}: assertion {a['assertion_id']} pins a program hash that is not the registered one ({ref['program_hash']})")
        inputs = a["subject"].get("inputs") or []
        want = [{"kind": "MANIFEST_PATH", "path": OBSERVATIONS_PATH_FORMAT.format(lane_id=lid)}]
        if [{k: v for k, v in i.items() if v is not None} for i in inputs] != want:
            raise PlanError("BAD_ASSERTION_INPUTS", f"lane {lid}: assertion {a['assertion_id']} must read exactly {want[0]['path']}")
    return suite, hashes


def freeze_plan(up: Upstreams, plan_doc: Any, *, for_verification: bool = False) -> FrozenPlan:
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
        suite_name, suite_hashes = _lane_engine_rules(lane, spec, assertions, for_verification)
        materialise_spec(lane["spec"], "http://127.0.0.1:1")                 # the rule for {origin} that the run applies: a plan the run would refuse is refused here, before anything starts
        ids = {a["assertion_id"] for a in assertions}
        unknown_probe = sorted(set(lane["probes"]) - ids)
        if unknown_probe:
            raise PlanError("BAD_PROBES", f"lane {lid}: probes name assertions that are not in this lane: {[u[:40] for u in unknown_probe]}")
        unprobed = sorted(ids - set(lane["probes"]))
        if unprobed:
            raise PlanError("BAD_PROBES", f"lane {lid}: assertion(s) {[u[:40] for u in unprobed]} name no probe: give each a fact of the reference check ({', '.join(f for f in PROBE_FACTS if f != UI_ONLY)}) "
                            f"or {UI_ONLY!r} (what the browser shows, with nothing independent behind it)")
        by_id = {a["assertion_id"]: a for a in assertions}
        if plan_doc["target"]["kind"] == "external-origin" and any(f != UI_ONLY for f in lane["probes"].values()):
            raise PlanError("BAD_PROBES", f"lane {lid}: an external target has no reference check: every probe is {UI_ONLY!r} (nothing independent backs the assertions)")
        for aid, fact in lane["probes"].items():
            if fact != UI_ONLY and not _fact_covers(fact, lane, by_id[aid]):
                raise PlanError("BAD_PROBES", f"lane {lid}: the fact {fact!r} cannot cover assertion {aid[:40]!r}: it speaks for {FACT_COVERS[fact]['says']}")
        # Everything the plan fixes about a lane besides the assertion itself is bound into the digest of every assertion of that lane, so the plan digest covers it:
        # what the target's request log must show, which independent facts may not contradict a verdict, the egress profile, the whole spec (steps included), the deadline,
        # the reviewed suite and the digests of its files (a Robot lane), and the plan's id and target.
        binding = {"engine": lane["engine"], "egress": lane["egress"], "requests": lane["requests"], "probes": lane["probes"],
                   "deadline_s": lane.get("deadline_s", int(K.DEFAULT_LANE_DEADLINE_S)), "spec_sha256": digest_of(lane["spec"]),
                   "plan": {"plan_id": plan_doc["plan_id"], "target": plan_doc["target"]}}
        if suite_name:
            binding.update(suite=suite_name, suite_files=suite_hashes)
        digests = {a["assertion_id"]: digest_of({"assertion": a, "binding": binding}) for a in assertions}
        frozen.append(FrozenLane(lane_id=lid, engine=lane["engine"], deadline_s=lane.get("deadline_s", int(K.DEFAULT_LANE_DEADLINE_S)), egress=lane["egress"],
                                 requests=copy.deepcopy(lane["requests"]), probes=dict(lane["probes"]), spec_template=copy.deepcopy(lane["spec"]),
                                 spec_digest=digest_of(lane["spec"]), spec_contract_hash=spec.spec_hash, suite=suite_name, suite_files=suite_hashes,
                                 assertions=tuple(assertions), assertion_digests=digests, harness_pin=pin))
    return FrozenPlan(plan=copy.deepcopy(plan_doc), plan_id=plan_doc["plan_id"], lanes=tuple(frozen), pins=pin_summary(up), runner_version=K.RUNNER_VERSION)


def thaw_lock(up: Upstreams, lock_doc: Any, *, for_verification: bool = False) -> FrozenPlan:
    """Read a lock document: re-freeze the plan it carries and require every recorded digest and pin to be what that gives (no trust in the lock's own numbers).

    ``for_verification`` is for reading the lock of a finished run on another machine or at another time: the suite file hashes are the ones the PLAN pins (``verify``
    compares them with the copies in the bundle; they are part of the plan digest) and the tool versions the lock names are not required to be the ones loaded now (``verify`` reports a difference as a note);
    every assertion, expected value, digest, pin and program hash is still recomputed and compared."""
    if not isinstance(lock_doc, dict) or lock_doc.get("schema") != K.LOCK_SCHEMA:
        raise PlanError("NOT_A_LOCK", f"this is not a {K.LOCK_SCHEMA} document")
    if lock_doc.get("schema_version") != K.PLAN_SCHEMA_VERSION:
        raise PlanError("UNSUPPORTED_LOCK_VERSION", f"unsupported schema_version {str(lock_doc.get('schema_version'))[:20]!r}: this runner reads {K.LOCK_SCHEMA} {K.PLAN_SCHEMA_VERSION} only"
                        + (" (a lock, or a bundle's plan lock, written by an older runner; run the plan again with this runner)" if lock_doc.get("schema_version") == "1.0" else ""))
    again = freeze_plan(up, lock_doc.get("plan"), for_verification=for_verification)
    expected, got = again.lock_document(), dict(lock_doc)
    if for_verification:
        for tooling in ("pins", "runner_version"):
            expected.pop(tooling, None)
            got.pop(tooling, None)
    if dumps_canonical(expected) != dumps_canonical(got):
        raise PlanError("LOCK_MISMATCH", "the lock does not equal the freeze of the plan it carries (an edited expected value, digest, pin, tool version or suite hash)")
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
