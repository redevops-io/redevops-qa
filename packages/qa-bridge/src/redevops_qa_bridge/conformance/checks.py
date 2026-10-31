# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Running one conformance item. Every runner raises :class:`ConformanceFailure` with a stable code and the concrete
mismatch (the two hashes, the two member lists, the two codes); a runner that returns has passed.

The runners use each side's own objects and the bridge only where the bridge is the thing under test (conversion).
Nothing is skipped: an item whose input one side cannot even load is a failure with the loader's own code.
"""
from __future__ import annotations

import copy
import dataclasses
import enum
import hashlib
import inspect
import json
from typing import Any, Callable, Dict, List, Optional, Tuple

from .. import convert, deps, hashing
from ..errors import BridgeError
from . import data as D
from .context import Context, get_context
from .items import Item, ctx_adapter_codes
from .model import EVIDENCE, ConformanceFailure, fail

# failure codes
HASH_DIVERGENCE = "HASH_DIVERGENCE"
GOLDEN_MISMATCH = "GOLDEN_MISMATCH"
CONVERSION_REFUSED = "CONVERSION_REFUSED"
ROUND_TRIP_DIFFERS = "ROUND_TRIP_DIFFERS"
SOURCE_REFUSED = "SOURCE_REFUSED"
FIELD_PARITY = "FIELD_PARITY"
ENUM_PARITY = "ENUM_PARITY"
PROTOCOL_PARITY = "PROTOCOL_PARITY"
REFUSAL_PARITY = "REFUSAL_PARITY"
ERROR_ATTRIBUTE_PARITY = "ERROR_ATTRIBUTE_PARITY"
ERROR_CODE_VOCABULARY = "ERROR_CODE_VOCABULARY"
INTEGRITY_CODE_VOCABULARY = "INTEGRITY_CODE_VOCABULARY"
VALUE_DIGEST_DEFINITION = "VALUE_DIGEST_DEFINITION"
SET_ORDER_DIVERGENCE = "SET_ORDER_DIVERGENCE"
REASON_CODE_PARITY = "REASON_CODE_PARITY"
VECTOR_SET_DRIFT = "VECTOR_SET_DRIFT"
VECTOR_FILE_UNUSABLE = "VECTOR_FILE_UNUSABLE"
CANON_DIVERGENCE = "CANON_DIVERGENCE"
SCHEMA_ID_PARITY = "SCHEMA_ID_PARITY"
SCHEMA_NOT_MIRRORED = "SCHEMA_NOT_MIRRORED"


def _d(h: str) -> str:
    return hashing.digest_of(h)


def _short(h: Optional[str]) -> Optional[str]:
    return h


def _norm(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _contracts_cls(ctx: Context, schema_id: str):
    reg = convert.registry()
    if schema_id in reg.records:
        return reg.records[schema_id][0]
    return reg.contracts_only_records[schema_id]


def _is_contracts_only(ctx: Context, schema_id: str) -> bool:
    return schema_id in convert.registry().contracts_only_records


def _canon_digest_of_contracts_form(ctx: Context, obj: Any) -> str:
    """canon-v1 over the contracts canonical form (for a type the harness does not mirror, the plan family)."""
    return ctx.neutral.canon.canon_hash(obj.canonical_form())


def _record_vector(vector_id: str, source: str, neutral_h: str, contracts_h: str, golden_h: str) -> bool:
    equal = _d(neutral_h) == _d(contracts_h) == _d(golden_h)
    EVIDENCE.vector(vector_id, source, neutral_h, contracts_h, golden_h, equal)
    return equal


# -- CHK1 ----------------------------------------------------------------------------------------------------------------

def _load_contracts(ctx: Context, schema_id: str, data: Dict[str, Any], what: str):
    try:
        return _contracts_cls(ctx, schema_id).from_json(copy.deepcopy(data))
    except Exception as exc:
        fail(SOURCE_REFUSED, f"contracts refused {what}: {exc}", cause_code=getattr(exc, "code", None))


def _convert(fn: Callable[[Any], Any], obj: Any, what: str) -> Any:
    try:
        return fn(obj)
    except BridgeError as exc:
        fail(HASH_DIVERGENCE if exc.code == "HASH_DISAGREEMENT" else CONVERSION_REFUSED,
             f"{what}: {exc.message}", bridge_code=exc.code, **{k: v for k, v in exc.details.items()
                                                                if isinstance(v, (str, int, bool, type(None)))})


def run_rec(ctx: Context, item: Item) -> None:
    d = item.data
    case = d["case"]
    vid = f"{d['file']}#cases/{d['name']}"
    obj = _load_contracts(ctx, case["schema_id"], D.case_input(case), d["name"])
    contracts_h = obj.content_hash
    if _is_contracts_only(ctx, case["schema_id"]):
        neutral_h = _canon_digest_of_contracts_form(ctx, obj)
    else:
        neutral_h = convert.neutral_digest(_convert(convert.from_contracts, obj, d["name"]))
    if not _record_vector(vid, "contracts_golden", neutral_h, contracts_h, case["hash"]):
        fail(HASH_DIVERGENCE if _d(neutral_h) != _d(contracts_h) else GOLDEN_MISMATCH,
             f"{d['name']}: canon-v1, rcv1 and the golden hash are not one digest",
             golden=case["hash"], rcv1=contracts_h, canon_v1=neutral_h)


def run_val(ctx: Context, item: Item) -> None:
    d = item.data
    entry = d["entry"]
    vid = f"{d['file']}#values/{d['name']}"
    reg = convert.registry()
    t = entry["type"]
    pair = reg.values.get(t)
    if pair is not None:
        try:
            obj = pair[0].from_json(copy.deepcopy(entry["input"]))
        except Exception as exc:
            fail(SOURCE_REFUSED, f"contracts refused {d['name']}: {exc}", cause_code=getattr(exc, "code", None))
        contracts_h = obj.value_hash()
        neutral_h = convert.neutral_digest(_convert(convert.from_contracts, obj, d["name"]))
    else:
        cls = reg.contracts_only_values.get(t)
        if cls is None:
            fail(SCHEMA_NOT_MIRRORED, f"{t} is neither mirrored nor a recorded contracts-only value")
        obj = cls.from_json(copy.deepcopy(entry["input"]))
        contracts_h = obj.value_hash()
        neutral_h = _canon_digest_of_contracts_form(ctx, obj)
    if not _record_vector(vid, "contracts_golden", neutral_h, contracts_h, entry["hash"]):
        fail(HASH_DIVERGENCE if _d(neutral_h) != _d(contracts_h) else GOLDEN_MISMATCH,
             f"{d['name']}: canon-v1, rcv1 and the golden hash are not one digest",
             golden=entry["hash"], rcv1=contracts_h, canon_v1=neutral_h)


def _assertion_sets(ctx: Context, assertions: List[Dict[str, Any]]) -> Tuple[str, str]:
    c, n = ctx.contracts, ctx.neutral
    c_set = [c.AssertionSpec.from_json(copy.deepcopy(a)) for a in assertions]
    n_set = [n.records.AssertionSpec.from_json(copy.deepcopy(a)) for a in assertions]
    return c.assertion_set_hash(c_set), n.records.assertion_set_hash(n_set)


def run_aset(ctx: Context, item: Item) -> None:
    d = item.data
    aset = d["aset"]
    try:
        contracts_h, neutral_h = _assertion_sets(ctx, aset["assertions"])
    except Exception as exc:
        fail(SOURCE_REFUSED, f"a side refused the assertion set {d['name']}: {exc}", cause_code=getattr(exc, "code", None))
    if not _record_vector(f"{d['file']}#assertion_sets/{d['name']}", "contracts_golden", neutral_h, contracts_h,
                          aset["hash"]):
        fail(HASH_DIVERGENCE, f"assertion set {d['name']}: canon-v1, rcv1 and the golden hash are not one digest",
             golden=aset["hash"], rcv1=contracts_h, canon_v1=neutral_h)


def run_rel(ctx: Context, item: Item) -> None:
    rel, sets = item.data["relation"], item.data["sets"]
    for kind in ("equal", "differ"):
        if kind not in rel:
            continue
        pairs = [rel[kind]] if kind == "equal" else rel[kind]
        for a, b in pairs:
            ha = _assertion_sets(ctx, sets[a]["assertions"])
            hb = _assertion_sets(ctx, sets[b]["assertions"])
            for side, x, y in (("rcv1", ha[0], hb[0]), ("canon-v1", ha[1], hb[1])):
                if (x == y) != (kind == "equal"):
                    fail(HASH_DIVERGENCE, f"relation {kind} {a} / {b} does not hold under {side}", sets=[a, b],
                         first=x, second=y)


def run_canon(ctx: Context, item: Item) -> None:
    d = item.data
    v = d["vector"]
    n, cc = ctx.neutral, deps.contracts_package_module("canonical")
    vid = f"{d['file']}#{v['id']}"
    try:
        text = n.canon.canonical_text(copy.deepcopy(v["input"]))
        neutral_h = n.canon.canon_hash(copy.deepcopy(v["input"]))
    except Exception as exc:
        fail(CANON_DIVERGENCE, f"the neutral canonicalizer refused a vector the contracts side accepts: {exc}", vector=vid)
    contracts_h = cc.content_hash(copy.deepcopy(v["input"]))
    EVIDENCE.vector(vid, "contracts_golden", neutral_h, contracts_h, v["rcv1"],
                    _d(neutral_h) == _d(contracts_h) == _d(v["rcv1"]))
    if text != v["canonical_json"]:
        fail(CANON_DIVERGENCE, f"{vid}: canonical text differs", expected=v["canonical_json"], canon_v1_text=text)
    if neutral_h.removeprefix("canon-v1:") != v["sha256_hex"]:
        fail(CANON_DIVERGENCE, f"{vid}: canon-v1 digest differs from the vector", expected=v["rcv1"], canon_v1=neutral_h)
    if contracts_h != v["rcv1"]:
        fail(GOLDEN_MISMATCH, f"{vid}: the contracts side no longer reproduces its own vector", expected=v["rcv1"],
             rcv1=contracts_h)


def run_canon_refusal(ctx: Context, item: Item) -> None:
    r = item.data["refusal"]
    cc = deps.contracts_package_module("canonical")
    refused = {}
    for side, fn in (("neutral", lambda: ctx.neutral.canon.canon_hash(copy.deepcopy(r["input"]))),
                     ("contracts", lambda: cc.content_hash(copy.deepcopy(r["input"])))):
        try:
            fn()
            refused[side] = False
        except Exception:
            refused[side] = True
    if not all(refused.values()):
        fail(CANON_DIVERGENCE, f"{r['id']}: both sides must refuse to canonicalize this input", refused=refused)


def run_bad_file(ctx: Context, item: Item) -> None:
    d = item.data
    fail(VECTOR_FILE_UNUSABLE, f"{d['side']} vector file {d['rel']} cannot be used: {d['error']}", **d)


def _neutral_predicate(ctx: Context, op: str, expected: Any):
    r = ctx.neutral.records
    kwargs = {"op": r.PredicateOp(op)}
    if expected is not None:
        kwargs["expected"] = copy.deepcopy(expected)
    return r.Predicate(**kwargs)


def run_pred(ctx: Context, item: Item) -> None:
    e = item.data["entry"]
    c = ctx.contracts
    contracts_pred = c.Predicate(c.PredicateOp(e["op"]), copy.deepcopy(e["expected"]))
    neutral_h = ctx.neutral.canon.canon_hash(_neutral_predicate(ctx, e["op"], e["expected"]).canonical_form())
    if not _record_vector(f"{item.data['file']}#predicate/{e['id']}", "contracts_golden", neutral_h, contracts_pred.digest,
                          e["expected_hash"]):
        fail(HASH_DIVERGENCE, f"expected_hash of predicate {e['id']} is not one digest", golden=e["expected_hash"],
             rcv1=contracts_pred.digest, canon_v1=neutral_h)


def _contracts_value_digest(ctx: Context, entry: Dict[str, Any]) -> str:
    c = ctx.contracts
    if entry["kind"] == "secret_ref":
        sr = deps.contracts_package_module("protocol.secrets").SecretRef
        return sr(**entry["value"]).fingerprint()
    if entry["kind"] == "string":
        return c.value_digest(entry["value"])
    return c.json_value_digest(copy.deepcopy(entry["value"]))


def run_valdigest(ctx: Context, item: Item) -> None:
    e = item.data["entry"]
    n = ctx.neutral
    contracts_h = _contracts_value_digest(ctx, e)
    receipts = deps.neutral_module("receipts")
    r = n.records
    if e["kind"] == "string":
        neutral_h = receipts.value_digest(r.Action(kind=r.ActionKind.FILL, value=e["value"]))
    elif e["kind"] == "secret_ref":
        neutral_h = receipts.value_digest(r.Action(kind=r.ActionKind.FILL, secret_ref=r.SecretRef(**e["value"])))
    else:
        neutral_h = n.canon.canon_hash(copy.deepcopy(e["value"]))
    if not _record_vector(f"{item.data['file']}#value_digest/{e['id']}", "contracts_golden", neutral_h, contracts_h,
                          e["digest"]):
        if _d(contracts_h) != _d(e["digest"]):
            fail(GOLDEN_MISMATCH, f"the contracts side does not reproduce the value digest {e['id']}",
                 golden=e["digest"], rcv1=contracts_h)
        fail(VALUE_DIGEST_DEFINITION, f"value digest {e['id']}: the harness digest is not rcv1 of the value's canonical "
             "JSON text", kind=e["kind"], golden=e["digest"], rcv1=contracts_h, canon_v1=neutral_h)


def _navigate(form: Any, path: str) -> Any:
    for part in path.split("."):
        form = form[part]
    return form


def run_setorder(ctx: Context, item: Item) -> None:
    case = item.data["case"]
    file = item.data["file"]
    data = copy.deepcopy(case["record_listed"])
    sid = data.get("schema_id")
    vid = f"{file}#set_ordering/{case['id']}"
    reg = convert.registry()
    try:
        c_obj = _contracts_cls(ctx, sid).from_json(copy.deepcopy(data))
    except Exception as exc:
        fail(SOURCE_REFUSED, f"contracts refused {case['id']}: {exc}", cause_code=getattr(exc, "code", None))
    contracts_h = c_obj.content_hash
    if contracts_h != case["rcv1"]:
        fail(GOLDEN_MISMATCH, f"{case['id']}: contracts does not reproduce its own ordering vector", golden=case["rcv1"],
             rcv1=contracts_h)
    if _is_contracts_only(ctx, sid):
        neutral_h = _canon_digest_of_contracts_form(ctx, c_obj)
        neutral_order = None
        differing = []
    else:
        try:
            n_obj = reg.records[sid][1].from_json(copy.deepcopy(data))
        except Exception as exc:
            fail(SOURCE_REFUSED, f"the neutral module refused {case['id']}: {exc}", cause_code=getattr(exc, "code", None))
        neutral_h = n_obj.canon_hash()
        neutral_order = _navigate(n_obj.to_json(), case["field"])
        differing = _differing_lists(c_obj.canonical_form(), n_obj.canonical_form())
    equal = _record_vector(vid, "contracts_golden", neutral_h, contracts_h, case["rcv1"])
    if not equal:
        fail(SET_ORDER_DIVERGENCE, f"{case['id']}: the neutral module orders {case['record']}.{case['field']} differently",
             rule=case["order"], key=case.get("key"), golden=case["rcv1"], rcv1=contracts_h, canon_v1=neutral_h,
             hash_if_ordered_the_other_way=case.get("rcv1_if_ordered_the_other_way"),
             neutral_equals_other_rule=bool(case.get("rcv1_if_ordered_the_other_way")
                                            and _d(neutral_h) == _d(case["rcv1_if_ordered_the_other_way"])),
             differing_fields=differing, canonical_order=_order_keys(case["canonical"], case.get("key")),
             neutral_order=_order_keys(neutral_order, case.get("key")))


def _strip_none(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _strip_none(x) for k, x in v.items() if x is not None}
    if isinstance(v, list):
        return [_strip_none(x) for x in v]
    return v


def _differing_lists(a: Any, b: Any, path: str = "", _top: bool = True) -> List[str]:
    """Paths of lists that hold the same elements in a different order in two canonical forms of one record (null
    members are absent in a canonical form, so they are dropped first)."""
    if _top:
        a, b = _strip_none(a), _strip_none(b)
    out: List[str] = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) & set(b)):
            out += _differing_lists(a[k], b[k], f"{path}.{k}" if path else k, False)
    elif isinstance(a, list) and isinstance(b, list):
        if a != b and sorted(map(_norm, a)) == sorted(map(_norm, b)):
            out.append(path)
        elif len(a) == len(b):
            for i, (x, y) in enumerate(zip(a, b)):
                out += _differing_lists(x, y, f"{path}[{i}]", False)
    return out


def _order_keys(items: Any, key: Optional[str]) -> Any:
    if not isinstance(items, list):
        return items
    return [i.get(key, _norm(i)) if isinstance(i, dict) and key else (_norm(i) if isinstance(i, dict) else i)
            for i in items]


def run_sections(ctx: Context, item: Item) -> None:
    doc, files = item.data["doc"], item.data["files"]
    ext = doc.get("extends")
    if ext:
        base = [f for f in files if f.side == "contracts" and f.rel == ext["file"]]
        if not base:
            fail(VECTOR_SET_DRIFT, f"the addendum extends {ext['file']}, which is not a pinned vector file")
        with open(ctx.pins.contracts.vector_path(ext["file"]), "rb") as handle:
            sha = hashlib.sha256(handle.read()).hexdigest()
        if sha != ext["sha256"]:
            fail(VECTOR_SET_DRIFT, "the addendum was written against a different base vector file", expected=ext["sha256"],
                 actual=sha)
    ids = {v["id"] for v in doc.get("vectors", [])}
    for section in ("predicates", "value_digests", "set_ordering"):
        entries = doc.get(section, [])
        entries = entries.get("cases", []) if isinstance(entries, dict) else entries
        for e in entries:
            ref = e.get("hashed_form_vector") or e.get("vector")
            if ref is not None and ref not in ids:
                fail(VECTOR_SET_DRIFT, f"{section} entry {e['id']} names vector {ref}, which the file does not hold")
    verifier = deps.neutral_module("verifier")
    for rel in doc.get("predicate_relations", []):
        c_specs = [ctx.contracts.AssertionSpec.from_json(copy.deepcopy(a)) for a in rel["assertions"]]
        n_specs = [ctx.neutral.records.AssertionSpec.from_json(copy.deepcopy(a)) for a in rel["assertions"]]
        got = {"rcv1": [x.content_hash for x in c_specs], "canon-v1": [x.canon_hash() for x in n_specs]}
        for side, hs in got.items():
            if [_d(h) for h in hs] != [_d(h) for h in rel["assertion_hashes"]]:
                fail(HASH_DIVERGENCE, f"assertion hashes of a predicate relation differ under {side}",
                     golden=rel["assertion_hashes"], got=hs)
        eh = {"rcv1": [x.expected_hash for x in c_specs], "canon-v1": [verifier.expected_hash(x) for x in n_specs]}
        for side, hs in eh.items():
            same = len({_d(h) for h in hs}) == 1
            if same != bool(rel["expected_hash_equal"]) or _d(hs[0]) != _d(rel["expected_hash"]):
                fail(HASH_DIVERGENCE, f"expected_hash of a predicate relation differs under {side}",
                     golden=rel["expected_hash"], got=hs)


def _variant_payload(d: Dict[str, Any]) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    v = d["variant"]
    case = d["golden"]["cases"][v.base_case]
    data = D.case_input(case)
    v.edit(data)
    return case["schema_id"], data, case


def run_variant(ctx: Context, item: Item) -> None:
    sid, data, _ = _variant_payload(item.data)
    v = item.data["variant"]
    obj = _load_contracts(ctx, sid, data, f"variant {v.variant_id}")
    contracts_h = obj.content_hash
    try:
        neutral_h = convert.neutral_digest(convert.from_contracts(obj))
    except BridgeError as exc:
        EVIDENCE.vector(f"variant:{v.variant_id}", "contracts_golden", "", contracts_h, contracts_h, False)
        fail(HASH_DIVERGENCE if exc.code == "HASH_DISAGREEMENT" else CONVERSION_REFUSED,
             f"variant {v.variant_id}: {v.why}", rcv1=contracts_h, bridge_code=exc.code, message=exc.message)
    _record_vector(f"variant:{v.variant_id}", "contracts_golden", neutral_h, contracts_h, contracts_h)


def run_reason_code(ctx: Context, item: Item) -> None:
    members = item.data["members"]
    g = item.data["golden"][0].data
    case = g["cases"]["fault_recovery"]
    undeclared, not_equal = [], []
    for member in members:
        data = D.case_input(case)
        data["reason_code"] = member
        data["result"] = "NOT_RECOVERED"
        data["postcondition_verified"] = False
        obj = _load_contracts(ctx, case["schema_id"], data, f"fault_recovery reason_code {member}")
        neutral = _convert(convert.from_contracts, obj, f"reason_code {member}")
        declared = {i.name for i in ctx.neutral.records.field_infos(type(neutral))}
        if "reason_code" not in declared:
            undeclared.append(member)
        elif getattr(neutral, "reason_code", None) is None or str(getattr(neutral, "reason_code")) != member:
            not_equal.append(member)
    if undeclared or not_equal:
        fail(REASON_CODE_PARITY, "the neutral FaultRecovery does not carry the contracts reason_code: it has no declared "
             "field, so the value survives only as an unrecognised extra", members_without_a_declared_field=undeclared,
             members_not_preserved=not_equal, vocabulary_size=len(members))


# -- CHK2 ----------------------------------------------------------------------------------------------------------------

def run_nrec(ctx: Context, item: Item) -> None:
    d = item.data
    case = d["case"]
    sid = case["schema_id"]
    reg = convert.registry()
    if sid not in reg.records:
        return _nrec_plan(ctx, d)
    try:
        n_obj = reg.records[sid][1].from_json(D.case_input(case))
    except Exception as exc:
        fail(SOURCE_REFUSED, f"the neutral module refused the golden input {d['name']}: {exc}",
             cause_code=getattr(exc, "code", None))
    neutral_h = n_obj.canon_hash()
    contracts_h = convert.contracts_digest(_convert(convert.to_contracts, n_obj, d["name"]))
    if not _record_vector(f"{d['file']}#cases/{d['name']}", "harness_neutral", neutral_h, contracts_h, case["hash"]):
        fail(HASH_DIVERGENCE, f"{d['name']}: neutral canon-v1, contracts rcv1 and the golden hash are not one digest",
             golden=case["hash"], rcv1=contracts_h, canon_v1=neutral_h)


def _nrec_plan(ctx: Context, d: Dict[str, Any]) -> None:
    """The plan family is contracts-only: the neutral canon-v1 over the plan's data must still equal rcv1."""
    case = d["case"]
    obj = _load_contracts(ctx, case["schema_id"], D.case_input(case), d["name"])
    neutral_h = _canon_digest_of_contracts_form(ctx, obj)
    if not _record_vector(f"{d['file']}#cases/{d['name']}", "harness_neutral", neutral_h, obj.content_hash, case["hash"]):
        fail(HASH_DIVERGENCE, f"{d['name']}: canon-v1 over the plan data differs from rcv1", golden=case["hash"],
             rcv1=obj.content_hash, canon_v1=neutral_h)


def run_nval(ctx: Context, item: Item) -> None:
    d = item.data
    entry = d["entry"]
    reg = convert.registry()
    pair = reg.values.get(entry["type"])
    if pair is None:
        cls = reg.contracts_only_values.get(entry["type"])
        if cls is None:
            fail(SCHEMA_NOT_MIRRORED, f"{entry['type']} is neither mirrored nor a recorded contracts-only value")
        obj = cls.from_json(copy.deepcopy(entry["input"]))
        neutral_h = _canon_digest_of_contracts_form(ctx, obj)
        contracts_h = obj.value_hash()
    else:
        try:
            n_obj = pair[1].from_json(copy.deepcopy(entry["input"]))
        except Exception as exc:
            fail(SOURCE_REFUSED, f"the neutral module refused {d['name']}: {exc}", cause_code=getattr(exc, "code", None))
        neutral_h = n_obj.canon_hash()
        contracts_h = convert.contracts_digest(_convert(convert.to_contracts, n_obj, d["name"]))
    if not _record_vector(f"{d['file']}#values/{d['name']}", "harness_neutral", neutral_h, contracts_h, entry["hash"]):
        fail(HASH_DIVERGENCE, f"{d['name']}: neutral canon-v1, contracts rcv1 and the golden hash are not one digest",
             golden=entry["hash"], rcv1=contracts_h, canon_v1=neutral_h)


def run_nvariant(ctx: Context, item: Item) -> None:
    sid, data, _ = _variant_payload(item.data)
    v = item.data["variant"]
    try:
        n_obj = convert.registry().records[sid][1].from_json(data)
    except Exception as exc:
        fail(SOURCE_REFUSED, f"the neutral module refused variant {v.variant_id}: {exc}",
             cause_code=getattr(exc, "code", None))
    neutral_h = n_obj.canon_hash()
    try:
        contracts_h = convert.contracts_digest(convert.to_contracts(n_obj))
    except BridgeError as exc:
        EVIDENCE.vector(f"variant:{v.variant_id}", "harness_neutral", neutral_h, "", neutral_h, False)
        fail(HASH_DIVERGENCE if exc.code == "HASH_DISAGREEMENT" else CONVERSION_REFUSED,
             f"variant {v.variant_id}: {v.why}", canon_v1=neutral_h, bridge_code=exc.code, message=exc.message)
    _record_vector(f"variant:{v.variant_id}", "harness_neutral", neutral_h, contracts_h, neutral_h)


def run_nvec(ctx: Context, item: Item) -> None:
    d = item.data
    v = d["vector"]
    cc = deps.contracts_package_module("canonical")
    vid = f"{d['file']}#{v['id']}"
    try:
        neutral_text = ctx.neutral.canon.canonical_text(copy.deepcopy(v["input"]))
        neutral_h = ctx.neutral.canon.canon_hash(copy.deepcopy(v["input"]))
    except Exception as exc:
        fail(CANON_DIVERGENCE, f"the neutral canonicalizer refused its own vector {vid}: {exc}")
    contracts_h = cc.content_hash(copy.deepcopy(v["input"]))
    EVIDENCE.vector(vid, "harness_neutral", neutral_h, contracts_h, v["rcv1"],
                    _d(neutral_h) == _d(contracts_h) == _d(v["rcv1"]))
    if neutral_text != v["canonical_json"] or _d(neutral_h) != v["sha256_hex"]:
        fail(CANON_DIVERGENCE, f"{vid}: the neutral module does not reproduce its own vector", expected=v["rcv1"],
             canon_v1=neutral_h)
    if contracts_h != v["rcv1"]:
        fail(HASH_DIVERGENCE, f"{vid}: contracts rcv1 differs from the harness vector", expected=v["rcv1"],
             rcv1=contracts_h)


def run_vecset(ctx: Context, item: Item) -> None:
    d = item.data
    missing, different = [], []
    index = {hv["id"]: hv for hf in d["harness"] for hv in hf.data["vectors"]}
    for v in d["vectors"]:
        hv = index.get(v["id"])
        if hv is None:
            missing.append(v["id"])
        elif hv["rcv1"] != v["rcv1"] or hv["canonical_json"] != v["canonical_json"]:
            different.append({"id": v["id"], "contracts": v["rcv1"], "harness": hv["rcv1"]})
    if missing or different:
        fail(VECTOR_SET_DRIFT, f"the harness vector files do not cover {d['file']}: a contracts golden change needs a "
             "matching harness vector change", file=d["file"], contracts_vectors=len(d["vectors"]),
             missing_in_harness=len(missing), missing_ids=missing[:200], different=different,
             harness_files=[hf.name for hf in d["harness"]])


def run_inventory(ctx: Context, item: Item) -> None:
    contracts_inv = item.data["contracts"]
    harness = [h for h in item.data["harness"] if h.name == contracts_inv.name]
    if not harness:
        fail(VECTOR_SET_DRIFT, f"the harness ships no {contracts_inv.name}")
    if harness[0].data != contracts_inv.data:
        a, b = contracts_inv.data, harness[0].data
        diff = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k)) if isinstance(a, dict) else ["<document>"]
        fail(VECTOR_SET_DRIFT, "the harness copy of the field inventory differs from the contracts inventory",
             differing_sections=diff)


# -- CHK3 ----------------------------------------------------------------------------------------------------------------

def _field_sets_contracts(cls) -> Dict[str, Any]:
    fields = dataclasses.fields(cls)
    custody = set(getattr(cls, "CUSTODY", ()))
    required = {f.name for f in fields if f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING}
    return {"hashed": sorted(f.name for f in fields if f.name not in custody),
            "custody": sorted(f.name for f in fields if f.name in custody),
            "sets": sorted(getattr(cls, "SET_FIELDS", {})), "required": sorted(required)}


def _field_sets_neutral(ctx: Context, cls) -> Dict[str, Any]:
    infos = ctx.neutral.records.field_infos(cls)
    return {"hashed": sorted(i.name for i in infos if not i.custody), "custody": sorted(i.name for i in infos if i.custody),
            "sets": sorted(i.name for i in infos if i.spec.is_set), "required": sorted(i.name for i in infos if i.required)}


def run_fields(ctx: Context, item: Item) -> None:
    reg = convert.registry()
    d = item.data
    c_cls, n_cls = (reg.records if d["kind"] == "record" else reg.values)[d["key"]]
    a, b = _field_sets_contracts(c_cls), _field_sets_neutral(ctx, n_cls)
    diff = {k: {"contracts_only": sorted(set(a[k]) - set(b[k])), "neutral_only": sorted(set(b[k]) - set(a[k]))}
            for k in a if a[k] != b[k]}
    if diff:
        fail(FIELD_PARITY, f"{c_cls.__name__}: hashed, custody, set or required field sets differ", schema=c_cls.__name__,
             differences=diff)


def _populated_contracts(ctx: Context, name: str):
    reg = convert.registry()
    cls = reg.reused[name][0]
    hints = __import__("typing").get_type_hints(cls)
    kwargs = {}
    for f in dataclasses.fields(cls):
        h = hints[f.name]
        if isinstance(h, type) and issubclass(h, enum.Enum):
            kwargs[f.name] = next(iter(h))
        elif "Sequence" in str(h) or "tuple" in str(h).lower():
            kwargs[f.name] = ("x@1#sha256:" + "0" * 64,) if name == "Check" else ("x",)
        else:
            kwargs[f.name] = "x"
    if name == "Check":
        kwargs["evidence_refs"] = ("x@1#sha256:" + "0" * 64,)
    return cls(**kwargs)


def run_reused_identity(ctx: Context, item: Item) -> None:
    name = item.data["key"]
    reg = convert.registry()
    c_obj = _populated_contracts(ctx, name)
    n_cls = reg.reused[name][1]
    n_json = {}
    for i in ctx.neutral.records.field_infos(n_cls):
        if i.spec.kind == "enum":
            n_json[i.name] = next(iter(i.spec.cls)).value
        elif i.spec.kind == "tuple":
            n_json[i.name] = ["x@1#sha256:" + "0" * 64] if name == "Check" else ["x"]
        else:
            n_json[i.name] = "x"
    n_obj = n_cls.from_json(n_json)
    hashed_c, hashed_n = sorted(k for k, v in c_obj.canonical_form().items() if v is not None), sorted(n_obj.canonical_form())
    if hashed_c != hashed_n:
        fail(FIELD_PARITY, f"{name}: the fields that enter the hash differ", schema=name,
             differences={"hashed": {"contracts_only": sorted(set(hashed_c) - set(hashed_n)),
                                     "neutral_only": sorted(set(hashed_n) - set(hashed_c))}})


def run_mirrored(ctx: Context, item: Item) -> None:
    d = item.data
    conf = ctx.pins.conformance
    reg = convert.registry()
    allowed = set(conf.get("contracts_only_schemas", ()))
    if d["kind"] == "record" and d["key"] in allowed:
        return
    if d["kind"] == "value" and d["key"] in set(conf.get("contracts_only_values", ())) and d["key"] in reg.contracts_only_values:
        return
    where = "contracts" if d["kind"] in ("record", "value") and (d["key"] in reg.contracts_only_records
                                                                   or d["key"] in reg.contracts_only_values) else "neutral"
    fail(SCHEMA_NOT_MIRRORED, f"{d['key']} exists only on the {where} side and is not a recorded exception",
         schema=d["key"], side=where)


def run_schema_ids(ctx: Context, item: Item) -> None:
    c, n = ctx.contracts, ctx.neutral
    reg = convert.registry()
    rows = []
    problems = []
    for sid, (c_cls, n_cls) in sorted(reg.records.items()):
        row = {"schema_id": sid, "contracts_schema_version": c_cls.SCHEMA_VERSION,
               "neutral_schema_version": ",".join(n.schemas.SUPPORTED_SCHEMAS.get(sid, ())) or None}
        row["equal"] = n.schemas.SUPPORTED_SCHEMAS.get(sid) == (c_cls.SCHEMA_VERSION,) and n_cls.SCHEMA_ID == c_cls.SCHEMA_ID
        rows.append(row)
        if not row["equal"]:
            problems.append(row)
    asid = deps.contracts_module("spec").ASSERTION_SET_SCHEMA_ID
    row = {"schema_id": asid, "contracts_schema_version": c.AssertionSpec.SCHEMA_VERSION,
           "neutral_schema_version": ",".join(n.schemas.SUPPORTED_SCHEMAS.get(asid, ())) or None}
    row["equal"] = n.schemas.SUPPORTED_SCHEMAS.get(asid) == (c.AssertionSpec.SCHEMA_VERSION,)
    rows.append(row)
    if not row["equal"]:
        problems.append(row)
    info = {"contract_id": c.QA_CONTRACT_ID, "neutral_api": n.NEUTRAL_API,
            "contract_id_equal": c.QA_CONTRACT_ID == n.CONTRACT_ID, "schema_version_equal": c.QA_SCHEMA_VERSION == n.SCHEMA_VERSION,
            "contracts_only": sorted(reg.contracts_only_records)}
    EVIDENCE.schemas = rows
    EVIDENCE.schema_info = info
    if problems or not info["contract_id_equal"] or not info["schema_version_equal"]:
        fail(SCHEMA_ID_PARITY, "schema ids, schema versions or the contract id differ", problems=problems,
             contract_id={"contracts": c.QA_CONTRACT_ID, "neutral": n.CONTRACT_ID},
             schema_version={"contracts": c.QA_SCHEMA_VERSION, "neutral": n.SCHEMA_VERSION})


# -- CHK4 ----------------------------------------------------------------------------------------------------------------

def run_enum(ctx: Context, item: Item) -> None:
    name = item.data["key"]
    c_enum, n_enum = convert.registry().enums[name]
    a = sorted((m.name, m.value) for m in c_enum)
    b = sorted((m.name, m.value) for m in n_enum)
    if a != b:
        fail(ENUM_PARITY, f"enum {name}: members or values differ", enum=name, contracts_only=sorted(set(a) - set(b)),
             neutral_only=sorted(set(b) - set(a)))


def run_enum_presence(ctx: Context, item: Item) -> None:
    name = item.data["key"]
    conf = ctx.pins.conformance
    reg = convert.registry()
    if name in reg.contracts_only_enums and name in set(conf.get("contracts_only_enums", ())):
        return
    if name in reg.neutral_only_enums and name in set(conf.get("neutral_only_enums", ())):
        return
    side = "contracts" if name in reg.contracts_only_enums else "neutral"
    members = [m.value for m in (reg.contracts_only_enums.get(name) or reg.neutral_only_enums.get(name))]
    code = ENUM_PARITY
    if side == "contracts" and name == "IntegrityRefusalCode":
        code = INTEGRITY_CODE_VOCABULARY
    elif side == "contracts" and name == "RecoveryReason":
        code = REASON_CODE_PARITY
    fail(code, f"enum {name} exists only on the {side} side and is not a recorded exception", enum=name, side=side,
         members=members)


# -- CHK5 ----------------------------------------------------------------------------------------------------------------

def _shape(proto: type) -> Dict[str, Any]:
    methods = {}
    for name, fn in vars(proto).items():
        if inspect.isfunction(fn) and not name.startswith("_"):
            sig = inspect.signature(fn)
            methods[name] = [(p.name, p.kind.name) for p in sig.parameters.values() if p.name != "self"]
    return {"attributes": sorted(getattr(proto, "__annotations__", {})), "methods": methods,
            "runtime_checkable": bool(getattr(proto, "_is_runtime_protocol", False))}


_PAIRS = {"QAAdapter": ("QAAdapter", "NeutralQAAdapter"), "CheckAdapter": ("CheckAdapter", "NeutralCheckAdapter"),
          "BlobStore": ("BlobStore", "BlobSink"), "Redactor": ("Redactor", "Redactor")}


def _protocols(ctx: Context, pair: str):
    c_name, n_name = _PAIRS[pair]
    return getattr(ctx.contracts, c_name), getattr(deps.neutral_module("ports"), n_name)


def run_protocol(ctx: Context, item: Item) -> None:
    pair = item.data["pair"]
    c_proto, n_proto = _protocols(ctx, pair)
    a, b = _shape(c_proto), _shape(n_proto)
    problems = {}      # parameter NAMES are compared (ADR A.2.5); the kind difference is covered by a bridge test
    if a["attributes"] != b["attributes"]:
        problems["attributes"] = {"contracts": a["attributes"], "neutral": b["attributes"]}
    if sorted(a["methods"]) != sorted(b["methods"]):
        problems["methods"] = {"contracts_only": sorted(set(a["methods"]) - set(b["methods"])),
                               "neutral_only": sorted(set(b["methods"]) - set(a["methods"]))}
    for m in sorted(set(a["methods"]) & set(b["methods"])):
        names_a, names_b = [p for p, _ in a["methods"][m]], [p for p, _ in b["methods"][m]]
        if names_a != names_b:
            problems.setdefault("parameters", {})[m] = {"contracts": names_a, "neutral": names_b}
    if not (a["runtime_checkable"] and b["runtime_checkable"]):
        problems["runtime_checkable"] = {"contracts": a["runtime_checkable"], "neutral": b["runtime_checkable"]}
    if problems:
        fail(PROTOCOL_PARITY, f"{pair}: method names, parameter names or kinds differ", pair=pair, **problems)


def run_api_versions(ctx: Context, item: Item) -> None:
    n = ctx.neutral
    got = {"qa-adapter": (ctx.contracts.QA_ADAPTER_API_VERSION, n.schemas.ADAPTER_API_VERSION),
           "qa-check-adapter": (ctx.contracts.CHECK_ADAPTER_API_VERSION, n.schemas.CHECK_ADAPTER_API_VERSION)}
    bad = {k: v for k, v in got.items() if v[0] != v[1] or not v[0].startswith(k + "/")}
    if bad:
        fail(PROTOCOL_PARITY, "adapter api_version strings differ", api_versions=bad)


class _RefQAAdapter:
    """Written against the protocol text alone (not generated from either side), so signature drift is detected."""
    adapter_id = "reference"
    adapter_version = "0"
    api_version = "qa-adapter/1"

    def open_session(self, profile): ...
    def observe(self, s, req): ...
    def locate(self, s, target, *, mode): ...
    def act(self, s, action, target): ...
    def assert_(self, s, subject): ...
    def capture(self, s, kinds): ...
    def reset(self, s, scope): ...
    def close_session(self, s): ...


class _RefCheckAdapter:
    adapter_id = "reference"
    adapter_version = "0"
    api_version = "qa-check-adapter/1"

    def open_workspace(self, profile): ...
    def resolve(self, w, ref): ...
    def run_check(self, w, subject): ...
    def capture(self, w, kinds): ...
    def reset(self, w, scope): ...
    def close_workspace(self, w): ...


def _satisfies(obj_or_cls: Any, proto: type) -> List[str]:
    """Structural problems: missing member, or a method whose parameter names differ from the protocol's."""
    shape = _shape(proto)
    problems = []
    for attr in shape["attributes"]:
        if not hasattr(obj_or_cls, attr):
            problems.append(f"missing attribute {attr}")
    for name, params in shape["methods"].items():
        fn = getattr(obj_or_cls, name, None)
        if fn is None:
            problems.append(f"missing method {name}")
            continue
        got = [(p.name, p.kind.name) for p in inspect.signature(fn).parameters.values() if p.name != "self"]
        if got != params:
            problems.append(f"{name}{got} differs from the protocol {params}")
    return problems


def run_reference_adapter(ctx: Context, item: Item) -> None:
    which = item.data["which"]
    ref = _RefQAAdapter() if which == "qa" else _RefCheckAdapter()
    pair = "QAAdapter" if which == "qa" else "CheckAdapter"
    c_proto, n_proto = _protocols(ctx, pair)
    problems = {}
    for side, proto in (("contracts", c_proto), ("neutral", n_proto)):
        found = _satisfies(ref, proto)
        if found or not isinstance(ref, proto):
            problems[side] = found or ["isinstance check failed"]
    if problems:
        fail(PROTOCOL_PARITY, f"a reference {pair} does not satisfy both protocols", **problems)


def run_qa_playwright(ctx: Context, item: Item) -> None:
    conf = ctx.pins.conformance
    target = conf.get("qa_playwright_class", "")
    if not target:
        if conf.get("qa_playwright_required", False):
            fail(PROTOCOL_PARITY, "qa_playwright_required is set but no qa_playwright_class is configured")
        return          # not present yet (the adapter package arrives later): nothing to compare, recorded in pins.toml
    module, _, cls_name = target.partition(":")
    try:
        cls = getattr(__import__(module, fromlist=[cls_name]), cls_name)
    except Exception as exc:
        fail(PROTOCOL_PARITY, f"the configured qa-playwright adapter {target} cannot be imported: {exc}")
    problems = {}
    for side, proto in (("contracts", ctx.contracts.QAAdapter), ("neutral", deps.neutral_module("ports").NeutralQAAdapter)):
        found = _satisfies(cls, proto)
        if found:
            problems[side] = found
    if problems:
        fail(PROTOCOL_PARITY, f"{target} does not satisfy both QAAdapter forms", **problems)


# -- CHK6 ----------------------------------------------------------------------------------------------------------------

def _outcome_of_contracts_error(exc: BaseException) -> Dict[str, Any]:
    out = {"refused": True, "code": getattr(exc, "code", type(exc).__name__)}
    if getattr(exc, "run_outcome", None):
        out.update(run_outcome=exc.run_outcome, run_reason=exc.run_reason)
    return out


def _contracts_refusal(ctx: Context, op: str, data: Dict[str, Any]) -> Dict[str, Any]:
    c = ctx.contracts
    try:
        if op == "verify_assertion_set":
            c.verify_assertion_set([c.AssertionSpec.from_json(a) for a in data["assertions"]], data["pinned_assertion_set_hash"])
        elif op == "parse_test_spec":
            c.TestSpec.from_json(data)
        elif op == "check_result_matches_assertion":
            c.check_result_matches_assertion(c.AssertionResult.from_json(data["result"]), c.AssertionSpec.from_json(data["assertion"]))
        elif op == "parse_recovery_candidate":
            c.parse_recovery_candidate(data)
        elif op == "verify_manifest_against_spec":
            c.verify_manifest_against_spec(c.RunManifest.from_json(data["manifest"]), c.TestSpec.from_json(data["spec"]))
        elif op == "classify_coverage":
            found = c.classify_coverage(data["declared"], data["executed"], data["skipped"])
            return {"classification": None if found is None else [found[0].value, found[1]]}
        elif op == "parse_run_manifest":
            c.RunManifest.from_json(data)
        elif op == "parse_qa_plan":
            c.QAPlan.from_json(data)
        elif op == "parse_assertion_spec":
            c.AssertionSpec.from_json(data)
        elif op == "parse_fault_event":
            c.FaultEvent.from_json(data)
        elif op == "outcome_to_verdict":
            return {"verdict": c.outcome_to_verdict(data["outcome"]).value}
        elif op == "verify_pin_well_formed":
            c.verify_pin_well_formed(data["pin"])
        elif op == "load_pinned_assertion_set":
            stored = None if data["stored"] is None else [c.AssertionSpec.from_json(a) for a in data["stored"]]
            c.load_pinned_assertion_set(data["pin"], stored)
        elif op == "verify_check_program":
            c.verify_check_program(c.CheckProgramRef.from_json(data["check_program_ref"]), data["registered_hash"])
        elif op == "check_batch_not_halted":
            c.check_batch_not_halted(data["halted_by"])
        else:
            fail(REFUSAL_PARITY, f"unknown refusal operation {op!r}: the suite cannot run it", operation=op)
    except ConformanceFailure:
        raise
    except Exception as exc:
        if hasattr(exc, "code"):
            return _outcome_of_contracts_error(exc)
        raise
    return {"refused": False}


def _outcome_of_neutral_error(exc: BaseException, layer: str) -> Dict[str, Any]:
    out = {"refused": True, "code": getattr(exc, "code", type(exc).__name__)}
    if getattr(exc, "run_outcome", None):
        out.update(run_outcome=exc.run_outcome, run_reason=exc.run_reason)
    return out


_PARSE_RECORD = {"parse_test_spec": "test-spec", "parse_run_manifest": "run-manifest", "parse_assertion_spec": "assertion-spec",
                 "parse_fault_event": "fault-event"}


def _neutral_load_frozen(ctx: Context, pin: Any, stored: Any, programs: Dict[Tuple[str, str], str]):
    n = ctx.neutral
    verifier, specstore = deps.neutral_module("verifier"), deps.neutral_module("specstore")
    sets = {}
    if stored is not None and isinstance(pin, str) and n.canon.is_contract_ref(pin):
        sets[pin] = stored
    store = specstore.InMemorySpecStore(sets)
    lineage = verifier.ApprovedLineage([pin] if isinstance(pin, str) and n.canon.is_contract_ref(pin) else [])
    return verifier.load_frozen_assertions(store, pin, lineage=lineage, programs=specstore.InMemoryProgramRegistry(programs))


def _neutral_refusal(ctx: Context, op: str, data: Dict[str, Any], golden: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    n = ctx.neutral
    r = n.records
    verifier, classify = deps.neutral_module("verifier"), deps.neutral_module("classify")
    recovery_types = deps.neutral_module("recovery_types")
    layer = "neutral"
    try:
        if op == "verify_assertion_set":
            verifier.FrozenAssertionSet(assertion_set_hash=data["pinned_assertion_set_hash"],
                                        assertions=tuple(r.AssertionSpec.from_json(a) for a in data["assertions"]))
        elif op in _PARSE_RECORD:
            cls = r.RECORDS_BY_SCHEMA_ID["runtime-contracts/qa/" + _PARSE_RECORD[op]]
            obj = cls.from_json(copy.deepcopy(data))
            layer = "bridge"
            convert.to_contracts(obj)
        elif op == "check_result_matches_assertion":
            verifier.check_result_matches_assertion(copy.deepcopy(data["result"]), r.AssertionSpec.from_json(data["assertion"]))
        elif op == "parse_recovery_candidate":
            recovery_types.parse_recovery_output([copy.deepcopy(data)])
        elif op == "verify_manifest_against_spec":
            spec = r.TestSpec.from_json(copy.deepcopy(data["spec"]))
            verifier.verify_manifest_against_spec(r.RunManifest.from_json(copy.deepcopy(data["manifest"])), spec.assertions)
        elif op == "classify_coverage":
            found = classify.classify_coverage(data["declared"], data["executed"], data["skipped"])
            return {"classification": None if found is None else [found[0].value, found[1]]}
        elif op == "parse_qa_plan":
            from ..plan import validate_plan
            layer = "bridge"
            try:
                validate_plan(copy.deepcopy(data))
            except BridgeError as exc:
                return {"refused": True, "code": exc.code, "layer": "bridge"}
        elif op == "outcome_to_verdict":
            return {"verdict": classify.outcome_to_verdict(data["outcome"]).value}
        elif op == "verify_pin_well_formed":
            _neutral_load_frozen(ctx, data["pin"], _reference_set(ctx), {})
        elif op == "load_pinned_assertion_set":
            _neutral_load_frozen(ctx, data["pin"], data["stored"], {})
        elif op == "verify_check_program":
            ref = copy.deepcopy(data["check_program_ref"])
            script = _script_assertion(ctx, ref)
            pin = n.records.assertion_set_hash([r.AssertionSpec.from_json(copy.deepcopy(script))])
            pin = "rcv1:" + pin.removeprefix("canon-v1:")
            programs = {} if data["registered_hash"] is None else {(ref["id"], ref["version"]): data["registered_hash"]}
            _neutral_load_frozen(ctx, pin, [script], programs)
        elif op == "check_batch_not_halted":
            latch = verifier.HaltLatch()
            if data["halted_by"] is not None:
                latch.trip(n.errors.ERRORS_BY_CODE.get(data["halted_by"], n.errors.AssertionHashMismatch)("halting refusal"))
            latch.check()
        else:
            fail(REFUSAL_PARITY, f"unknown refusal operation {op!r}: the suite cannot run it", operation=op)
    except ConformanceFailure:
        raise
    except Exception as exc:
        if hasattr(exc, "code"):
            out = _outcome_of_neutral_error(exc, layer)
            out["layer"] = layer
            if layer == "bridge" and getattr(exc, "details", {}).get("cause_code"):
                out["code"] = exc.details["cause_code"]
                out.pop("run_outcome", None)
                out.pop("run_reason", None)
            return out
        raise
    return {"refused": False}


def _reference_set(ctx: Context) -> List[Dict[str, Any]]:
    """The golden reference assertion set, as stored documents (what a store would hold under the reference pin)."""
    files = D.load_vector_files(ctx.pins)
    g = D.only(files, "contracts", "golden")[0].data
    return copy.deepcopy(g["assertion_sets"]["reference"]["assertions"])


def _script_assertion(ctx: Context, ref: Dict[str, Any]) -> Dict[str, Any]:
    files = D.load_vector_files(ctx.pins)
    g = D.only(files, "contracts", "golden")[0].data
    script = D.case_input(g["cases"]["assertion_spec_script"])
    script["check_program_ref"] = ref
    return script


def _strip_layer(out: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in out.items() if k != "layer"}


def _integrity_vocabulary(ctx: Context) -> Tuple[set, set]:
    """(contracts integrity refusal codes, neutral codes) used to tell the integrity-vocabulary divergence apart."""
    c = ctx.contracts
    contracts = {m.value for m in getattr(c, "IntegrityRefusalCode", ())}
    return contracts, set(_neutral_codes(ctx))


def run_refusal(ctx: Context, item: Item) -> None:
    fx = item.data["fixture"]
    op = fx["operation"] if "operation" in fx else None
    if op is None:
        fail(REFUSAL_PARITY, f"refusal fixture {fx.get('id')} names no operation")
    expect = fx["expect"]
    contracts_out = _contracts_refusal(ctx, op, copy.deepcopy(fx["input"]))
    neutral_out = _neutral_refusal(ctx, op, copy.deepcopy(fx["input"]), item.data.get("golden"))
    layer = neutral_out.get("layer", "neutral")
    neutral_cmp = _strip_layer(neutral_out)
    if contracts_out != expect:
        fail(GOLDEN_MISMATCH, f"{fx['id']}: the contracts side no longer behaves as its fixture says", operation=op,
             expected=expect, contracts=contracts_out)
    if _is_recorded_fold(ctx, expect, neutral_cmp):
        return
    if neutral_cmp != expect:
        contract_codes, neutral_codes = _integrity_vocabulary(ctx)
        code = expect.get("code")
        kind = INTEGRITY_CODE_VOCABULARY if (code in contract_codes and code not in neutral_codes) else REFUSAL_PARITY
        fail(kind, f"{fx['id']}: the neutral side answers differently to the same input", operation=op, expected=expect,
             contracts=contracts_out, neutral=neutral_cmp, refused_by=layer)


def _is_recorded_fold(ctx: Context, expect: Dict[str, Any], neutral: Dict[str, Any]) -> bool:
    """A contracts structural code the neutral module deliberately folds into SPEC_INVALID (pins.toml
    contracts_only_error_codes). Everything else about the answer must still be equal."""
    code = expect.get("code")
    fold = set(ctx.pins.conformance.get("contracts_only_error_codes", ())) - {"ASSERTION_INTEGRITY"}
    if code not in fold or neutral.get("code") != "SPEC_INVALID":
        return False
    return {k: v for k, v in neutral.items() if k != "code"} == {k: v for k, v in expect.items() if k != "code"}


def _neutral_codes(ctx: Context) -> Dict[str, type]:
    """code -> class for the neutral validation, integrity and adapter errors (errors.py and the verifier's BatchHalted)."""
    n = ctx.neutral
    out: Dict[str, type] = {}

    def walk(c):
        for s in c.__subclasses__():
            yield s
            yield from walk(s)
    deps.neutral_module("verifier")
    for cls in walk(n.errors.QAError):
        if cls.__module__.rsplit(".", 1)[-1] in ("errors", "verifier") and cls.code != "QA_ERROR":
            out[cls.code] = cls
    return out


def run_classification(ctx: Context, item: Item) -> None:
    case = item.data["case"]
    c = ctx.contracts
    got_c = c.classify_refusal(case["code"])
    got_c = None if got_c is None else [got_c[0].value, got_c[1]]
    expected = case["classification"]
    if got_c != expected:
        fail(GOLDEN_MISMATCH, f"classify_refusal({case['code']!r}) no longer matches its fixture", expected=expected,
             contracts=got_c)
    codes = _neutral_codes(ctx)
    cls = codes.get(case["code"])
    if cls is None and case["code"] == ctx.neutral.errors.REASON_ASSERTION_INTEGRITY and expected is not None:
        return          # the neutral module names the outcome reason itself with this constant
    if cls is None:
        contract_codes, _ = _integrity_vocabulary(ctx)
        fail(INTEGRITY_CODE_VOCABULARY if case["code"] in contract_codes else REFUSAL_PARITY,
             f"the neutral module has no error for {case['code']!r}, so it cannot classify it as the contracts side does",
             code=case["code"], contracts_classification=expected, neutral="no error class with this code")
    got_n = ["INCONCLUSIVE", "ASSERTION_INTEGRITY"] if getattr(cls, "run_outcome", None) else None
    if got_n != expected:
        fail(REFUSAL_PARITY, f"classification of {case['code']!r} differs", expected=expected, neutral=got_n)


def run_idempotency(ctx: Context, item: Item) -> None:
    case = item.data["case"]
    c = ctx.contracts

    class _R:
        def __init__(self, d, key):
            self.run_id, self.step_id, self.idempotency_key = d["run_id"], d["step_id"], key

    got = list(c.idempotency_key_violations(_R(r, r["idempotency_key"]) for r in case["receipts"]))
    if got != case["violations"]:
        fail(GOLDEN_MISMATCH, f"idempotency rule {case['id']}: contracts differs from its fixture", expected=case["violations"],
             contracts=got)
    idem = deps.neutral_module("idempotency")
    produced = [_R(r, idem.idempotency_key(r["run_id"], r["step_id"])) for r in case["receipts"]]
    neutral_got = list(c.idempotency_key_violations(produced))
    if neutral_got:
        fail(REFUSAL_PARITY, f"keys produced by the neutral module break the rule in case {case['id']}",
             violations=neutral_got)


def run_error_class(ctx: Context, item: Item) -> None:
    code = item.data["code"]
    c, n = ctx.contracts, ctx.neutral
    c_cls = c.ADAPTER_ERRORS.get(c.ResultCode(code)) if code in {rc.value for rc in c.ResultCode} else None
    n_cls = n.errors.ADAPTER_ERRORS.get(code)
    if c_cls is None or n_cls is None:
        fail(ERROR_ATTRIBUTE_PARITY, f"adapter error {code} exists on one side only", contracts=c_cls is not None,
             neutral=n_cls is not None)
    a, b = c_cls("m"), n_cls("m")
    ca = {"category": a.category.value, "retryable": a.retryable, "recoverable": a.recoverable, "class_hint": a.class_hint.value}
    nb = {"category": b.category.value, "retryable": b.retryable, "recoverable": b.recoverable, "class_hint": b.class_hint.value}
    if ca != nb:
        fail(ERROR_ATTRIBUTE_PARITY, f"adapter error {code}: category, retryable, recoverable or class_hint differ",
             code=code, contracts=ca, neutral=nb, differing=sorted(k for k in ca if ca[k] != nb[k]))


def run_error_vocabulary(ctx: Context, item: Item) -> None:
    c = ctx.contracts
    conf = ctx.pins.conformance
    base = deps.contracts_module("base")
    contracts_codes = {v for k, v in vars(base.Code).items() if not k.startswith("_") and isinstance(v, str)}
    contracts_codes |= {rc.value for rc in c.ResultCode if rc.value != "OK"}
    neutral_codes = set(_neutral_codes(ctx))
    contracts_only = sorted(contracts_codes - neutral_codes - set(conf.get("contracts_only_error_codes", ())))
    neutral_only = sorted(neutral_codes - contracts_codes - set(conf.get("neutral_only_error_codes", ())))
    integrity, _ = _integrity_vocabulary(ctx)
    if contracts_only or neutral_only:
        code = INTEGRITY_CODE_VOCABULARY if set(contracts_only) & integrity else ERROR_CODE_VOCABULARY
        fail(code, "the two sides define different error codes", contracts_only=contracts_only, neutral_only=neutral_only)


# -- CHK7 ----------------------------------------------------------------------------------------------------------------

def _roundtrip(ctx: Context, obj: Any, what: str) -> None:
    n_obj = _convert(convert.from_contracts, obj, what)
    back = _convert(convert.to_contracts, n_obj, what)
    if back != obj or convert.contracts_digest(back) != convert.contracts_digest(obj) or back.to_json() != obj.to_json():
        fail(ROUND_TRIP_DIFFERS, f"{what}: contracts to neutral to contracts is not the identity",
             before=convert.contracts_digest(obj), after=convert.contracts_digest(back))


def run_rt(ctx: Context, item: Item) -> None:
    d = item.data
    case = d["case"]
    if _is_contracts_only(ctx, case["schema_id"]):
        obj = _load_contracts(ctx, case["schema_id"], D.case_input(case), d["name"])
        again = _contracts_cls(ctx, case["schema_id"]).from_json(obj.to_json())
        if again != obj:
            fail(ROUND_TRIP_DIFFERS, f"{d['name']}: the contracts-only record does not round-trip through its own JSON")
        return
    _roundtrip(ctx, _load_contracts(ctx, case["schema_id"], D.case_input(case), d["name"]), d["name"])


def run_nrt(ctx: Context, item: Item) -> None:
    d = item.data
    case = d["case"]
    reg = convert.registry()
    if case["schema_id"] not in reg.records:
        return
    try:
        n_obj = reg.records[case["schema_id"]][1].from_json(D.case_input(case))
    except Exception as exc:
        fail(SOURCE_REFUSED, f"the neutral module refused {d['name']}: {exc}", cause_code=getattr(exc, "code", None))
    c_obj = _convert(convert.to_contracts, n_obj, d["name"])
    back = _convert(convert.from_contracts, c_obj, d["name"])
    if back != n_obj or back.canon_hash() != n_obj.canon_hash():
        fail(ROUND_TRIP_DIFFERS, f"{d['name']}: neutral to contracts to neutral is not the identity",
             before=n_obj.canon_hash(), after=back.canon_hash())


def run_rtval(ctx: Context, item: Item) -> None:
    d = item.data
    entry = d["entry"]
    pair = convert.registry().values.get(entry["type"])
    if pair is None:
        cls = convert.registry().contracts_only_values[entry["type"]]
        obj = cls.from_json(copy.deepcopy(entry["input"]))
        if cls.from_json(obj.to_json()) != obj:
            fail(ROUND_TRIP_DIFFERS, f"{d['name']}: the contracts-only value does not round-trip through its own JSON")
        return
    try:
        obj = pair[0].from_json(copy.deepcopy(entry["input"]))
    except Exception as exc:
        fail(SOURCE_REFUSED, f"contracts refused {d['name']}: {exc}", cause_code=getattr(exc, "code", None))
    _roundtrip(ctx, obj, d["name"])


def run_rtvariant(ctx: Context, item: Item) -> None:
    sid, data, _ = _variant_payload(item.data)
    v = item.data["variant"]
    obj = _load_contracts(ctx, sid, data, f"variant {v.variant_id}")
    try:
        _roundtrip(ctx, obj, f"variant {v.variant_id}")
    except ConformanceFailure as exc:
        exc.details.setdefault("variant", v.variant_id)
        raise


def run_unavailable(ctx: Context, item: Item) -> None:      # pragma: no cover - replaced in run_item
    d = item.data
    fail(d["code"], d["message"], **d.get("details", {}))


RUNNERS: Dict[str, Callable[[Context, Item], None]] = {
    "rec": run_rec, "val": run_val, "aset": run_aset, "rel": run_rel, "canon": run_canon, "canon_refusal": run_canon_refusal,
    "bad_file": run_bad_file, "pred": run_pred, "valdigest": run_valdigest, "setorder": run_setorder,
    "sections": run_sections, "variant": run_variant, "reason_code": run_reason_code,
    "nrec": run_nrec, "nval": run_nval, "nvariant": run_nvariant, "nvec": run_nvec, "vecset": run_vecset,
    "inventory": run_inventory,
    "fields": run_fields, "reused_identity": run_reused_identity, "mirrored": run_mirrored, "schema_ids": run_schema_ids,
    "enum": run_enum, "enum_presence": run_enum_presence,
    "protocol": run_protocol, "api_versions": run_api_versions, "reference_adapter": run_reference_adapter,
    "qa_playwright": run_qa_playwright,
    "refusal": run_refusal, "classification": run_classification, "idempotency": run_idempotency,
    "error_class": run_error_class, "error_vocabulary": run_error_vocabulary,
    "rt": run_rt, "nrt": run_nrt, "rtval": run_rtval, "rtvariant": run_rtvariant,
}


def run_item(item: Item) -> None:
    """Run one item. Raises :class:`ConformanceFailure`; returning means it passed."""
    if item.kind == "unavailable":
        d = item.data
        fail(d["code"], d["message"], **d.get("details", {}))
    runner = RUNNERS.get(item.kind)
    if runner is None:
        fail("UNKNOWN_ITEM_KIND", f"no runner for item kind {item.kind!r}", item=item.item_id)
    runner(get_context(), item)
