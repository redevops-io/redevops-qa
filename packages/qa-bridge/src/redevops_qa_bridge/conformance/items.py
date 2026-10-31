# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""What the conformance suite checks, enumerated from the pinned files and packages (ADR A.2.5 item 4).

Seven checks; each is a list of items and each item is one pytest test, so the collected count means something:

====== ===========================================================================================================
CHK1   hash equality, contracts golden to neutral: every golden case and value, assertion sets and relations, all
       canonical vectors of every pinned vector file (base and any addendum), predicate and value digests, set order
CHK2   hash equality, harness neutral vectors to contracts, and vector-set parity (a contracts vector without a
       matching harness vector fails)
CHK3   identity and custody field parity per schema; schema ids and versions
CHK4   enum parity
CHK5   protocol parity (QAAdapter, CheckAdapter, BlobStore, Redactor; reference adapter; qa-playwright when present)
CHK6   mutation-refusal parity (every refusal fixture: same reason code on both sides) and error-code parity
CHK7   round trip: contracts to neutral to contracts is the identity
====== ===========================================================================================================

If the pinned files or packages cannot be read, each check gets one ``unavailable`` item that fails with the reason, so
the run is red with a nonzero collected count and the receipt says why.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from .. import deps
from .context import Context, get_context
from .data import VectorFile, case_input, deep, load_vector_files, only
from .model import ConformanceFailure
from .variants import VARIANTS

CHECKS = {
    "CHK1": "hash-equality-contracts-to-neutral",
    "CHK2": "hash-equality-neutral-to-contracts",
    "CHK3": "identity-custody-field-parity",
    "CHK4": "enum-parity",
    "CHK5": "protocol-parity",
    "CHK6": "mutation-refusal-and-error-code-parity",
    "CHK7": "round-trip",
}


@dataclass(frozen=True)
class Item:
    check: str
    item_id: str
    kind: str
    data: Any = None

    @property
    def test_id(self) -> str:
        return f"{self.item_id}"


def _unavailable(error: ConformanceFailure) -> Dict[str, List[Item]]:
    return {c: [Item(c, "unavailable", "unavailable", {"code": error.code, "message": error.message,
                                                        "details": error.details})] for c in CHECKS}


def enumerate_items() -> Dict[str, List[Item]]:
    try:
        ctx = get_context()
        files = load_vector_files(ctx.pins)
    except ConformanceFailure as exc:
        return _unavailable(exc)
    items: Dict[str, List[Item]] = {c: [] for c in CHECKS}
    add = lambda check, item_id, kind, data=None: items[check].append(Item(check, item_id, kind, data))  # noqa: E731
    reg = _registry(ctx)

    # -- vector files that cannot be used are failures, never silently ignored
    for f in files:
        if f.kind == "unrecognized":
            add("CHK1" if f.side == "contracts" else "CHK2", f"file:{f.side}:{f.rel}", "bad_file",
                {"side": f.side, "rel": f.rel, "error": f.error or "format not recognised"})

    golden_files = only(files, "contracts", "golden")
    for gf in golden_files:
        g = gf.data
        for name, case in sorted(g["cases"].items()):
            data = {"file": gf.rel, "name": name, "case": case}
            add("CHK1", f"rec:{name}", "rec", data)
            add("CHK2", f"nrec:{name}", "nrec", data)
            add("CHK7", f"rt:{name}", "rt", data)
            add("CHK7", f"nrt:{name}", "nrt", data)
        for name, entry in sorted(g["values"].items()):
            data = {"file": gf.rel, "name": name, "entry": entry}
            add("CHK1", f"val:{name}", "val", data)
            add("CHK2", f"nval:{name}", "nval", data)
            add("CHK7", f"rtval:{name}", "rtval", data)
        for name, aset in sorted(g["assertion_sets"].items()):
            add("CHK1", f"aset:{name}", "aset", {"file": gf.rel, "name": name, "aset": aset})
        for i, rel in enumerate(g["relations"]):
            add("CHK1", f"rel:{i}", "rel", {"file": gf.rel, "relation": rel, "sets": g["assertion_sets"]})
        for r in g["refusals"]:
            add("CHK6", f"refusal:{gf.name}#{r['id']}", "refusal", {"fixture": r, "source": gf.name,
                                                                   "golden": g})
        for v in VARIANTS:
            if "contracts" in v.sides:
                add("CHK1", f"variant:{v.variant_id}", "variant", {"variant": v, "golden": g, "file": gf.rel})
                add("CHK7", f"rtvariant:{v.variant_id}", "rtvariant", {"variant": v, "golden": g, "file": gf.rel})
            if "neutral" in v.sides:
                add("CHK2", f"nvariant:{v.variant_id}", "nvariant", {"variant": v, "golden": g, "file": gf.rel})

    for cf in only(files, "contracts", "canon"):
        for v in cf.data["vectors"]:
            add("CHK1", f"canon:{cf.name}#{v['id']}", "canon", {"file": cf.name, "vector": v, "side": "contracts"})
        for r in cf.data.get("refusals", []):
            add("CHK1", f"canon-refusal:{cf.name}#{r['id']}", "canon_refusal", {"file": cf.name, "refusal": r})
        if "extends" in cf.data or "predicate_relations" in cf.data:
            add("CHK1", f"sections:{cf.name}", "sections", {"file": cf.name, "doc": cf.data, "files": files})
        for section, kind in (("predicates", "pred"), ("value_digests", "valdigest")):
            for entry in cf.data.get(section, []):
                add("CHK1", f"{kind}:{cf.name}#{entry['id']}", kind, {"file": cf.name, "entry": entry})
        for case in cf.data.get("set_ordering", {}).get("cases", []):
            add("CHK1", f"setorder:{case['id']}", "setorder", {"file": cf.name, "case": case})
        for r in cf.data.get("set_ordering", {}).get("refusals", []):
            add("CHK6", f"refusal:{cf.name}#{r['id']}", "refusal", {"fixture": r, "source": cf.name, "golden": None})

    for cl in only(files, "contracts", "clarifications"):
        d = cl.data
        for r in d.get("refusals", []):
            add("CHK6", f"refusal:{cl.name}#{r['id']}", "refusal", {"fixture": r, "source": cl.name, "golden": None})
        for r in d.get("identity_boundary", {}).get("refusals", []):
            add("CHK6", f"refusal:{cl.name}#identity_boundary/{r['id']}", "refusal",
                {"fixture": r, "source": cl.name, "golden": None})
        for c in d.get("classification", {}).get("cases", []):
            add("CHK6", f"classification:{c['code'] or 'EMPTY'}", "classification", {"case": c})
        for c in d.get("idempotency", {}).get("cases", []):
            add("CHK6", f"idempotency:{c['id']}", "idempotency", {"case": c})
        fr = d.get("fault_recovery", {})
        if fr.get("reason_code_vocabulary"):
            add("CHK1", "reason-code:FaultRecovery", "reason_code", {"members": fr["reason_code_vocabulary"],
                                                                      "golden": golden_files})

    for vf in only(files, "harness", "canon"):
        for v in vf.data["vectors"]:
            add("CHK2", f"nvec:{vf.name}#{v['id']}", "nvec", {"file": vf.name, "vector": v})
        for r in vf.data.get("refusals", []):
            add("CHK2", f"nvec-refusal:{vf.name}#{r['id']}", "canon_refusal", {"file": vf.name, "refusal": r})
    harness_canon = only(files, "harness", "canon")
    for cf in only(files, "contracts", "canon"):
        add("CHK2", f"vecset:{cf.name}", "vecset", {"file": cf.name, "vectors": cf.data["vectors"],
                                                  "harness": harness_canon})
    for inv in only(files, "contracts", "inventory"):
        add("CHK2", f"inventory:{inv.name}", "inventory", {"contracts": inv, "harness": only(files, "harness", "inventory")})

    # -- CHK3 .. CHK5 are driven by the pinned packages
    for sid in sorted(reg.records):
        add("CHK3", f"fields:{reg.records[sid][0].__name__}", "fields", {"kind": "record", "key": sid})
    for sid in sorted(reg.contracts_only_records):
        add("CHK3", f"mirrored:{sid}", "mirrored", {"kind": "record", "key": sid})
    for sid in sorted(reg.neutral_only_records):
        add("CHK3", f"mirrored:{sid}", "mirrored", {"kind": "neutral_record", "key": sid})
    for name in sorted(reg.values):
        add("CHK3", f"fields:{name}", "fields", {"kind": "value", "key": name})
    for name in sorted(reg.reused):
        add("CHK3", f"identity:{name}", "reused_identity", {"key": name})
    for name in sorted(set(reg.contracts_only_values) | set(reg.neutral_only_values)):
        add("CHK3", f"mirrored:{name}", "mirrored", {"kind": "value", "key": name})
    add("CHK3", "schema-ids", "schema_ids", None)

    for name in sorted(reg.enums):
        add("CHK4", f"enum:{name}", "enum", {"key": name})
    for name in sorted(set(reg.contracts_only_enums) | set(reg.neutral_only_enums)):
        add("CHK4", f"enum-presence:{name}", "enum_presence", {"key": name})

    for pair in ("QAAdapter", "CheckAdapter", "BlobStore", "Redactor"):
        add("CHK5", f"protocol:{pair}", "protocol", {"pair": pair})
    add("CHK5", "api-versions", "api_versions", None)
    add("CHK5", "reference-adapter:QAAdapter", "reference_adapter", {"which": "qa"})
    add("CHK5", "reference-adapter:CheckAdapter", "reference_adapter", {"which": "check"})
    add("CHK5", "qa-playwright", "qa_playwright", None)

    # -- CHK6: error classes and vocabulary
    for code in sorted(ctx_adapter_codes(ctx)):
        add("CHK6", f"error-class:{code}", "error_class", {"code": code})
    add("CHK6", "error-vocabulary", "error_vocabulary", None)
    return _finish(ctx, items)


def _finish(ctx: Context, items: Dict[str, List[Item]]) -> Dict[str, List[Item]]:
    """Mark the declared not-applicable items, then add one completeness item per check."""
    declared = {(n.check, n.item): n for n in ctx.pins.not_applicable}
    seen = set()
    for check, lst in items.items():
        for i, it in enumerate(lst):
            entry = declared.get((check, it.item_id))
            if entry is not None:
                lst[i] = Item(check, it.item_id, "not_applicable", {"entry": entry, "real": it})
                seen.add((check, it.item_id))
    for (check, item_id), entry in declared.items():
        if (check, item_id) not in seen:
            items[check].append(Item(check, f"na-missing:{item_id}", "na_missing", {"entry": entry}))
    for check, lst in items.items():
        lst.append(Item(check, f"completeness:{check}", "completeness",
                        {"check": check, "actual": len(lst), "expected": ctx.pins.expected_items.get(check),
                         "pin_set": ctx.pins.pin_set}))
    return items


def ctx_adapter_codes(ctx: Context) -> List[str]:
    c, n = ctx.contracts, ctx.neutral
    return sorted({rc.value for rc in c.ADAPTER_ERRORS} | set(n.errors.ADAPTER_ERRORS))


def _registry(ctx: Context):
    from ..convert import registry
    return registry()
