# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Block unknown or incompatible redistributables for the optional execution adapters.

Reads ``third_party/adapter-license-matrix.yaml`` and fails (exit 1) when:

* the matrix is malformed or a required fact is missing;
* a licence is unknown, blocked, or needs review but the entry claims it may be redistributed;
* a claim of ``redistributable`` is not supported by a verified licence text, an inspected bundle and recorded notices;
* a commercial SDK or Apple toolchain is enabled by default;
* a package that an adapter package or a workflow installs is not listed in the matrix, or is pinned differently;
* (with --wheelhouse DIR) a recorded wheel, licence file or notice breakdown that the wheels of a built bundle do not bear out, or a licence-like file the matrix does not record;
* a wheel of bundle/third-party.lock.json (what the pinned bundle ships) has no entry here with the same name, version, file name and sha256 under a shipping status
  (``redistributable`` or ``staged_unmodified``), a shipped wheel is recorded under any other status, or the matrix lists a shipped wheel the lock does not hold;
* an adapter framework is installed without an exact pin;
* a ``third_party_evidence`` item claims ``verified`` without its evidence fields (exact version, how the component was identified from the shipped bytes, and for every source its
  URL, retrieval date and sha256, plus a licence text that ships in the bundle's THIRD_PARTY_NOTICES tree under the sha256 the notices lock records), or a component whose evidence is
  not all ``verified`` does not list the open items under ``public_distribution_blockers``;
* (with --notices DIR) the THIRD_PARTY_NOTICES tree of a built bundle is not exactly what third_party/notices/notices.lock.json records.

A verified item records facts (which component, which version, which licence text, fetched from where, when, with which digest). It is never a clearance: ``public_distribution`` stays
``owner_decision_required`` and no text in the matrix says a component is cleared or approved.

This is technical triage, not legal advice. ``--verify-upstream`` re-fetches each licence file at its pinned tag and compares
its SHA-256 with the matrix (it needs the network and is not run by the offline test suite).

Usage: ``python tools/check_adapter_licenses.py [--matrix FILE] [--root DIR] [--verify-upstream]``
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MATRIX = ROOT / "third_party" / "adapter-license-matrix.yaml"

SCHEMA = "redevops-qa/adapter-license-matrix"
KINDS = {"framework", "library", "driver", "dependency_group", "ci_tool", "commercial_toolchain"}
PINNED_KINDS = {"framework", "library", "driver"}
GROUP_KINDS = {"dependency_group", "ci_tool"}
REDISTRIBUTION = {"redistributable", "optional_extra", "staged_unmodified", "excluded_by_default", "unverified"}
SHIPPING = {"redistributable", "staged_unmodified"}        # statuses under which a wheel may be inside the bundle
VERIFICATION = {"verified", "wheel-inspected", "registry-metadata", "unverified"}
TRADEMARK = {"verified", "unverified"}
BUNDLE_CHECK = {"inspected", "not_inspected"}
ALLOWED, REVIEW, UNVERIFIED, BLOCKED = 0, 1, 2, 3
RANK_NAME = {ALLOWED: "allowed", REVIEW: "review", UNVERIFIED: "unverified", BLOCKED: "blocked"}
EVIDENCE_STATUS = {"verified", "declared_only", "unverified"}
EVIDENCE_ROLES = {"licence_text", "related_licence_text", "declared_licence", "identification", "integrity"}
NOTICES_LOCK_SCHEMA = "redevops-qa/third-party-notices-lock"
NOTICES_LOCK = ROOT / "third_party" / "notices" / "notices.lock.json"
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CLAIMS = re.compile(r"\b(cleared|approved|clearance|compatible|permitted)\b", re.I)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EXACT = re.compile(r"^\d+(\.\d+)*([.-]?(a|b|rc|beta|dev)\d+)?$")
_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9.+:_-]+)")


@dataclass(frozen=True)
class Finding:
    code: str
    component: str
    message: str

    def __str__(self) -> str:
        return f"FAIL {self.code} [{self.component}]: {self.message}"


# --------------------------------------------------------------------------------------------- SPDX expressions
class _Parser:
    def __init__(self, text: str, policy: dict):
        self.tokens = [m.group(1) for m in _TOKEN.finditer(text)]
        if "".join(self.tokens).replace(" ", "") != re.sub(r"\s+", "", text):
            raise ValueError("unparseable licence expression")
        self.pos = 0
        self.policy = policy
        self.atoms: List[Tuple[str, int]] = []

    def peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def parse(self) -> int:
        rank = self.expr()
        if self.peek() is not None:
            raise ValueError(f"unexpected token {self.peek()!r}")
        return rank

    def expr(self) -> int:
        rank = self.term()
        while self.peek() == "OR":
            self.take()
            rank = min(rank, self.term())
        return rank

    def term(self) -> int:
        rank = self.factor()
        while self.peek() == "AND":
            self.take()
            rank = max(rank, self.factor())
        return rank

    def factor(self) -> int:
        token = self.peek()
        if token is None or token in ("AND", "OR", "WITH", ")"):
            raise ValueError("expected a licence identifier")
        if token == "(":
            self.take()
            rank = self.expr()
            if self.peek() != ")":
                raise ValueError("missing ')'")
            self.take()
            return rank
        ident = self.take()
        rank = atom_rank(ident, self.policy)
        if self.peek() == "WITH":
            self.take()
            exception = self.take() if self.peek() not in (None, "AND", "OR", ")") else ""
            if exception not in self.policy.get("allowed_exceptions", []):
                rank = BLOCKED
        self.atoms.append((ident, rank))
        return rank


def atom_rank(ident: str, policy: dict) -> int:
    if ident == "unverified":
        return UNVERIFIED
    if ident in policy.get("blocked_spdx", []) or any(ident.startswith(p) for p in policy.get("blocked_prefixes", [])):
        return BLOCKED
    if ident in policy.get("allowed_spdx", []):
        return ALLOWED
    if ident in policy.get("review_spdx", []):
        return REVIEW
    return BLOCKED          # unknown identifiers (including any other LicenseRef) are never accepted


def rank_of(expression: object, policy: dict) -> Tuple[int, str]:
    """Rank of an SPDX expression under the policy: (rank, reason). Anything unparseable is blocked."""
    if not isinstance(expression, str) or not expression.strip():
        return BLOCKED, "empty licence expression"
    try:
        parser = _Parser(expression, policy)
        rank = parser.parse()
    except (ValueError, IndexError) as exc:
        return BLOCKED, f"{expression!r}: {exc}"
    return rank, expression


# --------------------------------------------------------------------------------------------- the matrix
def load_matrix(path: Path) -> dict:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("matrix is not a mapping")
    return data


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def _need(findings: List[Finding], comp_id: str, obj: dict, keys: Iterable[str], where: str = "") -> bool:
    ok = True
    for key in keys:
        value = obj.get(key) if isinstance(obj, dict) else None
        if value is None or value == "" or (isinstance(value, (list, dict)) and key not in ("notices", "bundled_deps") and not value):
            findings.append(Finding("MISSING_FIELD", comp_id, f"{where}{key} is missing or empty"))
            ok = False
    return ok


def effective_rank(comp: dict, policy: dict) -> Tuple[int, List[str]]:
    """Worst rank over the entry's own licence, its members and its bundled content, with the reasons that are not allowed."""
    worst, why = ALLOWED, []

    def add(expression: object, label: str) -> None:
        nonlocal worst
        rank, reason = rank_of(expression, policy)
        if rank != ALLOWED:
            why.append(f"{label}: {reason} is {RANK_NAME[rank]}")
        worst = max(worst, rank)

    if "spdx" in comp:
        add(comp["spdx"], "licence")
    for member in comp.get("members") or []:
        add(member.get("spdx"), f"member {member.get('name')}")
    for dep in comp.get("bundled_deps") or []:
        add(dep.get("spdx"), f"bundled {dep.get('name')}")
    return worst, why


def check_matrix(matrix: dict) -> List[Finding]:
    findings: List[Finding] = []
    if matrix.get("schema") != SCHEMA or matrix.get("version") != 1:
        return [Finding("MATRIX_SCHEMA", "matrix", f"schema must be {SCHEMA} version 1")]
    policy = matrix.get("policy") or {}
    for key in ("allowed_spdx", "review_spdx", "blocked_spdx", "blocked_prefixes", "allowed_exceptions", "ci_tooling"):
        if not isinstance(policy.get(key), list):
            findings.append(Finding("MATRIX_SCHEMA", "policy", f"policy.{key} must be a list"))
    overlap = set(policy.get("allowed_spdx", [])) & (set(policy.get("review_spdx", [])) | set(policy.get("blocked_spdx", [])))
    if overlap:
        findings.append(Finding("MATRIX_SCHEMA", "policy", f"identifiers in more than one policy list: {sorted(overlap)}"))
    comps = matrix.get("components")
    if not isinstance(comps, list) or not comps:
        return findings + [Finding("MATRIX_SCHEMA", "matrix", "components must be a non-empty list")]
    by_id: Dict[str, dict] = {}
    for comp in comps:
        cid = comp.get("id") if isinstance(comp, dict) else None
        if not cid or cid in by_id:
            findings.append(Finding("MATRIX_SCHEMA", str(cid), "component id missing or duplicated"))
            continue
        by_id[cid] = comp
    for cid, comp in by_id.items():
        findings.extend(_check_component(cid, comp, policy, by_id))
        for text in _strings(comp):
            if _CLAIMS.search(text):                    # the whole entry, not only the evidence: this file records facts and decisions, it never says a component is cleared, approved, compatible or permitted
                findings.append(Finding("MATRIX_CLAIM", cid, f"the matrix never says a component is cleared, approved, compatible or permitted ({text[:70]!r})"))
                break
    findings += check_required_decisions(matrix)
    if any((c.get("redistribution") or {}).get("status") == "staged_unmodified" for c in by_id.values()):
        block = matrix.get("bundle_public_distribution")
        if not isinstance(block, dict) or block.get("status") != "owner_decision_required" or block.get("pending_decisions") != pending_decisions(matrix):
            findings.append(Finding("BUNDLE_PUBLIC_DISTRIBUTION", "matrix", f"bundle_public_distribution must say status: owner_decision_required and list exactly the shipped items without a settled owner decision: {pending_decisions(matrix)}"))
    return findings


def _check_component(cid: str, comp: dict, policy: dict, by_id: Dict[str, dict]) -> List[Finding]:
    out: List[Finding] = []
    kind = comp.get("kind")
    if kind not in KINDS:
        return [Finding("MATRIX_SCHEMA", cid, f"kind must be one of {sorted(KINDS)}")]
    base_ok = _need(out, cid, comp, ["name", "adapter", "notices", "trademark", "redistribution", "verification"])
    if not base_ok:
        return out
    tm, red, ver = comp["trademark"], comp["redistribution"], comp["verification"]
    _need(out, cid, tm, ["status", "note"], "trademark.")
    _need(out, cid, red, ["status", "reason"], "redistribution.")
    _need(out, cid, ver, ["status", "method", "checked_on"], "verification.")
    if not isinstance(red.get("default_enabled"), bool):
        out.append(Finding("MISSING_FIELD", cid, "redistribution.default_enabled must be true or false"))
    if tm.get("status") not in TRADEMARK:
        out.append(Finding("MATRIX_SCHEMA", cid, f"trademark.status must be one of {sorted(TRADEMARK)}"))
    if red.get("status") not in REDISTRIBUTION:
        out.append(Finding("MATRIX_SCHEMA", cid, f"redistribution.status must be one of {sorted(REDISTRIBUTION)}"))
    if ver.get("status") not in VERIFICATION:
        out.append(Finding("MATRIX_SCHEMA", cid, f"verification.status must be one of {sorted(VERIFICATION)}"))
    for notice in comp["notices"] or []:
        if not (isinstance(notice, dict) and notice.get("file") and notice.get("content")):
            out.append(Finding("MISSING_FIELD", cid, "every notice needs a file and a content description"))
    status, verified = red.get("status"), ver.get("status")

    # --- required facts by kind
    if kind in PINNED_KINDS:
        _need(out, cid, comp, ["project", "pinned_release", "pinned_ref", "spdx", "license_url", "license_file_sha256", "artifacts",
                               "bundled_deps_check"])
        if comp.get("bundled_deps_check") not in BUNDLE_CHECK:
            out.append(Finding("MATRIX_SCHEMA", cid, f"bundled_deps_check must be one of {sorted(BUNDLE_CHECK)}"))
        if not isinstance(comp.get("bundled_deps"), list):
            out.append(Finding("MISSING_FIELD", cid, "bundled_deps must be a list (empty when none was found)"))
        if comp.get("bundled_deps_check") == "not_inspected" and comp.get("bundled_deps"):
            out.append(Finding("MATRIX_SCHEMA", cid, "bundled_deps are listed but the bundle is marked not_inspected"))
        if not _EXACT.match(str(comp.get("pinned_release", ""))):
            out.append(Finding("UNPINNED", cid, f"pinned_release {comp.get('pinned_release')!r} is not an exact version"))
        if not _SHA256.match(str(comp.get("license_file_sha256", ""))):
            out.append(Finding("MATRIX_SCHEMA", cid, "license_file_sha256 must be 64 lowercase hex digits"))
        url = str(comp.get("license_url", ""))
        ref = urllib.parse.quote(str(comp.get("pinned_ref", "")), safe="")
        if not url.startswith("https://github.com/") or f"/blob/{ref}/" not in url:
            out.append(Finding("MATRIX_SCHEMA", cid, "license_url must be a github.com blob URL at the pinned_ref (a tag, not a branch)"))
        if verified != "verified":
            out.append(Finding("UNVERIFIED_LICENSE", cid, "a framework, library or driver entry needs a verified licence text at the pinned tag"))
        for art in comp.get("artifacts") or []:
            if not (isinstance(art, dict) and art.get("ecosystem") in ("pypi", "npm") and art.get("name") and art.get("version")):
                out.append(Finding("MATRIX_SCHEMA", cid, "every artifact needs ecosystem (pypi or npm), name and version"))
            elif art.get("version") != comp.get("pinned_release"):
                out.append(Finding("UNPINNED", cid, f"artifact {art['name']} version {art['version']} differs from pinned_release"))
            if isinstance(art, dict) and art.get("sha256") and not _SHA256.match(str(art["sha256"])):
                out.append(Finding("MATRIX_SCHEMA", cid, f"artifact {art.get('name')} sha256 is not 64 hex digits"))
    elif kind in GROUP_KINDS:
        members = comp.get("members")
        if not isinstance(members, list) or not members:
            out.append(Finding("MISSING_FIELD", cid, "members must be a non-empty list"))
        for member in members or []:
            _need(out, cid, member, ["name", "version_constraint", "spdx"], "member: ")
    else:   # commercial_toolchain
        _need(out, cid, comp, ["spdx", "license_url"])
        if not str(comp.get("license_url", "")).startswith("https://"):
            out.append(Finding("MATRIX_SCHEMA", cid, "license_url must be https"))
        if red.get("default_enabled") is not False or status != "excluded_by_default":
            out.append(Finding("COMMERCIAL_ENABLED", cid, "a commercial SDK or toolchain must be excluded_by_default and not enabled by default"))
        if rank_of(comp.get("spdx"), policy)[0] < BLOCKED:
            out.append(Finding("COMMERCIAL_LICENSE_CLASS", cid, "a commercial toolchain's licence must be a blocked identifier (LicenseRef-Proprietary...)"))

    # --- the policy gate
    rank, why = effective_rank(comp, policy)
    if rank == BLOCKED and status != "excluded_by_default":
        out.append(Finding("BLOCKED_LICENSE", cid, f"unknown or incompatible licence but status is {status}: {'; '.join(why)}"))
    if status == "redistributable":
        if rank != ALLOWED:
            out.append(Finding("REDISTRIBUTING_UNAPPROVED_LICENSE", cid, f"{'; '.join(why)}"))
        if verified != "verified":
            out.append(Finding("UNVERIFIED_REDISTRIBUTION", cid, "redistributable needs verification.status = verified"))
        if kind in PINNED_KINDS and comp.get("bundled_deps_check") != "inspected":
            out.append(Finding("UNVERIFIED_REDISTRIBUTION", cid, "redistributable needs the bundled content to be inspected"))
        if not comp.get("notices"):
            out.append(Finding("MISSING_NOTICES", cid, "redistributable needs the notices to ship recorded"))
    if verified == "unverified" and status not in ("unverified", "excluded_by_default"):
        out.append(Finding("UNVERIFIED_REDISTRIBUTION", cid, "nothing was verified, so only unverified or excluded_by_default can be claimed"))
    if red.get("default_enabled") is True:
        if status not in ("redistributable", "optional_extra") or rank > REVIEW:
            out.append(Finding("ENABLED_BY_DEFAULT_NOT_APPROVED", cid, "only an entry whose licences are allowed or under review and that is not excluded may be on by default"))
    # --- wheels shipped in the pinned bundle
    shipped = comp.get("shipped_wheels")
    if shipped is not None:
        if not isinstance(shipped, list) or not shipped:
            out.append(Finding("MISSING_FIELD", cid, "shipped_wheels must be a non-empty list when present"))
            shipped = []
        if status not in SHIPPING:
            out.append(Finding("SHIPPED_NOT_STAGED", cid, f"shipped_wheels are recorded but the status is {status}: a wheel inside the bundle needs a shipping status"))
        for wheel in shipped:
            at = f"shipped wheel {wheel.get('name') if isinstance(wheel, dict) else wheel!r}"
            if not (isinstance(wheel, dict) and _need(out, cid, wheel, ["name", "version", "file", "sha256", "license_declared", "license_files"], f"{at}: ")):
                continue
            if not _SHA256.match(str(wheel["sha256"])):
                out.append(Finding("MATRIX_SCHEMA", cid, f"{at}: sha256 is not 64 hex digits"))
            for lf in wheel["license_files"]:
                if not (isinstance(lf, dict) and lf.get("path") and _SHA256.match(str(lf.get("sha256", "")))):
                    out.append(Finding("MATRIX_SCHEMA", cid, f"{at}: every licence file needs a path inside the wheel and a sha256"))
    if status == "staged_unmodified":
        if red.get("public_distribution") != "owner_decision_required":
            out.append(Finding("STAGED_PUBLIC_CLAIM", cid, "a staged_unmodified entry says public_distribution: owner_decision_required (clearing it is a decision, and needs status redistributable with a verified licence text)"))
        reason = str(red.get("reason", ""))
        if "private staging only" not in reason.lower() or "owner decision" not in reason.lower():
            out.append(Finding("STAGED_PUBLIC_CLAIM", cid, "the reason of a staged_unmodified entry must say 'private staging only' and that public distribution requires an owner decision"))
        if not shipped:
            out.append(Finding("MISSING_FIELD", cid, "staged_unmodified needs shipped_wheels"))
        if not comp.get("notices"):
            out.append(Finding("MISSING_NOTICES", cid, "staged_unmodified needs the notice and licence files that travel with the wheel recorded"))
        if verified not in ("verified", "wheel-inspected"):
            out.append(Finding("UNVERIFIED_STAGING", cid, "a wheel is shipped only after its licence metadata and files were read (verification.status verified or wheel-inspected)"))
        if kind in PINNED_KINDS and comp.get("bundled_deps_check") != "inspected":
            out.append(Finding("UNVERIFIED_STAGING", cid, "a framework or library is shipped only after the content of the wheel was inspected (bundled_deps_check: inspected)"))
        if red.get("default_enabled") is not False:
            out.append(Finding("ENABLED_BY_DEFAULT_NOT_APPROVED", cid, "a staged entry is not enabled by default"))
    out += _check_evidence(cid, comp, policy)
    if status == "staged_unmodified":
        out += _check_owner_decision(cid, "the shipped component", comp.get("owner_decision"))
    # --- requires
    for req in comp.get("requires") or []:
        other = by_id.get(req)
        if other is None:
            out.append(Finding("MATRIX_SCHEMA", cid, f"requires unknown component {req!r}"))
        elif red.get("default_enabled") is True and other.get("redistribution", {}).get("status") in ("excluded_by_default", "unverified"):
            out.append(Finding("ENABLED_BY_DEFAULT_NOT_APPROVED", cid, f"enabled by default but requires {req}, which is {other['redistribution']['status']}"))
    return out


# --------------------------------------------------------------------------------------------- evidence of what the shipped bytes are
def _strings(obj: object) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _check_evidence(cid: str, comp: dict, policy: dict) -> List[Finding]:
    """The ``third_party_evidence`` items of one component. ``verified`` is a claim about facts and needs all of them: the exact component and version, how it was identified from the shipped
    bytes, and for each source the URL, the retrieval date and the sha256 of what was fetched (a source whose digest is that of one of this repository's own evidence tables is refused: a table
    is derived, not fetched), with at least one licence text that is shipped (a notice id of the notices lock). ``declared_only`` says a licence is declared by the primary source but no licence
    text could be established for the shipped bytes; every declaring source quotes the declaration verbatim. ``unverified`` says nothing could be established. Nothing here clears anything.
    Every item also carries an owner_decision block (``none yet`` when the owner has not decided)."""
    out: List[Finding] = []
    items = comp.get("third_party_evidence")
    red = comp.get("redistribution") or {}
    if items is None:
        if "public_distribution_blockers" in red:
            out.append(Finding("EVIDENCE_SCHEMA", cid, "public_distribution_blockers is listed but the entry has no third_party_evidence"))
        return out
    if not isinstance(items, list) or not items:
        return [Finding("EVIDENCE_SCHEMA", cid, "third_party_evidence must be a non-empty list when present")]
    ids: Dict[str, dict] = {}
    for item in items:
        iid = item.get("id") if isinstance(item, dict) else None
        if not _nonempty(iid) or iid in ids:
            out.append(Finding("EVIDENCE_SCHEMA", cid, f"evidence item id missing or duplicated: {iid!r}"))
            continue
        ids[iid] = item
        at = f"evidence {iid}"
        status = item.get("status")
        if status not in EVIDENCE_STATUS:
            out.append(Finding("EVIDENCE_SCHEMA", cid, f"{at}: status must be one of {sorted(EVIDENCE_STATUS)}"))
            continue
        for key in ("component", "version", "spdx", "residual"):
            if not _nonempty(item.get(key)):
                out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: {key} is missing or empty"))
        out += _check_owner_decision(cid, at, item.get("owner_decision"))
        if status != "verified" and not re.fullmatch(r"unverified|declared:.+", str(item.get("spdx", ""))):
            out.append(Finding("EVIDENCE_SPDX_ESTABLISHED", cid, f"{at}: an item that is {status} does not state a licence as established: spdx is 'unverified' (or 'declared:<expression>'), the declared expression goes in declared_spdx (found {item.get('spdx')!r})"))
        sources = item.get("sources")
        if status == "unverified":
            if not _nonempty(item.get("reason")):
                out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: an unverified item states the exact reason"))
            continue
        if not _nonempty(item.get("identified_by")):
            out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: identified_by (how the component and version were read from the shipped bytes) is missing"))
        if not isinstance(item.get("shipped_members"), list) and not _nonempty(item.get("inlined_in")):
            out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: shipped_members (paths in the wheel) or inlined_in is required"))
        roles = set()
        if not isinstance(sources, list) or not sources:
            out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: sources must be a non-empty list"))
            sources = []
        for src in sources:
            if not isinstance(src, dict) or src.get("role") not in EVIDENCE_ROLES:
                out.append(Finding("EVIDENCE_SCHEMA", cid, f"{at}: every source has a role of {sorted(EVIDENCE_ROLES)}"))
                continue
            role = src["role"]
            roles.add(role)
            if not str(src.get("url", "")).startswith("https://"):
                out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: a {role} source needs an https url"))
            if not _DATE.match(str(src.get("retrieved_on", ""))):
                out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: a {role} source needs retrieved_on as YYYY-MM-DD"))
            if not _SHA256.match(str(src.get("sha256", ""))):
                out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: a {role} source needs the sha256 of what was fetched (64 lowercase hex digits)"))
            if role in ("licence_text", "related_licence_text") and not _nonempty(src.get("notice")):
                out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: a {role} source names the notice id that ships it"))
            if role in ("licence_text", "related_licence_text") and not isinstance(src.get("ships_as_fetched"), bool):
                out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: a {role} source says whether the shipped notice is the fetched file as it is (ships_as_fetched: true or false)"))
            if role == "declared_licence" and not _nonempty(src.get("quote")):
                out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: a declared_licence source quotes the declaration verbatim (quote)"))
            if src.get("derived") is not None and not _nonempty(src.get("derived")):
                out.append(Finding("EVIDENCE_SCHEMA", cid, f"{at}: derived, when present, names what the digest was derived from"))
        if "identification" not in roles:
            out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: at least one identification source is required"))
        texts = item.get("licence_texts")
        if status == "verified":
            if "licence_text" not in roles:
                out.append(Finding("EVIDENCE_UNSUPPORTED_VERIFIED", cid, f"{at}: verified needs a fetched licence text (a licence_text source)"))
            if not isinstance(texts, list) or not texts:
                out.append(Finding("EVIDENCE_UNSUPPORTED_VERIFIED", cid, f"{at}: verified needs licence_texts, the notice ids that ship the text"))
            if str(item.get("spdx", "")).strip().lower() == "unverified":
                out.append(Finding("EVIDENCE_UNSUPPORTED_VERIFIED", cid, f"{at}: verified with no licence identifier"))
        else:   # declared_only
            if "declared_licence" not in roles:
                out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: declared_only needs a declared_licence source"))
            if not _nonempty(item.get("licence_text_absent")):
                out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: declared_only states what could not be established and where the text was looked for (licence_text_absent)"))
            if not isinstance(item.get("options"), list) or not item.get("options"):
                out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"{at}: declared_only lists the options the owner has (options)"))
    # the open items are the blockers for public distribution, and the entry says so
    if red.get("status") == "staged_unmodified":
        open_ids = sorted(i for i, it in ids.items() if it.get("status") != "verified")
        listed = red.get("public_distribution_blockers")
        if not isinstance(listed, list) or sorted(listed) != open_ids:
            out.append(Finding("EVIDENCE_BLOCKERS", cid, f"public_distribution_blockers must list exactly the evidence items that are not verified: {open_ids} (found {listed!r})"))
    # bundled content that names evidence agrees with it: a licence is claimed exactly when the evidence is verified
    for dep in comp.get("bundled_deps") or []:
        refs = dep.get("evidence")
        spdx = str(dep.get("spdx", "")).strip()
        if refs is None:
            if spdx == "unverified" and red.get("status") == "staged_unmodified":
                out.append(Finding("EVIDENCE_MISSING_FIELD", cid, f"bundled {dep.get('name')}: an unverified licence in a shipped wheel needs an evidence item that states why"))
            continue
        for ref in refs if isinstance(refs, list) else [refs]:
            item = ids.get(ref)
            if item is None:
                out.append(Finding("EVIDENCE_SCHEMA", cid, f"bundled {dep.get('name')}: evidence {ref!r} is not an item of this entry"))
            elif item.get("status") == "verified" and spdx == "unverified":
                out.append(Finding("EVIDENCE_SCHEMA", cid, f"bundled {dep.get('name')}: its evidence {ref} is verified but the licence is still marked unverified"))
            elif item.get("status") != "verified" and spdx != "unverified":
                out.append(Finding("EVIDENCE_SCHEMA", cid, f"bundled {dep.get('name')}: its evidence {ref} is {item.get('status')} but the licence is claimed as {spdx!r}; only a verified item supports a licence, an open one stays unverified"))
    return out


DECISIONS = {"accepted", "accepted provisionally", "conditional acceptance", "none yet"}
CONDITION_KINDS = {"notices_shipped", "residuals_retained", "documented", "declaration_verified", "table_section"}
_NODE_NOTICES = ["playwright-playwright-driver-license", "playwright-playwright-driver-package-license", "playwright-playwright-driver-package-notice"]
#: What the owner decided on 2026-11-03, kept HERE and not only in the matrix, so that deleting or weakening a recorded condition is a finding. Per item id: the decision, its date, the elected licence if
#: any, and the minimum conditions (kind plus the content the record must at least contain). The record may state more, never less. The checker cannot know that the owner took the decision at all:
#: it keeps the owner's wording from being edited away, it does not authenticate it.
REQUIRED_DECISIONS = {
    "pw-node-runtime": {"decision": "accepted provisionally", "date": "2026-11-03", "conditions": [
        {"kind": "notices_shipped", "notices": _NODE_NOTICES}, {"kind": "residuals_retained", "contains": ["signature", "linked"]}]},
    "pw-node-icu": {"decision": "accepted", "date": "2026-11-03", "conditions": [
        {"kind": "notices_shipped", "notices": ["playwright-playwright-driver-license"]}, {"kind": "table_section", "item": "pw-node-runtime", "name": "ICU", "spdx": "Unicode-3.0"}]},
    "pw-minimatch": {"decision": "accepted", "date": "2026-11-03", "conditions": [
        {"kind": "notices_shipped", "notices": ["minimatch-10.2.5-license", "playwright-playwright-driver-package-lib-utilsbundle-js-license"]},
        {"kind": "notices_shipped", "notices": ["minimatch-10.2.5-package-json"], "label_contains": "attribution"}]},
    "pw-proxy-agent-negotiate": {"decision": "conditional acceptance", "date": "2026-11-03", "conditions": [
        {"kind": "documented", "files": {"third_party/notices/README.md": ["proxy-agent-negotiate", "no licence text"], "bundle/README.md": ["proxy-agent-negotiate", "no licence text"], "tools/build_bundle.py": ["proxy-agent-negotiate", "no licence text"]}}]},
    "rf-tablesorter-2.30.5": {"decision": "conditional acceptance", "date": "2026-11-03", "elected_licence": "MIT", "conditions": [
        {"kind": "declaration_verified", "token": "MIT", "min_sources": 5}]},
}


def check_required_decisions(matrix: dict) -> List[Finding]:
    """The recorded decisions against REQUIRED_DECISIONS: same decision, date and elected licence, and every required condition present at least as strong as required (notices a superset, the
    label requirement kept, retained residual words a superset, documented files and words a superset, at least as many declaring sources)."""
    out: List[Finding] = []
    items = {i.get("id"): (c.get("id"), i) for c in matrix.get("components", []) for i in c.get("third_party_evidence") or [] if isinstance(i, dict)}
    for iid, want in REQUIRED_DECISIONS.items():
        if iid not in items:
            out.append(Finding("OWNER_DECISION_WEAKENED", iid, "an item the owner decided on is missing from the matrix"))
            continue
        cid, item = items[iid]
        block = item.get("owner_decision") or {}
        for key in ("decision", "date", "elected_licence"):
            if key in want and block.get(key) != want[key]:
                out.append(Finding("OWNER_DECISION_WEAKENED", cid, f"{iid}: the owner decided {key} {want[key]!r}, the record says {block.get(key)!r}"))
        have = [c for c in block.get("conditions") or [] if isinstance(c, dict)]
        for req in want["conditions"]:
            if not any(_at_least(c, req) for c in have):
                out.append(Finding("OWNER_CONDITION_WEAKENED", cid, f"{iid}: the record has no condition of kind {req['kind']} at least as strong as the owner's ({_brief(req)})"))
    return out


def _brief(req: dict) -> str:
    return ", ".join(f"{k}={v!r}" for k, v in req.items() if k != "kind")[:200]


def _at_least(c: dict, req: dict) -> bool:
    if c.get("kind") != req["kind"]:
        return False
    kind = req["kind"]
    if kind == "notices_shipped":
        return set(req["notices"]) <= set(c.get("notices") or []) and (not req.get("label_contains") or req["label_contains"] == c.get("label_contains"))
    if kind == "residuals_retained":
        return set(req["contains"]) <= set(c.get("contains") or [])
    if kind == "documented":
        have = c.get("files") or {}
        return all(f in have and set(words) <= set(have[f]) for f, words in req["files"].items())
    if kind == "declaration_verified":
        return c.get("token") == req["token"] and int(c.get("min_sources") or 0) >= req["min_sources"]
    if kind == "table_section":
        return all(c.get(k) == req[k] for k in ("item", "name", "spdx"))
    return False


def _check_owner_decision(cid: str, at: str, block: object) -> List[Finding]:
    """The structure of an owner_decision block: a decision from DECISIONS; anything but ``none yet`` needs the date, ``decided_by: owner`` and at least one condition (id, text, kind, a recorded
    status). The conditions are evaluated by check_owner_conditions, which needs the notices lock and the repository."""
    if not isinstance(block, dict) or block.get("decision") not in DECISIONS:
        return [Finding("OWNER_DECISION_MISSING", cid, f"{at}: an owner_decision block with a decision of {sorted(DECISIONS)} is required (a shipped item has either a decision or 'none yet')")]
    if block["decision"] == "none yet":
        return []
    out: List[Finding] = []
    if not _DATE.match(str(block.get("date", ""))) or block.get("decided_by") != "owner":
        out.append(Finding("OWNER_DECISION_INCOMPLETE", cid, f"{at}: a recorded decision needs date (YYYY-MM-DD) and decided_by: owner"))
    conds = block.get("conditions")
    if not isinstance(conds, list) or not conds:
        out.append(Finding("OWNER_DECISION_INCOMPLETE", cid, f"{at}: a recorded decision needs its conditions"))
        return out
    seen = set()
    for cond in conds:
        if not isinstance(cond, dict) or not _nonempty(cond.get("id")) or cond.get("id") in seen or not _nonempty(cond.get("text")) or cond.get("kind") not in CONDITION_KINDS or cond.get("status") not in ("satisfied", "open"):
            out.append(Finding("OWNER_DECISION_INCOMPLETE", cid, f"{at}: every condition needs a unique id, text, a kind of {sorted(CONDITION_KINDS)} and a status (satisfied or open)"))
            continue
        seen.add(cond["id"])
    if block["decision"] == "conditional acceptance" and block.get("elected_licence") is not None and not _nonempty(block.get("elected_licence")):
        out.append(Finding("OWNER_DECISION_INCOMPLETE", cid, f"{at}: elected_licence, when present, names the licence"))
    return out


def _eval_condition(cond: dict, item: dict, items_by_id: Dict[str, dict], lock_by_id: Dict[str, dict], root: Path) -> Tuple[bool, str]:
    """Whether one condition is evidenced, computed from the matrix, the notices lock and the repository files. Returns (satisfied, detail)."""
    kind = cond.get("kind")
    if kind == "notices_shipped":
        ids = cond.get("notices") or []
        missing = [i for i in ids if i not in lock_by_id]
        if not ids or missing:
            return False, f"notices not in the notices lock: {missing or ids}"
        wanted = str(cond.get("label_contains", ""))
        bad = [i for i in ids if wanted and wanted.lower() not in str(lock_by_id[i].get("label", "")).lower()]
        if bad:
            return False, f"notices without the label {wanted!r}: {bad}"
        return True, "shipped"
    if kind == "residuals_retained":
        text = str(item.get("residual", "")).lower()
        absent = [w for w in cond.get("contains", []) if str(w).lower() not in text]
        return (not absent and bool(cond.get("contains")), f"the residual no longer mentions {absent}")
    if kind == "documented":
        if not _nonempty(item.get("licence_text_absent")) or item.get("status") != "declared_only":
            return False, "the item does not record what is missing (declared_only with licence_text_absent)"
        for rel, words in (cond.get("files") or {}).items():
            path = Path(root) / rel
            if not path.is_file():
                return False, f"{rel} does not exist"
            body = path.read_text(encoding="utf-8", errors="replace")
            lacking = [w for w in words if w not in body]
            if lacking:
                return False, f"{rel} does not mention {lacking}"
        return bool(cond.get("files")), "documented"
    if kind == "declaration_verified":
        token, need = str(cond.get("token", "")), int(cond.get("min_sources", 0) or 0)
        quoted = [s for s in item.get("sources") or [] if isinstance(s, dict) and s.get("role") == "declared_licence" and token and token in str(s.get("quote", ""))]
        elected = item.get("owner_decision", {}).get("elected_licence")
        if elected != token:
            return False, f"the elected licence is {elected!r}, the condition names {token!r}"
        if token not in str(item.get("declared_spdx", "")):
            return False, f"the declared expression {item.get('declared_spdx')!r} does not offer {token}"
        return (len(quoted) >= need > 0, f"{len(quoted)} declaring sources quote {token}, {need} needed")
    if kind == "table_section":
        ref = items_by_id.get(str(cond.get("item")))
        table = (ref or {}).get("table")
        if not isinstance(table, dict) or not (Path(root) / str(table.get("path", ""))).is_file():
            return False, "the table is missing"
        sections = [s for s in _load_json(Path(root) / table["path"]).get("sections", []) if s.get("name") == cond.get("name")]
        return (len(sections) == 1 and sections[0].get("spdx") == cond.get("spdx"), f"the table has no section {cond.get('name')} with {cond.get('spdx')}")
    return False, "unknown condition kind"


def check_owner_decisions(matrix: dict, lock: dict, root: Path = ROOT) -> List[Finding]:
    """Evaluate the conditions of every recorded owner decision (items and shipped components): the status the matrix records must be the one computed, and a decision whose condition is not evidenced
    is a finding. Also computes the bundle-level list of pending decisions."""
    out: List[Finding] = []
    lock_by_id = {f.get("id"): f for f in lock.get("files", []) if isinstance(f, dict)}
    for comp in matrix.get("components", []):
        items = {i.get("id"): i for i in comp.get("third_party_evidence") or [] if isinstance(i, dict)}
        for owner_item in [comp, *items.values()]:
            block = owner_item.get("owner_decision")
            if not isinstance(block, dict) or block.get("decision") in (None, "none yet"):
                continue
            label = owner_item.get("id")
            for cond in block.get("conditions") or []:
                if not isinstance(cond, dict):
                    continue
                ok, detail = _eval_condition(cond, owner_item, items, lock_by_id, root)
                if (cond.get("status") == "satisfied") != ok:
                    out.append(Finding("OWNER_CONDITION_STATUS", str(comp.get("id")), f"{label}: condition {cond.get('id')} is recorded as {cond.get('status')} but computes as {'satisfied' if ok else 'open'}: {detail}"))
                if not ok:
                    out.append(Finding("OWNER_CONDITION_UNEVIDENCED", str(comp.get("id")), f"{label}: the decision {block.get('decision')!r} rests on condition {cond.get('id')}, which is not evidenced: {detail}"))
    return out


def pending_decisions(matrix: dict) -> List[str]:
    """Ids of the shipped items (staged components and their evidence items) that have no owner decision yet or a decision with an open condition."""
    pending = []
    for comp in matrix.get("components", []):
        if (comp.get("redistribution") or {}).get("status") != "staged_unmodified":
            continue
        for label, holder in [(comp["id"], comp), *[(i["id"], i) for i in comp.get("third_party_evidence") or [] if isinstance(i, dict) and "id" in i]]:
            block = holder.get("owner_decision") or {}
            if block.get("decision") in (None, "none yet") or any(c.get("status") != "satisfied" for c in block.get("conditions") or [] if isinstance(c, dict)):
                pending.append(label)
    return sorted(pending)

# --------------------------------------------------------------------------------------------- what the repository installs
UNSCANNABLE = "<unscannable>"
# pip options that take an argument naming something this scan cannot read (a requirements file, a path, an index)
_ARG_OPTIONS = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url", "-f",
                "--find-links"}
_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def parse_requirement(text: str) -> Tuple[str, str]:
    """(normalised distribution name, specifier text) of a requirement string."""
    m = _REQ.match(text.split(";")[0])
    if not m:
        raise ValueError(f"cannot read requirement {text!r}")
    return _norm(m.group(1)), m.group(3).strip()


def known_names(matrix: dict) -> Dict[str, List[Tuple[str, str]]]:
    """name -> [(component id, exact version or '')] for every distribution the matrix accounts for."""
    known: Dict[str, List[Tuple[str, str]]] = {}
    for comp in matrix["components"]:
        for art in comp.get("artifacts") or []:
            known.setdefault(_norm(art["name"]), []).append((comp["id"], str(art.get("version", ""))))
        for member in comp.get("members") or []:
            known.setdefault(_norm(member["name"]), []).append((comp["id"], ""))
    for name in matrix["policy"].get("ci_tooling", []):
        known.setdefault(_norm(name), [])
    return known


def gather_installs(root: Path) -> List[Tuple[str, str, str]]:
    """(source, name, specifier) for package dependencies and workflow ``pip install`` arguments under ``root``."""
    found: List[Tuple[str, str, str]] = []
    for path in sorted((root / "packages").glob("*/pyproject.toml")):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        project = data.get("project", {})
        reqs = list(project.get("dependencies", []))
        for extra in project.get("optional-dependencies", {}).values():
            reqs += list(extra)
        for req in reqs:
            name, spec = parse_requirement(req)
            found.append((str(path.relative_to(root)), name, spec))
    workflows = root / ".github" / "workflows"
    for path in sorted(workflows.glob("*.y*ml")) if workflows.is_dir() else []:
        text = re.sub(r"\\\n\s*", " ", path.read_text(encoding="utf-8"))        # join shell line continuations
        for line in text.splitlines():
            m = re.search(r"pip install (.*)$", line)
            if not m:
                continue
            tokens = [a or b for a, b in re.findall(r'"([^"]+)"|(\S+)', m.group(1))]
            skip = False
            for req in tokens:
                if skip:
                    skip = False
                    continue
                option = req.split("=", 1)[0]
                if option in _ARG_OPTIONS or (len(req) > 2 and req[:2] in _ARG_OPTIONS and not req.startswith("--")):
                    found.append((str(path.relative_to(root)), UNSCANNABLE, req))
                    skip = req in _ARG_OPTIONS          # the next token is the option's argument
                elif req.startswith("-"):
                    continue
                elif req.startswith(("$", ".", "/", "git+", "~")) or "://" in req or "/" in req:
                    found.append((str(path.relative_to(root)), UNSCANNABLE, req))
                else:
                    name, spec = parse_requirement(req)
                    found.append((str(path.relative_to(root)), name, spec))
    for path in sorted((root / "packages").glob("*/package.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for section in ("dependencies", "optionalDependencies", "devDependencies"):
            for name, spec in (data.get(section) or {}).items():
                found.append((str(path.relative_to(root)), _norm(name), "==" + spec if re.match(r"^\d", spec) else spec))
    return found


def check_installs(matrix: dict, installs: List[Tuple[str, str, str]]) -> List[Finding]:
    out: List[Finding] = []
    known = known_names(matrix)
    framework_names = {_norm(a["name"]): a for c in matrix["components"] if c.get("kind") in PINNED_KINDS for a in c.get("artifacts") or []}
    for source, name, spec in installs:
        if name == UNSCANNABLE:
            out.append(Finding("UNSCANNABLE_INSTALL", spec, f"{source} installs from something the licence scan cannot read (a requirements "
                                                              "file, path, URL, index or editable install); list the packages on the command line"))
            continue
        if name.startswith("redevops-qa"):
            continue        # the repository's own packages
        if name not in known:
            out.append(Finding("UNKNOWN_DEPENDENCY", name, f"installed by {source} but not listed in the licence matrix"))
            continue
        if name in framework_names:
            art = framework_names[name]
            if not spec.startswith("=="):
                out.append(Finding("UNPINNED", name, f"{source} installs an adapter framework without an exact pin (found {spec or 'no specifier'!r})"))
            elif spec[2:].strip() != str(art["version"]):
                out.append(Finding("PIN_MISMATCH", name, f"{source} pins {spec[2:].strip()} but the matrix records {art['version']}"))
    return out


# --------------------------------------------------------------------------------------------- what the bundle ships
def check_bundle_lock(matrix: dict, lock: dict) -> List[Finding]:
    """Every wheel of the bundle's third-party lock must be recorded in the matrix under a shipping status, with the same name, version, file name, sha256 and declared licence; and the
    matrix must not record a shipped wheel that the lock does not hold. Without this the two drift silently (they did)."""
    out: List[Finding] = []
    recorded: Dict[Tuple[str, str], Tuple[str, dict, str]] = {}
    for comp in matrix.get("components", []):
        for wheel in comp.get("shipped_wheels") or []:
            if isinstance(wheel, dict):
                recorded[(_norm(wheel.get("name", "")), str(wheel.get("version", "")))] = (comp["id"], wheel, comp.get("redistribution", {}).get("status", ""))
    locked = set()
    for w in lock.get("wheels", []):
        key = (_norm(w["name"]), str(w["version"]))
        locked.add(key)
        hit = recorded.get(key)
        if hit is None:
            out.append(Finding("UNLISTED_SHIPPED_WHEEL", w["name"], f"{w['filename']} is in bundle/third-party.lock.json but no matrix entry records it as a shipped wheel"))
            continue
        cid, wheel, status = hit
        if status not in SHIPPING:
            out.append(Finding("SHIPPED_NOT_STAGED", cid, f"{w['filename']} is shipped in the bundle but its entry is {status}"))
        if wheel.get("file") != w["filename"] or wheel.get("sha256") != w["sha256"]:
            out.append(Finding("SHIPPED_WHEEL_MISMATCH", cid, f"the matrix records {wheel.get('file')} {str(wheel.get('sha256'))[:12]}, the lock holds {w['filename']} {w['sha256'][:12]}"))
        if wheel.get("license_declared") != w.get("license"):
            out.append(Finding("SHIPPED_LICENSE_DRIFT", cid, f"the matrix records the declared licence {wheel.get('license_declared')!r}, the lock {w.get('license')!r}"))
    for key, (cid, wheel, _status) in sorted(recorded.items()):
        if key not in locked:
            out.append(Finding("STALE_SHIPPED_WHEEL", cid, f"{wheel.get('file')} is recorded as shipped but is not in bundle/third-party.lock.json"))
    return out


# --------------------------------------------------------------------------------------------- the notices that ship, and the tables of facts behind the matrix
_NODE_ITEM = re.compile(r"^- (.+?), located at (.+?), is licensed as follows:[ \t]*$", re.M)
_NPM_BODY_HEAD = re.compile(r"^=+\n")
_NPM_BODY_TAIL = re.compile(r"\n=+\s*$")
NODE_TABLE_SCHEMA = "redevops-qa/node-licence-sections"
NPM_TABLE_SCHEMA = "redevops-qa/npm-inlined-packages"
#: licences the registry declares and the notice text classifies as, for the same package (the one pair that is allowed to differ is a package with no licence text at all)
#: words a Node.js LICENSE section must contain for the licence its table row states: a list of alternatives, each a tuple of words that must all be there (whitespace collapsed, lower case)
NODE_SPDX_SUPPORT = {
    "MIT": [("permission is hereby granted, free of charge",)], "Apache-2.0": [("apache license",)],
    "BSD-3-Clause": [("neither the name",), ("names of the contributors may not be used to endorse",)], "ISC": [("permission to use, copy, modify, and/or distribute",)],
    "Zlib": [("altered source versions must be plainly marked",)], "Unicode-3.0": [("unicode license v3",)], "BlueOak-1.0.0": [("blue oak model license",)], "Artistic-2.0": [("artistic license 2.0",)],
    "CC0-1.0": [("dedicated", "public domain")], "CC0-1.0 OR BSD-2-Clause": [("creativecommons.org/publicdomain/zero", "bsd 2-clause license")],
}
_NPM_AGREE = {"MIT": "MIT", "ISC": "ISC", "BSD-3-Clause": "BSD-3-Clause", "BSD-2-Clause": "BSD-2-Clause", "BlueOak-1.0.0": "BlueOak-1.0.0"}


def location_class(location: str) -> str:
    """Where in the Node.js source tree a licence section says the component lives (a statement about the path only, not about what is linked into the executable)."""
    loc = location.strip().rstrip("/")
    if loc.startswith(("tools/", "test/")) or loc == "deps/googletest":
        return "tools-or-test-path"
    if loc in ("deps/npm", "deps/corepack"):
        return "separate-javascript-tree"
    return "source-dependency"


def node_license_sections(text: str) -> List[dict]:
    """The externally maintained libraries a Node.js LICENSE file lists ('- NAME, located at PATH, is licensed as follows:'), each with the sha256 of its section (from its list line to the next)."""
    hits = list(_NODE_ITEM.finditer(text))
    out = []
    for i, m in enumerate(hits):
        end = hits[i + 1].start() if i + 1 < len(hits) else len(text)
        out.append({"name": m.group(1), "location": m.group(2), "location_class": location_class(m.group(2)),
                    "section_sha256": hashlib.sha256(text[m.start():end].encode("utf-8")).hexdigest()})
    return out


def npm_notice_sections(text: str) -> Dict[str, Tuple[str, str]]:
    """{'name@version': (licence class, sha256 of the section body)} of a '%% name@version NOTICES AND INFORMATION BEGIN HERE' sidecar file (the body is what lies between the '====' rules)."""
    parts = _SECTION.split(text)
    out: Dict[str, Tuple[str, str]] = {}
    for i in range(1, len(parts), 2):
        body = parts[i + 1].split("\nEND OF ", 1)[0]
        body = _NPM_BODY_TAIL.sub("", _NPM_BODY_HEAD.sub("", body, count=1))
        out[parts[i]] = (classify_notice(body), hashlib.sha256(body.encode("utf-8")).hexdigest())
    return out


def _load_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_notices_lock(path: Path = NOTICES_LOCK) -> dict:
    return _load_json(path)


def _safe_dest(dest: object) -> bool:
    if not isinstance(dest, str) or not dest or dest.startswith("/") or "\\" in dest:
        return False
    return all(part not in ("", ".", "..") for part in dest.split("/"))


def check_notices_lock(matrix: dict, lock: dict, root: Path = ROOT) -> List[Finding]:
    """The notices lock (what the bundle ships under THIRD_PARTY_NOTICES) against the repository and the matrix: every file well formed, every repository file present with its digest and no
    repository file unlisted, every licence file the matrix records for a shipped wheel in the lock (with the digest the matrix records), nothing in the lock that is not shipped, and every notice
    an evidence item names present."""
    out: List[Finding] = []
    if lock.get("schema") != NOTICES_LOCK_SCHEMA or lock.get("version") != 1 or not isinstance(lock.get("files"), list) or not lock["files"]:
        return [Finding("NOTICES_LOCK", "notices.lock.json", f"schema must be {NOTICES_LOCK_SCHEMA} version 1 with a non-empty files list")]
    by_id: Dict[str, dict] = {}
    dests = set()
    repo_paths = set()
    wheel_files: Dict[Tuple[str, str, str], str] = {}
    for f in lock["files"]:
        fid = f.get("id") if isinstance(f, dict) else None
        if not _nonempty(fid) or fid in by_id:
            out.append(Finding("NOTICES_LOCK", str(fid), "file id missing or duplicated"))
            continue
        by_id[fid] = f
        if not _safe_dest(f.get("dest")) or f["dest"] in dests or f["dest"] in ("INDEX.json",):
            out.append(Finding("NOTICES_LOCK", fid, f"dest {f.get('dest')!r} is not a unique relative path of the tree"))
        dests.add(f.get("dest"))
        if not _SHA256.match(str(f.get("sha256", ""))):
            out.append(Finding("NOTICES_LOCK", fid, "sha256 must be 64 lowercase hex digits"))
        if not isinstance(f.get("covers"), list):
            out.append(Finding("NOTICES_LOCK", fid, "covers must be a list (empty when the file belongs to no evidence item)"))
        origin = f.get("origin") or {}
        kind = origin.get("kind")
        if kind == "wheel":
            if not all(_nonempty(origin.get(k)) for k in ("wheel", "version", "member")):
                out.append(Finding("NOTICES_LOCK", fid, "a wheel origin names the wheel, its version and the member"))
            else:
                wheel_files[(_norm(origin["wheel"]), str(origin["version"]), origin["member"])] = f.get("sha256", "")
        elif kind in ("upstream", "authored"):
            rel = str(origin.get("path", ""))
            repo_paths.add(rel)
            path = Path(root) / rel
            if not rel.startswith("third_party/notices/") or not _safe_dest(rel):
                out.append(Finding("NOTICES_LOCK", fid, f"{rel!r} is not a file under third_party/notices/"))
            elif not path.is_file():
                out.append(Finding("NOTICES_LOCK", fid, f"{rel} does not exist"))
            elif hashlib.sha256(path.read_bytes()).hexdigest() != f.get("sha256"):
                out.append(Finding("NOTICE_DIGEST", fid, f"{rel} does not have the sha256 the lock records"))
            if kind == "upstream":
                if not str(origin.get("url", "")).startswith("https://") or not _DATE.match(str(origin.get("retrieved_on", ""))):
                    out.append(Finding("NOTICES_LOCK", fid, "an upstream file records the https url it was fetched from and the date (retrieved_on)"))
                if origin.get("excerpt") and not str(f.get("label", "")).startswith("EXCERPT"):
                    out.append(Finding("NOTICES_LOCK", fid, "an excerpt is labelled EXCERPT (label), so that nobody reads it as a whole file"))
                if "original" in str(f.get("dest", "")).lower() and not _nonempty(f.get("label")):
                    out.append(Finding("NOTICES_LOCK", fid, "a text of a related project (original, candidate, upstream of a fork) carries a label that says whose it is"))
        else:
            out.append(Finding("NOTICES_LOCK", fid, "origin.kind must be wheel, upstream or authored"))
    base = Path(root) / "third_party" / "notices"
    if base.is_dir():
        for p in sorted(base.rglob("*")):
            rel = p.relative_to(root).as_posix()
            if p.is_file() and p.name != "notices.lock.json" and rel not in repo_paths:
                out.append(Finding("UNLISTED_NOTICE_FILE", rel, "a file under third_party/notices that the notices lock does not list (it would not ship)"))
    recorded: Dict[Tuple[str, str, str], str] = {}
    for comp in matrix.get("components", []):
        if (comp.get("redistribution") or {}).get("status") not in SHIPPING:
            continue
        for wheel in comp.get("shipped_wheels") or []:
            for lf in wheel.get("license_files") or []:
                recorded[(_norm(wheel.get("name", "")), str(wheel.get("version", "")), lf.get("path"))] = lf.get("sha256")
    for key, digest in sorted(recorded.items()):
        if key not in wheel_files:
            out.append(Finding("NOTICE_NOT_SHIPPED", f"{key[0]} {key[1]}", f"{key[2]} is a licence file of a shipped wheel but the notices lock does not ship a copy"))
        elif wheel_files[key] != digest:
            out.append(Finding("NOTICE_DIGEST", f"{key[0]} {key[1]}", f"{key[2]}: the lock and the matrix record different sha256 values"))
    for key in sorted(set(wheel_files) - set(recorded)):
        out.append(Finding("NOTICES_LOCK", f"{key[0]} {key[1]}", f"{key[2]} is locked as a notice but the matrix does not record it as a licence file of that wheel"))
    by_url: Dict[str, List[dict]] = {}
    for f in by_id.values():
        if (f.get("origin") or {}).get("url"):
            by_url.setdefault(f["origin"]["url"], []).append(f)
    for comp in matrix.get("components", []):
        for item in comp.get("third_party_evidence") or []:
            if not isinstance(item, dict):
                continue
            for src in item.get("sources") or []:                      # a quote is checked against the stored bytes where the source is pinned (a notice with the same url); the others are checked only for presence
                if isinstance(src, dict) and src.get("quote") and src.get("url") in by_url:
                    bodies = [(Path(root) / f["origin"]["path"]).read_text(encoding="utf-8", errors="replace") for f in by_url[src["url"]] if (Path(root) / str(f["origin"].get("path", ""))).is_file()]
                    if bodies and not any(src["quote"] in b for b in bodies):
                        out.append(Finding("QUOTE_NOT_IN_SOURCE", comp.get("id", "?"), f"evidence {item.get('id')}: the quote {src['quote'][:60]!r} is not in the pinned file(s) of {src['url']}"))
            for nid in item.get("licence_texts") or []:
                if nid not in by_id:
                    out.append(Finding("EVIDENCE_NOTICE", comp.get("id", "?"), f"evidence {item.get('id')}: licence text {nid!r} is not in the notices lock"))
                elif item.get("id") not in (by_id[nid].get("covers") or []):
                    out.append(Finding("EVIDENCE_NOTICE", comp.get("id", "?"), f"evidence {item.get('id')}: the lock does not list it under covers of {nid}"))
            for src in item.get("sources") or []:
                if isinstance(src, dict) and src.get("role") == "licence_text" and _nonempty(src.get("notice")):
                    entry = by_id.get(src["notice"])
                    if entry is None:
                        out.append(Finding("EVIDENCE_NOTICE", comp.get("id", "?"), f"evidence {item.get('id')}: notice {src['notice']!r} is not in the notices lock"))
                    elif src.get("ships_as_fetched") is True and entry.get("sha256") != src.get("sha256"):
                        out.append(Finding("EVIDENCE_NOTICE", comp.get("id", "?"), f"evidence {item.get('id')}: the fetched text ({str(src.get('sha256'))[:12]}) is not the shipped notice {src['notice']} ({str(entry.get('sha256'))[:12]})"))
    return out


def npm_table_digests(data: dict) -> Dict[str, str]:
    """Digests over what was FETCHED, derived from an npm table: the sorted 'package tarball-sha256' lines (one per distinct package) and the sorted 'package licence-file sha256' lines.
    An evidence source may name one of them (``derived``) instead of a digest of the table file itself."""
    rows = {r.get("package"): r for r in data.get("packages", [])}
    tarballs = "\n".join(sorted(f"{k} {r.get('tarball_sha256')}" for k, r in rows.items()))
    files = "\n".join(sorted(f"{k} {f} {h}" for k, r in rows.items() for f, h in (r.get("licence_files_in_tarball") or {}).items()))
    return {"npm-table:tarballs": hashlib.sha256(tarballs.encode()).hexdigest(), "npm-table:licence-files": hashlib.sha256(files.encode()).hexdigest()}


def check_evidence_tables(matrix: dict, root: Path = ROOT) -> List[Finding]:
    """The JSON tables an evidence item points at (``table: {path, sha256, kind}``): present, with the recorded digest and the right schema."""
    out: List[Finding] = []
    for comp in matrix.get("components", []):
        for item in comp.get("third_party_evidence") or []:
            table = item.get("table") if isinstance(item, dict) else None
            if table is None:
                continue
            at = f"{comp.get('id')}/{item.get('id')}"
            path = Path(root) / str(table.get("path", ""))
            if not path.is_file() or not str(table.get("path", "")).startswith("third_party/evidence/"):
                out.append(Finding("EVIDENCE_TABLE", at, f"{table.get('path')} is not a file under third_party/evidence/"))
                continue
            if hashlib.sha256(path.read_bytes()).hexdigest() != table.get("sha256"):
                out.append(Finding("EVIDENCE_TABLE", at, f"{table.get('path')} does not have the recorded sha256"))
                continue
            data = _load_json(path)
            want = {"node-licence-sections": NODE_TABLE_SCHEMA, "npm-inlined-packages": NPM_TABLE_SCHEMA}.get(table.get("kind"))
            if want is None or data.get("schema") != want:
                out.append(Finding("EVIDENCE_TABLE", at, f"{table.get('path')}: kind {table.get('kind')!r} and schema {data.get('schema')!r} do not agree"))
            elif table.get("kind") == "npm-inlined-packages":
                if data.get("count") != len(data.get("packages", [])):
                    out.append(Finding("EVIDENCE_TABLE", at, f"{table.get('path')}: count {data.get('count')} is not the number of rows {len(data.get('packages', []))}"))
                if data.get("distinct") != len({r.get("package") for r in data.get("packages", [])}):
                    out.append(Finding("EVIDENCE_TABLE", at, f"{table.get('path')}: distinct is not the number of distinct packages"))
            elif data.get("count") != len(data.get("sections", [])):
                out.append(Finding("EVIDENCE_TABLE", at, f"{table.get('path')}: count {data.get('count')} is not the number of sections {len(data.get('sections', []))}"))
    # a source digest must be of something fetched or derived from what was fetched, never the digest of one of this repository's own evidence tables
    own = {hashlib.sha256(p.read_bytes()).hexdigest(): p.name for p in sorted((Path(root) / "third_party" / "evidence").glob("*.json"))} if (Path(root) / "third_party" / "evidence").is_dir() else {}
    for comp in matrix.get("components", []):
        by_item = {i.get("id"): i for i in comp.get("third_party_evidence") or [] if isinstance(i, dict)}
        for item in by_item.values():
            for src in item.get("sources") or []:
                if not isinstance(src, dict):
                    continue
                at = f"{comp.get('id')}/{item.get('id')}"
                if src.get("sha256") in own:
                    out.append(Finding("EVIDENCE_SELF_REFERENCE", at, f"a {src.get('role')} source carries the sha256 of the repository's own table {own[src['sha256']]}: a table is derived, not fetched (name what it was derived from with `derived`)"))
                if src.get("derived"):
                    table = item.get("table")
                    if not isinstance(table, dict) or table.get("kind") != "npm-inlined-packages" or not (Path(root) / str(table.get("path", ""))).is_file():
                        out.append(Finding("EVIDENCE_DERIVED", at, "a derived source needs the npm table of its own item"))
                    elif npm_table_digests(_load_json(Path(root) / table["path"])).get(src["derived"]) != src.get("sha256"):
                        out.append(Finding("EVIDENCE_DERIVED", at, f"the sha256 of the source is not {src['derived']} recomputed from the table's rows"))
    return out


def check_notices_tree(lock: dict, tree: Path, wheelhouse: Optional[Path] = None) -> List[Finding]:
    """A built bundle's THIRD_PARTY_NOTICES tree against the notices lock: exactly the locked files and INDEX.json, each with the locked digest, an INDEX that lists what the lock lists, and (with the
    wheelhouse) every wheel-origin file byte for byte the member of the shipped wheel."""
    import zipfile
    out: List[Finding] = []
    tree = Path(tree)
    if not tree.is_dir():
        return [Finding("NOTICES_TREE", str(tree), "no such directory")]
    files = {p.relative_to(tree).as_posix(): p for p in tree.rglob("*") if p.is_file()}
    want = {f["dest"]: f for f in lock.get("files", [])}
    for dest in sorted(set(want) - set(files)):
        out.append(Finding("NOTICES_TREE", dest, "locked but not in the tree"))
    for dest in sorted(set(files) - set(want) - {"INDEX.json"}):
        out.append(Finding("NOTICES_TREE", dest, "in the tree but not in the notices lock"))
    for dest, f in sorted(want.items()):
        if dest in files and hashlib.sha256(files[dest].read_bytes()).hexdigest() != f.get("sha256"):
            out.append(Finding("NOTICE_DIGEST", dest, "the file does not have the locked sha256"))
    if "INDEX.json" not in files:
        out.append(Finding("NOTICES_TREE", "INDEX.json", "missing"))
    else:
        index = _load_json(files["INDEX.json"])
        listed = {e.get("path"): e.get("sha256") for e in index.get("files", [])}
        if listed != {d: f.get("sha256") for d, f in want.items()}:
            out.append(Finding("NOTICES_TREE", "INDEX.json", "does not list exactly the locked files with their sha256"))
    if wheelhouse is not None:
        for dest, f in sorted(want.items()):
            origin = f.get("origin") or {}
            if origin.get("kind") != "wheel" or dest not in files:
                continue
            wheels = [w for w in Path(wheelhouse).glob("*.whl") if _wheel_key(w.name) == (_norm(origin["wheel"]), str(origin["version"]))]
            if len(wheels) != 1:
                out.append(Finding("NOTICES_TREE", dest, f"expected exactly one wheel {origin['wheel']} {origin['version']} in the wheelhouse, found {len(wheels)}"))
                continue
            with zipfile.ZipFile(wheels[0]) as zf:
                if origin["member"] not in zf.namelist() or zf.read(origin["member"]) != files[dest].read_bytes():
                    out.append(Finding("NOTICES_TREE", dest, f"is not byte for byte {origin['member']} of {wheels[0].name}"))
    return out


def _wheel_key(filename: str) -> Optional[Tuple[str, str]]:
    m = re.fullmatch(r"([A-Za-z0-9_.]+)-([A-Za-z0-9_.!+]+)-.+\.whl", filename)
    return (_norm(m.group(1)), m.group(2)) if m else None


# --------------------------------------------------------------------------------------------- the inventory of shipped third-party material (best effort)
IMPORT_TABLE_SCHEMA = "redevops-qa/playwright-import-candidates"
_YEARS = r"(?:(?:19|20)\d\d(?:\s*[-,\u2013]\s*(?:(?:19|20)\d\d|present))*[,\s]*)+"
_INV_HOLD = re.compile(r"copyright\s*(?:\(c\)|\u00a9)?\s*" + _YEARS + r"([^\n\r*]{2,80})|(?:\(c\)|\u00a9)\s*" + _YEARS + r"([^\n\r*]{2,80})", re.I)
_INV_HOLD2 = re.compile(r"(?:\(c\)|\u00a9)\s+([A-Z][A-Za-z0-9.,' &-]{2,60})|(?<![a-z])copyright[\s#]+(?!notice|and\b|holder|law|statement|information|\(c\)|owner|the\b|of\b|\d)([A-Z][A-Za-z.' -]{3,50})")
_INV_MARK = re.compile(r"@license|spdx-license-identifier|permission is hereby granted|dual licensed|licensed under|released under the|all rights reserved|redistribution and use in source", re.I)
_INV_SKIP = {"wasm", "ttf", "png", "ico", "gif", "jpg", "jpeg", "woff", "woff2", "pyc", "map", "svg"}


def scan_wheel_inventory(zf, own_holders: Iterable[str]) -> Dict[str, Tuple[List[str], List[str]]]:
    """A candidate inventory of licence-bearing text files of a wheel, derived mechanically: every text file (binary files and fonts, images and source maps are skipped) is searched for copyright holder
    lines ('Copyright (c) 2019 Mapbox', '(c) JS Foundation ...', 'copyright Andre Burgaud') and licence markers ('Licensed under', 'Permission is hereby granted', 'SPDX-License-Identifier', '@license',
    'Dual licensed', 'All rights reserved'). A file is a candidate when it names a holder that is not one of ``own_holders`` (regular expressions, case-insensitive), or carries a marker and no holder
    and no Apache-2.0 header of the product's own. BEST EFFORT: a file with no header (a minified file whose comments were stripped, a library with no notice) is not found, and the scan cannot show
    that an inventory is complete. Returns {path: (foreign holders, markers)}."""
    own = [re.compile(o, re.I) for o in own_holders]
    out: Dict[str, Tuple[List[str], List[str]]] = {}
    for name in zf.namelist():
        if name.endswith("/") or name.rsplit(".", 1)[-1].lower() in _INV_SKIP or name.endswith("/node"):
            continue
        data = zf.read(name)
        if b"\0" in data[:4096]:
            continue
        text = data.decode("utf-8", "replace")
        holders = {(m.group(1) or m.group(2)).strip(" .,;:*/'\"") for m in _INV_HOLD.finditer(text)} | {(m.group(1) or m.group(2)).strip(" .,;:*/'\"") for m in _INV_HOLD2.finditer(text)}
        foreign = sorted(h for h in holders if h and not any(o.search(h) for o in own))
        marks = sorted({m.group(0).lower() for m in _INV_MARK.finditer(text)})
        if foreign or (marks and not holders and "apache license" not in text.lower()):
            out[name] = (foreign[:6], marks[:6])
    return out


def _inventory_patterns(comp: dict, rec: dict) -> List[str]:
    pats = [lf.get("path") for lf in rec.get("license_files") or []]
    for item in comp.get("third_party_evidence") or []:
        if isinstance(item, dict) and item.get("wheel", rec.get("name")) == rec.get("name"):
            pats += list(item.get("shipped_members") or []) + ([item["inlined_in"]] if item.get("inlined_in") else []) + list(item.get("covers_paths") or [])
    return [p for p in pats if isinstance(p, str)]


def check_inventory_scan(matrix: dict, comp: dict, rec: dict, zf, at: str) -> List[Finding]:
    """Fail on a licence-bearing file the header scan finds in a shipped wheel that no evidence item covers (by shipped_members, inlined_in or covers_paths) and no recorded licence file is. The scan is
    best effort and CANNOT prove completeness: it finds what carries a header, nothing else."""
    import fnmatch
    inv = matrix.get("inventory")
    if not isinstance(inv, dict) or not comp.get("third_party_evidence"):
        return []
    pats = _inventory_patterns(comp, rec)
    out = []
    for path, (holders, marks) in sorted(scan_wheel_inventory(zf, inv.get("own_holders") or []).items()):
        if not any(fnmatch.fnmatchcase(path, pat) for pat in pats):
            out.append(Finding("INVENTORY_UNCOVERED", at, f"{path} carries a licence or copyright header (holders {holders}, markers {marks}) that no evidence item covers: add an item whose shipped_members, inlined_in or covers_paths names it"))
    return out


def check_import_candidates(matrix: dict, root: Path = ROOT) -> List[Finding]:
    """The packages Playwright's own sources import for the parts that end up in the wheel (third_party/evidence/playwright-*-import-candidates.json, made by tools/collect_licence_evidence.py
    import-candidates from the repository tarball and lock file at the pinned tag) against the matrix: each must be one of the inlined npm packages of the sidecar notices, named in an evidence item
    (``packages``), or listed under inventory.excluded_packages with the reason it is not in the wheel. Best effort: it follows import statements, not what a bundler actually inlined."""
    inv = matrix.get("inventory")
    if not isinstance(inv, dict):
        return []
    out: List[Finding] = []
    table_path = next(((Path(root) / "third_party" / "evidence").glob("playwright-*-import-candidates.json")), None) if (Path(root) / "third_party" / "evidence").is_dir() else None
    if table_path is None:
        return [Finding("INVENTORY_CANDIDATES", "matrix", "the inventory block needs third_party/evidence/playwright-*-import-candidates.json")]
    data = _load_json(table_path)
    if data.get("schema") != IMPORT_TABLE_SCHEMA:
        return [Finding("INVENTORY_CANDIDATES", table_path.name, f"schema must be {IMPORT_TABLE_SCHEMA}")]
    covered = set()
    for comp in matrix.get("components", []):
        for item in comp.get("third_party_evidence") or []:
            if isinstance(item, dict):
                covered |= set(item.get("packages") or [])
                table = item.get("table")
                if isinstance(table, dict) and table.get("kind") == "npm-inlined-packages" and (Path(root) / str(table.get("path", ""))).is_file():
                    covered |= {r.get("package", "").rsplit("@", 1)[0] for r in _load_json(Path(root) / table["path"]).get("packages", [])}
    excluded = inv.get("excluded_packages") or {}
    for bad, reason in excluded.items():
        if not _nonempty(reason):
            out.append(Finding("INVENTORY_CANDIDATES", "matrix", f"inventory.excluded_packages {bad}: a reason is required"))
    names = {p.get("name") for p in data.get("packages", [])}
    for pkg in sorted(names - covered - set(excluded)):
        out.append(Finding("INVENTORY_UNCOVERED_PACKAGE", "matrix", f"{pkg} is imported by Playwright's sources for the wheel (import-candidates table) but is in no evidence item (packages), not among the inlined npm packages and not under inventory.excluded_packages"))
    return out


# --------------------------------------------------------------------------------------------- the wheels themselves
_SECTION = re.compile(r"^%% (\S+) NOTICES AND INFORMATION BEGIN HERE\n", re.M)
# a licence-bearing file: any file whose name says licence, copying, notice(s), third-party, authors or copyright, anywhere in the wheel, and anything under a licenses/ or notices/ directory
_LICENCE_FILE_NAME = re.compile(r"(^|/)(licen[sc]es?|notices?|third[-_ ]?party[^/]*)/|(^|/)[^/]*(licen[sc]e|copying|notice|third[-_ ]?party|authors|copyright)[^/]*$", re.I)


def classify_notice(text: str) -> str:
    """The licence a notice section states, from its own words (a deterministic reading of the file, not a legal classification)."""
    t = text.lower()
    if "no license text found" in t:
        return "none-declared"
    if "blue oak model license" in t:
        return "BlueOak-1.0.0"
    if "redistribution and use in source and binary forms" in t:
        return "BSD-3-Clause" if "endorse" in t else "BSD-2-Clause"
    if "permission to use, copy, modify, and/or distribute" in t or "permission to use, copy, modify, and distribute" in t:
        return "ISC"
    if "permission is hereby granted, free of charge" in t:
        return "MIT"
    if "apache license" in t:
        return "Apache-2.0"
    return "other"


def notice_breakdown(text: str) -> Tuple[int, Dict[str, int]]:
    """(number of sections, {licence: count}) of a sidecar notice file made of '%% name@version NOTICES AND INFORMATION BEGIN HERE' sections."""
    parts = _SECTION.split(text)
    counts: Dict[str, int] = {}
    for i in range(1, len(parts), 2):
        kind = classify_notice(parts[i + 1].split("END OF ", 1)[0])
        counts[kind] = counts.get(kind, 0) + 1
    return len(parts) // 2, dict(sorted(counts.items()))


def check_wheelhouse(matrix: dict, wheelhouse: Path, root: Path = ROOT) -> List[Finding]:
    """What the matrix says about the shipped wheels against the wheels themselves (the built bundle's wheelhouse): the file and its sha256, every recorded licence file by path and sha256,
    no licence-like file the matrix does not record, every member recorded under recorded_members (by path, size in BYTES, as stored in the wheel, and sha256), and, where the matrix records a breakdown of an inlined notice file, the breakdown recomputed from the file."""
    import zipfile
    out: List[Finding] = []
    for comp in matrix.get("components", []):
        for rec in comp.get("shipped_wheels") or []:
            at = f"{comp['id']}/{rec.get('name')}"
            path = Path(wheelhouse) / str(rec.get("file"))
            if not path.is_file():
                out.append(Finding("WHEEL_MISSING", at, f"{rec.get('file')} is not in {wheelhouse}"))
                continue
            if hashlib.sha256(path.read_bytes()).hexdigest() != rec.get("sha256"):
                out.append(Finding("WHEEL_DIGEST", at, f"{rec.get('file')} does not have the recorded sha256"))
                continue
            with zipfile.ZipFile(path) as zf:
                names = set(zf.namelist())
                recorded = {lf["path"]: lf["sha256"] for lf in rec.get("license_files") or []}
                for member, digest in recorded.items():
                    if member not in names:
                        out.append(Finding("LICENCE_FILE_MISSING", at, f"{member} is not in the wheel"))
                    elif hashlib.sha256(zf.read(member)).hexdigest() != digest:
                        out.append(Finding("LICENCE_FILE_DIGEST", at, f"{member} does not have the recorded sha256"))
                for member in sorted(n for n in names if _LICENCE_FILE_NAME.search(n) and not n.endswith("/") and n not in recorded):
                    out.append(Finding("UNRECORDED_LICENCE_FILE", at, f"{member} is in the wheel but not recorded in license_files"))
                for item in rec.get("recorded_members") or []:
                    member = item.get("path")
                    if member not in names:
                        out.append(Finding("MEMBER_MISSING", at, f"{member} is not in the wheel"))
                        continue
                    data = zf.read(member)
                    if len(data) != item.get("size") or zf.getinfo(member).file_size != item.get("size"):
                        out.append(Finding("MEMBER_SIZE_MISMATCH", at, f"{member} is {zf.getinfo(member).file_size} bytes in the wheel, the matrix records {item.get('size')}"))
                    if hashlib.sha256(data).hexdigest() != item.get("sha256"):
                        out.append(Finding("MEMBER_DIGEST_MISMATCH", at, f"{member} does not have the recorded sha256"))
                for notice in rec.get("inlined_notices") or []:
                    member = notice.get("path")
                    if member not in names:
                        out.append(Finding("LICENCE_FILE_MISSING", at, f"{member} is not in the wheel"))
                        continue
                    sections, counts = notice_breakdown(zf.read(member).decode("utf-8", "replace"))
                    if sections != notice.get("sections") or counts != notice.get("breakdown"):
                        out.append(Finding("NOTICE_BREAKDOWN_MISMATCH", at, f"{member}: the file has {sections} sections {counts}, the matrix records {notice.get('sections')} {notice.get('breakdown')}"))
                out += _check_wheel_evidence(comp, rec, zf, at, root)
                out += check_inventory_scan(matrix, comp, rec, zf, at)
    return out


def _check_wheel_evidence(comp: dict, rec: dict, zf, at: str, root: Path) -> List[Finding]:
    """The evidence items of ``comp`` against the wheel ``zf``: every shipped member of an item is in the wheel and recorded with its digest, every inlined_in file is in the wheel, and the tables
    behind an item (the Node.js licence sections, the inlined npm packages) are exactly what the wheel's own notice files say."""
    out: List[Finding] = []
    names = set(zf.namelist())
    known = {m.get("path"): m.get("sha256") for m in rec.get("recorded_members") or []}
    known.update({lf.get("path"): lf.get("sha256") for lf in rec.get("license_files") or []})
    for item in comp.get("third_party_evidence") or []:
        if not isinstance(item, dict) or item.get("wheel", rec.get("name")) != rec.get("name"):
            continue
        iid = f"{at}/evidence {item.get('id')}"
        for src in item.get("sources") or []:                                # a source that is a member of the shipped wheel: its quote must be in the member's bytes
            if isinstance(src, dict) and src.get("wheel_member"):
                body = zf.read(src["wheel_member"]).decode("utf-8", "replace") if src["wheel_member"] in names else None
                if body is None or (src.get("quote") and src["quote"] not in body):
                    out.append(Finding("QUOTE_NOT_IN_SOURCE", iid, f"{src['wheel_member']} is not in the wheel or does not contain the quote {str(src.get('quote'))[:60]!r}"))
        for member in item.get("shipped_members") or []:
            if member not in names:
                out.append(Finding("EVIDENCE_MEMBER_MISSING", iid, f"{member} is not in the wheel"))
            elif member not in known:
                out.append(Finding("EVIDENCE_MEMBER_UNRECORDED", iid, f"{member} is named by the evidence but the matrix records no sha256 for it (recorded_members or license_files)"))
        if item.get("inlined_in") and item["inlined_in"] not in names:
            out.append(Finding("EVIDENCE_MEMBER_MISSING", iid, f"{item['inlined_in']} is not in the wheel"))
        table = item.get("table")
        if not isinstance(table, dict) or not (Path(root) / str(table.get("path", ""))).is_file():
            continue
        data = _load_json(Path(root) / table["path"])
        if table.get("kind") == "node-licence-sections":
            member = table.get("source_member")
            if member not in names:
                out.append(Finding("EVIDENCE_MEMBER_MISSING", iid, f"{member} is not in the wheel"))
                continue
            text = zf.read(member).decode("utf-8", "replace")
            now = node_license_sections(text)
            if hashlib.sha256(text.encode("utf-8")).hexdigest() != data.get("license_file_sha256"):
                out.append(Finding("NODE_TABLE_MISMATCH", iid, f"{member} is not the licence file the table was made from"))
            have = [{k: v for k, v in sec.items() if k in ("name", "location", "location_class", "section_sha256")} for sec in data.get("sections", [])]
            if now != have:
                out.append(Finding("NODE_TABLE_MISMATCH", iid, f"{member} lists {len(now)} components, the table records {len(have)}, or a section's text or place differs"))
            if any(not _nonempty(sec.get("spdx")) for sec in data.get("sections", [])):
                out.append(Finding("NODE_TABLE_MISMATCH", iid, "every section of the table states the licence its text names (spdx)"))
            hits = list(_NODE_ITEM.finditer(text))
            for n, sec in enumerate(data.get("sections", [])):
                if n >= len(hits):
                    break
                body = re.sub(r"\s+", " ", text[hits[n].start(): hits[n + 1].start() if n + 1 < len(hits) else len(text)].lower())
                alts = NODE_SPDX_SUPPORT.get(sec.get("spdx"))
                if alts is None or not any(all(w in body for w in alt) for alt in alts):
                    out.append(Finding("NODE_TABLE_MISMATCH", iid, f"{sec.get('name')}: the section's own text does not support the licence {sec.get('spdx')!r} the table states"))
        elif table.get("kind") == "npm-inlined-packages":
            now: Dict[Tuple[str, str], Tuple[str, str]] = {}
            for member in table.get("source_members") or []:
                if member not in names:
                    out.append(Finding("EVIDENCE_MEMBER_MISSING", iid, f"{member} is not in the wheel"))
                    continue
                for key, (kind, digest) in npm_notice_sections(zf.read(member).decode("utf-8", "replace")).items():
                    now[(key, member.rsplit("/", 1)[-1])] = (kind, digest)
            have_pk = {(p.get("package"), p.get("notice_file")): p for p in data.get("packages", [])}
            if data.get("count") != len(now) or data.get("distinct") != len({k[0] for k in now}):
                out.append(Finding("NPM_TABLE_MISMATCH", iid, f"the table says {data.get('count')} sections of {data.get('distinct')} packages, the wheel's notice files have {len(now)} of {len({k[0] for k in now})}"))
            for key in sorted(set(now) - set(have_pk)):
                out.append(Finding("NPM_TABLE_MISMATCH", iid, f"{key[0]} has a notice section in {key[1]} but no row in the table"))
            for key in sorted(set(have_pk) - set(now)):
                out.append(Finding("NPM_TABLE_MISMATCH", iid, f"{key[0]} is in the table for {key[1]} but has no notice section in the wheel"))
            for key in sorted(set(now) & set(have_pk)):
                row = have_pk[key]
                kind, digest = now[key]
                if row.get("notice_section_sha256") != digest:
                    out.append(Finding("NPM_TABLE_MISMATCH", iid, f"{key[0]}: the notice text in {key[1]} is not the one the table was made from"))
                if row.get("tarball_sha512_verified") is not True:
                    out.append(Finding("NPM_TABLE_MISMATCH", iid, f"{key[0]}: the published tarball was not verified against its registry integrity value"))
                registry = str(row.get("registry_license"))
                has_file = bool(row.get("licence_files_in_tarball"))
                if kind == "none-declared":
                    if has_file or registry in ("", "None"):
                        out.append(Finding("NPM_LICENCE_DISAGREES", iid, f"{key[0]}: the notice holds no licence text, the table must record a declared licence and no licence file in the tarball"))
                elif _NPM_AGREE.get(registry) != kind or not row.get("notice_text_contains_tarball_licence_file"):
                    out.append(Finding("NPM_LICENCE_DISAGREES", iid, f"{key[0]}: the registry declares {registry!r}, the notice text reads as {kind}, or the tarball's licence file is not in the notice"))
    return out


# --------------------------------------------------------------------------------------------- optional upstream check
Fetcher = Callable[[str], bytes]


def _default_fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=30) as response:     # noqa: S310 (https URL derived from the matrix)
        return response.read()


def raw_url(blob_url: str) -> str:
    m = re.match(r"^https://github\.com/([^/]+/[^/]+)/blob/([^/]+)/(.+)$", blob_url)
    if not m:
        raise ValueError(f"not a github blob URL: {blob_url}")
    return f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/{m.group(3)}"


def verify_upstream(matrix: dict, fetch: Fetcher = _default_fetch) -> List[Finding]:
    out: List[Finding] = []
    for comp in matrix["components"]:
        if comp.get("kind") not in PINNED_KINDS:
            continue
        try:
            digest = hashlib.sha256(fetch(raw_url(comp["license_url"]))).hexdigest()
        except Exception as exc:     # a fetch failure is a failure, never a pass
            out.append(Finding("UPSTREAM_UNREACHABLE", comp["id"], f"{type(exc).__name__}: {exc}"))
            continue
        if digest != comp["license_file_sha256"]:
            out.append(Finding("UPSTREAM_HASH_MISMATCH", comp["id"], f"upstream licence text hashes to {digest}"))
        for notice in comp.get("notices") or []:
            if notice.get("url") and notice.get("sha256"):
                try:
                    got = hashlib.sha256(fetch(raw_url(notice["url"]))).hexdigest()
                except Exception as exc:
                    out.append(Finding("UPSTREAM_UNREACHABLE", comp["id"], f"{notice['file']}: {type(exc).__name__}: {exc}"))
                    continue
                if got != notice["sha256"]:
                    out.append(Finding("UPSTREAM_HASH_MISMATCH", comp["id"], f"{notice['file']} hashes to {got}"))
    return out


def run(matrix_path: Path = DEFAULT_MATRIX, root: Path = ROOT, upstream: bool = False, fetch: Fetcher = _default_fetch) -> List[Finding]:
    try:
        matrix = load_matrix(matrix_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [Finding("MATRIX_UNREADABLE", str(matrix_path), f"{type(exc).__name__}: {exc}")]
    findings = check_matrix(matrix)
    if any(f.code == "MATRIX_SCHEMA" and f.component in ("matrix", "policy") for f in findings):
        return findings
    findings += check_installs(matrix, gather_installs(root))
    lock_path = root / "bundle" / "third-party.lock.json"
    if lock_path.is_file():
        try:
            findings += check_bundle_lock(matrix, json.loads(lock_path.read_text(encoding="utf-8")))
        except (OSError, ValueError, KeyError) as exc:
            findings.append(Finding("BUNDLE_LOCK_UNREADABLE", str(lock_path), f"{type(exc).__name__}: {exc}"))
    mroot = Path(matrix_path).resolve().parent.parent          # the repository the matrix belongs to (third_party/..): where its evidence tables and notices live; ``root`` is what is scanned for installs
    findings += check_evidence_tables(matrix, mroot)
    findings += check_import_candidates(matrix, mroot)
    notices_path = mroot / "third_party" / "notices" / "notices.lock.json"
    if notices_path.is_file():
        try:
            lock_ = load_notices_lock(notices_path)
            findings += check_notices_lock(matrix, lock_, mroot)
            findings += check_owner_decisions(matrix, lock_, mroot)
        except (OSError, ValueError) as exc:
            findings.append(Finding("NOTICES_LOCK", str(notices_path), f"{type(exc).__name__}: {exc}"))
    elif any(c.get("third_party_evidence") for c in matrix["components"]) or any(c.get("shipped_wheels") for c in matrix["components"]):
        findings.append(Finding("NOTICES_LOCK", str(notices_path), "the matrix records shipped wheels but third_party/notices/notices.lock.json does not exist"))
    if upstream:
        findings += verify_upstream(matrix, fetch)
    return findings


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--wheelhouse", type=Path, help="a built bundle's wheelhouse: check the recorded wheels, licence files and notice breakdowns against the wheels themselves")
    ap.add_argument("--notices", type=Path, help="a built bundle's THIRD_PARTY_NOTICES directory: check it against third_party/notices/notices.lock.json (and, with --wheelhouse, against the shipped wheels)")
    ap.add_argument("--verify-upstream", action="store_true", help="re-fetch each licence file at its pinned tag and compare hashes (network)")
    args = ap.parse_args(argv[1:])
    findings = run(args.matrix, args.root, args.verify_upstream)
    if args.wheelhouse:
        findings += check_wheelhouse(load_matrix(args.matrix), args.wheelhouse, args.root)
    if args.notices:
        findings += check_notices_tree(load_notices_lock(args.root / "third_party" / "notices" / "notices.lock.json"), args.notices, args.wheelhouse)
    for finding in findings:
        print(finding)
    if findings:
        return 1
    matrix = load_matrix(args.matrix)
    print(f"OK {len(matrix['components'])} components, no unknown or incompatible redistributable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
