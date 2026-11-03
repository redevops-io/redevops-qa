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
* an adapter framework is installed without an exact pin.

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
    # --- requires
    for req in comp.get("requires") or []:
        other = by_id.get(req)
        if other is None:
            out.append(Finding("MATRIX_SCHEMA", cid, f"requires unknown component {req!r}"))
        elif red.get("default_enabled") is True and other.get("redistribution", {}).get("status") in ("excluded_by_default", "unverified"):
            out.append(Finding("ENABLED_BY_DEFAULT_NOT_APPROVED", cid, f"enabled by default but requires {req}, which is {other['redistribution']['status']}"))
    return out


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


# --------------------------------------------------------------------------------------------- the wheels themselves
_SECTION = re.compile(r"^%% (\S+) NOTICES AND INFORMATION BEGIN HERE\n", re.M)
_LICENCE_FILE_NAME = re.compile(r"(^|/)(LICEN[SC]E|NOTICE|COPYING|AUTHORS|ThirdPartyNotices)[^/]*$|\.LICENSE$", re.I)


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


def check_wheelhouse(matrix: dict, wheelhouse: Path) -> List[Finding]:
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
    if upstream:
        findings += verify_upstream(matrix, fetch)
    return findings


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--wheelhouse", type=Path, help="a built bundle's wheelhouse: check the recorded wheels, licence files and notice breakdowns against the wheels themselves")
    ap.add_argument("--verify-upstream", action="store_true", help="re-fetch each licence file at its pinned tag and compare hashes (network)")
    args = ap.parse_args(argv[1:])
    findings = run(args.matrix, args.root, args.verify_upstream)
    if args.wheelhouse:
        findings += check_wheelhouse(load_matrix(args.matrix), args.wheelhouse)
    for finding in findings:
        print(finding)
    if findings:
        return 1
    matrix = load_matrix(args.matrix)
    print(f"OK {len(matrix['components'])} components, no unknown or incompatible redistributable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
