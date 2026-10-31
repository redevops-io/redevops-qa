# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Block unknown or incompatible redistributables for the optional execution adapters.

Reads ``third_party/adapter-license-matrix.yaml`` and fails (exit 1) when:

* the matrix is malformed or a required fact is missing;
* a licence is unknown, blocked, or needs review but the entry claims it may be redistributed;
* a claim of ``redistributable`` is not supported by a verified licence text, an inspected bundle and recorded notices;
* a commercial SDK or Apple toolchain is enabled by default;
* a package that an adapter package or a workflow installs is not listed in the matrix, or is pinned differently;
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
REDISTRIBUTION = {"redistributable", "optional_extra", "excluded_by_default", "unverified"}
VERIFICATION = {"verified", "registry-metadata", "unverified"}
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
    if upstream:
        findings += verify_upstream(matrix, fetch)
    return findings


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--verify-upstream", action="store_true", help="re-fetch each licence file at its pinned tag and compare hashes (network)")
    args = ap.parse_args(argv[1:])
    findings = run(args.matrix, args.root, args.verify_upstream)
    for finding in findings:
        print(finding)
    if findings:
        return 1
    matrix = load_matrix(args.matrix)
    print(f"OK {len(matrix['components'])} components, no unknown or incompatible redistributable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
