# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Repository hygiene for this package: no secret-shaped strings, neutral wording, no frozen-source markers, determinism
across hash seeds, and identical results on repeat runs. Patterns are assembled at run time so this file does not match them."""
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
FILES = sorted(p for p in PKG.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix in
               {".py", ".md", ".toml", ".yaml", ".yml", ".json", ".txt", ".cfg", ""} and ".egg-info" not in str(p))


def j(*parts):
    return "".join(parts)


SECRET_SHAPES = {
    "aws access key id": re.compile(j("A", "KIA", "[0-9A-Z]{16}")),
    "github token": re.compile(j("gh", "[pousr]_", "[A-Za-z0-9]{30,}")),
    "slack token": re.compile(j("xo", "x[baprs]-", "[A-Za-z0-9-]{10,}")),
    "private key block": re.compile(j("-----", "BEGIN ", "[A-Z ]*", "PRIVATE KEY-----")),
    "json web token": re.compile(j("ey", "J[A-Za-z0-9_-]{10,}\\.ey", "J[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{5,}")),
    "google api key": re.compile(j("AI", "za[0-9A-Za-z_-]{35}")),
    "stripe key": re.compile(j("sk_", "(live|test)_[0-9A-Za-z]{20,}")),
    "credential assignment": re.compile(j("(?i)(pass", "word|secret|api[_-]?key|tok", "en)\\s*[:=]\\s*[\"'][A-Za-z0-9/+_=-]{16,}[\"']")),
    "long base64 blob": re.compile(j("(?<![A-Za-z0-9+/])(?![0-9a-f]+(?![A-Za-z0-9+/]))", "[A-Za-z0-9+/]{60,}", "={0,2}")),
}

WORDING = {
    "role words": re.compile(j(r"\b(?:ow", "ner|inte", "grator)\b"), re.I),
    "stage labels": re.compile(j(r"\b(?:I[1-5]|H[0-9]|Q[1-9]|B[1-3]|C[1-4]|R[1-5]|G[0-9]|S[1-7]|TK-D[0-9]|RK[0-9]+)\b")),
    "programme wording": re.compile(j(r"benchmark ", "programme|Track ", "I\\b|Track ", "P\\b|pilot ", "baseline|exploratory ", "infra"), re.I),
    "internal document names": re.compile(j("REDEVOPS_QA_", "PHASE|REDEVOPS_QA_", "TIER|REDEVOPS_QA_", "SEALED|ADR_", "QA_|_COMPONENT_", "INVENTORY")),
    "frozen-source wording": re.compile(j("frozen ", "head|frozen ", "PR|sealed ", "mutation|ground ", "truth|held", "-out set|baseline ", "freeze"), re.I),
    "phase wording": re.compile(j("Phase ", "1\\b|workstream ", "[0-9]"), re.I),
}

MARKERS = {
    "the reserved local-network subnet": j("192.", "168.", "40."),
    "a developer home directory": j("/Users", "/"),
    "a local scratch path": j("scratch", "pad"),
}


@pytest.mark.parametrize("name", sorted(SECRET_SHAPES))
def test_no_committed_file_contains_a_secret_shaped_string(name):
    pat = SECRET_SHAPES[name]
    hits = [str(p.relative_to(PKG)) for p in FILES if pat.search(p.read_text(encoding="utf-8", errors="replace"))]
    assert hits == [], hits


@pytest.mark.parametrize("name", sorted(WORDING))
def test_wording_is_neutral_in_every_file(name):
    pat = WORDING[name]
    hits = []
    for p in FILES:
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if pat.search(line):
                hits.append(f"{p.relative_to(PKG)}:{n}")
    assert hits == [], hits


@pytest.mark.parametrize("name", sorted(MARKERS))
def test_no_file_names_a_reserved_subnet_or_a_local_path(name):
    marker = MARKERS[name]
    hits = [str(p.relative_to(PKG)) for p in FILES if marker in p.read_text(encoding="utf-8", errors="replace")]
    assert hits == [], hits


def test_the_file_set_is_not_empty_and_includes_sources_and_tests():
    rels = {str(p.relative_to(PKG)) for p in FILES}
    assert "pyproject.toml" in rels and any(r.startswith("src/") for r in rels) and any(r.startswith("tests/") for r in rels)


def _driver(seed):
    env = {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/tmp"), "PYTHONHASHSEED": str(seed), "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONPATH": os.pathsep.join([str(PKG / "src")])}
    r = subprocess.run([sys.executable, "-B", str(PKG / "tests" / "qc_determinism_driver.py")], env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_results_and_hashes_are_identical_across_hash_seeds_and_processes():
    outs = {seed: _driver(seed) for seed in (0, 1, 2, 12345, "random")}
    assert len(set(outs.values())) == 1 and re.fullmatch(r"[0-9a-f]{64}", outs[0])


def test_repeat_runs_in_one_process_are_byte_identical(case_root, registry):
    from redevops_qa_checks.canonical import canonical_bytes
    from redevops_qa_checks.engine import CheckEngine
    e = CheckEngine(case_root, registry)
    for spec in (x for x in registry.entries() if x.tier == "OFFLINE"):
        s = {"check_program_ref": spec.ref, "inputs": [{"kind": "MANIFEST_PATH", "path": "."}], "tier": "OFFLINE"}
        assert canonical_bytes(e.run_check(s).value) == canonical_bytes(CheckEngine(case_root, registry).run_check(s).value)


def test_the_result_does_not_depend_on_the_order_files_were_created(tmp_path, registry):
    from qc_fixtures import good_set, write_tree
    from redevops_qa_checks.canonical import canonical_bytes
    from redevops_qa_checks.engine import CheckEngine
    docs = good_set()
    a = write_tree(tmp_path / "a", docs)
    b = write_tree(tmp_path / "b", dict(reversed(list(docs.items()))))
    for spec in (x for x in registry.entries() if x.tier == "OFFLINE"):
        s = {"check_program_ref": spec.ref, "inputs": [{"kind": "MANIFEST_PATH", "path": "."}], "tier": "OFFLINE"}
        assert canonical_bytes(CheckEngine(a, registry).run_check(s).value) == canonical_bytes(CheckEngine(b, registry).run_check(s).value), spec.id
