# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The bridge is the only package that imports both sides, and importing it imports neither."""
import ast
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
BRIDGE_SRC = ROOT / "packages" / "qa-bridge" / "src" / "redevops_qa_bridge"
CONTRACTS = "runtime_contracts"
HARNESS = "agent_harness"
SPDX = "SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause"


def _tops(tree, module_level_only):
    nodes = tree.body if module_level_only else list(ast.walk(tree))
    out = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            out.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            out.add(node.module.split(".")[0])
    return out


def _py_files(base):
    return sorted(p for p in base.rglob("*.py") if "__pycache__" not in p.parts)


def test_no_other_package_imports_both_sides():
    offenders = []
    for pkg in (ROOT / "packages").iterdir():
        if not pkg.is_dir() or pkg.name == "qa-bridge":
            continue
        tops = set()
        for f in _py_files(pkg):
            tops |= _tops(ast.parse(f.read_text(encoding="utf-8")), module_level_only=False)
        if CONTRACTS in tops and HARNESS in tops:
            offenders.append(pkg.name)
    assert not offenders, f"only qa-bridge may import both runtime_contracts and agent_harness: {offenders}"


def test_the_bridge_imports_neither_dependency_at_module_level():
    for f in _py_files(BRIDGE_SRC):
        top = _tops(ast.parse(f.read_text(encoding="utf-8")), module_level_only=True)
        assert not ({CONTRACTS, HARNESS} & top), f"{f.name} imports a dependency at import time"


def test_importing_the_bridge_does_not_import_the_dependencies():
    code = ("import sys; import redevops_qa_bridge; "
            "bad = [m for m in sys.modules if m.split('.')[0] in ('runtime_contracts', 'agent_harness')]; "
            "sys.exit(1 if bad else 0)")
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(BRIDGE_SRC.parent), "PYTHONDONTWRITEBYTECODE": "1"}
    done = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def test_the_package_declares_no_runtime_dependency():
    with open(ROOT / "packages" / "qa-bridge" / "pyproject.toml", "rb") as handle:
        meta = tomllib.load(handle)
    assert meta["project"]["dependencies"] == []
    named = {d.lower().replace("_", "-") for group in meta["project"].get("optional-dependencies", {}).values() for d in group}
    assert not any(n.startswith(("runtime-contracts", "agent-harness", "context-runtime")) for n in named)


def test_every_python_file_carries_the_family_licence_header():
    missing = [str(p.relative_to(ROOT)) for base in (ROOT / "packages", ROOT / "tests")
               for p in _py_files(base) if SPDX not in p.read_text(encoding="utf-8").splitlines()[0:3][0:3].__str__()]
    assert not missing, missing


def test_no_open_source_claims():
    bad = []
    for f in [*ROOT.glob("*.md"), *(ROOT / "packages").rglob("*.md")]:
        text = f.read_text(encoding="utf-8").lower().replace("\n", " ")
        i = text.find("open source")
        while i != -1:
            window = text[max(0, i - 12):i]
            if not any(neg in window for neg in ("not ", "never ", "no ")):
                bad.append(str(f.relative_to(ROOT)))
            i = text.find("open source", i + 1)
    assert not bad, f"'open source' used as a claim in {bad}"
