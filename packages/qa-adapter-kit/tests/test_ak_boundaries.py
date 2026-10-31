# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The kit stays product-local and framework-free: standard library only, no harness, contracts or framework import, no
Commons-Clause text copied in, and no download or network call of its own."""
import ast
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "qa_adapter_kit"
FILES = sorted(SRC.rglob("*.py"))
FORBIDDEN_ROOTS = {"agent_harness", "runtime_contracts", "redevops_qa_bridge", "qa_playwright", "selenium", "robot", "robotframework", "appium",
                   "playwright", "yaml", "requests", "urllib3", "httpx", "aiohttp", "docker", "paramiko", "boto3"}


def imported_roots(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_there_are_source_files():
    assert len(FILES) >= 10


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_only_the_standard_library_and_the_package_itself_are_imported(path):
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    extra = imported_roots(path) - stdlib - {"qa_adapter_kit"}
    assert extra == set(), f"{path.name} imports {sorted(extra)}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_framework_harness_or_contracts_module_is_imported(path):
    assert imported_roots(path) & FORBIDDEN_ROOTS == set()


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_module_opens_a_network_connection_or_shells_out_through_a_shell(path):
    text = path.read_text(encoding="utf-8")
    for word in ("urllib.request", "socket.create_connection", "shell=True", "os.system(", "os.popen(", "http.client"):
        assert word not in text, f"{path.name} uses {word}"


def test_the_package_declares_no_dependency():
    import tomllib
    data = tomllib.loads((SRC.parents[1] / "pyproject.toml").read_text())
    assert data["project"]["dependencies"] == []


def test_no_commons_clause_text_is_copied_into_the_kit():
    for path in FILES:
        text = path.read_text(encoding="utf-8")
        assert "Commons Clause License Condition" not in text and "Sell the Software" not in text


def test_every_source_file_carries_the_family_spdx_line():
    for path in FILES:
        if path.stat().st_size:
            assert path.read_text(encoding="utf-8").startswith("# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause"), path.name


def test_the_frozen_contract_surface_is_not_touched_by_this_package():
    # the kit lives under packages/qa-adapter-kit only; the repository's frozen inputs are pins.toml and the pinned trees
    root = SRC.parents[3]
    assert not (root / "packages" / "qa-adapter-kit" / "src" / "agent_harness").exists()
