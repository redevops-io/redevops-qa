# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Import boundaries of qa-playwright: the harness neutral module only through one file, the bridge only through its
documented path-preparation helper, Playwright only in the real driver and only by a lazy import."""
import ast
import tomllib
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
SRC = PKG / "src" / "qa_playwright"
SPDX = "SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause"
FORBIDDEN = {"runtime_contracts", "context_runtime", "redevops_qa", "askui", "browser_use"}


def files(base):
    return sorted(p for p in base.rglob("*.py") if "__pycache__" not in p.parts)


def tops(tree, module_level_only):
    nodes = tree.body if module_level_only else list(ast.walk(tree))
    found = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            found.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            found.add(node.module.split(".")[0])
    return found


def test_only_one_module_imports_the_harness_and_it_is_the_documented_choke_point():
    importers = {p.name for p in files(SRC) if "agent_harness" in tops(ast.parse(p.read_text()), False)}
    assert importers == {"_harness.py"}


def test_the_bridge_is_reached_only_from_the_choke_point_and_only_inside_a_function():
    for path in files(SRC):
        tree = ast.parse(path.read_text())
        has = "redevops_qa_bridge" in tops(tree, False)
        assert has == (path.name == "_harness.py"), path.name
        assert "redevops_qa_bridge" not in tops(tree, True), f"{path.name} imports the bridge at import time"


def test_no_module_imports_contracts_context_runtime_or_any_other_family_package():
    for path in files(SRC):
        assert not (FORBIDDEN & tops(ast.parse(path.read_text()), False)), path.name


def test_playwright_is_never_imported_at_module_level_and_only_the_real_driver_names_it():
    for path in files(SRC):
        text = path.read_text()
        tree = ast.parse(text)
        assert "playwright" not in tops(tree, False), f"{path.name} imports playwright statically"
    names = {p.name for p in files(SRC) if "importlib.import_module(\"playwright.sync_api\")" in p.read_text()}
    assert names == {"playwright_driver.py"}


def test_the_package_declares_no_runtime_dependency_and_playwright_only_as_an_optional_pinned_extra():
    meta = tomllib.loads((PKG / "pyproject.toml").read_text())
    assert meta["project"]["dependencies"] == []
    assert meta["project"]["optional-dependencies"]["browser"] == ["playwright==1.64.1"]
    assert meta["project"]["license"] == "LicenseRef-AGPL-3.0-or-later-with-Commons-Clause" and meta["project"]["license-files"] == ["LICENSE*"]      # an SPDX string; the wheel carries the texts


def test_every_source_and_test_file_has_the_spdx_header():
    for base in (SRC, PKG / "tests"):
        for path in files(base):
            assert path.read_text().splitlines()[0] == f"# {SPDX}", path


def test_no_credential_shaped_literal_is_written_in_the_package():
    import re
    shapes = [r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{36}", r"xox[abprse]-[A-Za-z0-9-]{10,}", r"sk-[A-Za-z0-9]{20,}",
              r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "RDQA" + "-CANARY-"]
    for path in files(PKG):
        text = path.read_text()
        for shape in shapes:
            assert re.search(shape, text) is None, f"{path.name}: {shape}"


def test_no_network_client_library_is_imported_by_the_adapter_package():
    for path in files(SRC):
        assert not ({"socket", "urllib", "http", "requests", "httpx", "aiohttp", "ssl"} & tops(ast.parse(path.read_text()), False)), path.name
