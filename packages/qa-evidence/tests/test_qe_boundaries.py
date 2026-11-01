# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The package stays stdlib-only and offline: no third-party import, no network, no shell, no clock, SPDX lines, no copied licence text."""
import ast
import sys
import tomllib
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
SRC = PKG / "src" / "qa_evidence"
FILES = sorted(SRC.rglob("*.py"))
FORBIDDEN_ROOTS = {"agent_harness", "runtime_contracts", "redevops_qa_bridge", "qa_playwright", "qa_adapter_kit", "redevops_qa_checks", "selenium", "robot",
                   "playwright", "yaml", "requests", "urllib3", "httpx", "aiohttp", "jsonschema", "docker", "boto3"}


def imported_roots(path):
    roots = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_there_are_source_files():
    assert len(FILES) >= 12


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_only_the_standard_library_and_the_package_itself_are_imported(path):
    extra = imported_roots(path) - set(sys.stdlib_module_names) - {"__future__", "qa_evidence"}
    assert extra == set(), f"{path.name} imports {sorted(extra)}"
    assert imported_roots(path) & FORBIDDEN_ROOTS == set()


NETWORK_OR_PROCESS = {"socket", "ssl", "subprocess", "http", "urllib", "ftplib", "smtplib", "telnetlib", "webbrowser", "asyncio", "multiprocessing",
                      "xmlrpc", "socketserver", "ctypes"}


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_module_touches_the_network_a_shell_or_a_subprocess(path):
    assert imported_roots(path) & NETWORK_OR_PROCESS == set()
    text = path.read_text(encoding="utf-8")
    for word in ("shell=True", "os.system(", "os.popen(", "os.exec", "os.spawn", "os.fork", "eval(", "exec(", "__import__", "pickle", "marshal"):
        assert word not in text, f"{path.name} uses {word}"


def test_the_package_declares_no_dependency_and_its_licence():
    data = tomllib.loads((PKG / "pyproject.toml").read_text())
    assert data["project"]["dependencies"] == []
    assert data["project"]["license"]["text"] == "LicenseRef-AGPL-3.0-or-later-with-Commons-Clause"
    assert data["project"]["requires-python"] == ">=3.11"
    assert data["project"]["scripts"] == {"redevops-qa-evidence": "qa_evidence.cli:main"}
    assert data["tool"]["setuptools"]["package-data"] == {"qa_evidence": ["schemas/*.json"]}


def test_every_source_and_test_file_carries_the_family_spdx_line():
    for path in [*FILES, *sorted((PKG / "tests").glob("*.py"))]:
        if path.stat().st_size:
            assert path.read_text(encoding="utf-8").startswith("# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause"), path.name


def test_no_licence_condition_text_is_copied_into_the_package():
    for path in [*FILES, PKG / "README.md"]:
        text = path.read_text(encoding="utf-8")
        assert "Commons Clause License Condition" not in text and "Sell the Software" not in text


def test_the_readme_uses_the_source_available_wording_and_never_calls_the_licence_open_source():
    text = (PKG / "README.md").read_text(encoding="utf-8")
    assert "source-available" in text
    assert "open source" not in text.lower().replace("not open source", "").replace("not \"open source\"", "")


def test_the_package_does_not_touch_the_verifier_the_playwright_adapter_or_a_fixture_app():
    root = PKG.parents[1]
    assert not (PKG / "src" / "agent_harness").exists()
    for name in ("qa-playwright", "qa-fixture-app", "qa-runner"):
        for path in (PKG / "src").rglob("*.py"):
            assert name.replace("-", "_") not in path.read_text(encoding="utf-8"), (name, path.name)
    assert (root / "packages" / "qa-evidence").is_dir()
