# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Import boundaries of qa-egress: standard library plus the harness neutral module through one file; no third-party code,
no contracts, no browser library; the harness policy is consumed, not copied."""
import ast
import sys
import tomllib
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
SRC = PKG / "src" / "qa_egress"
SPDX = "SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause"
STDLIB = set(sys.stdlib_module_names)


def files(base):
    return sorted(p for p in base.rglob("*.py") if "__pycache__" not in p.parts)


def tops(tree):
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            found.add(node.module.split(".")[0])
    return found


def test_the_sources_import_only_the_standard_library_the_package_itself_and_the_harness_through_one_file():
    for path in files(SRC):
        extra = tops(ast.parse(path.read_text())) - STDLIB - {"qa_egress"}
        allowed = {"agent_harness", "redevops_qa_bridge"} if path.name == "_harness.py" else set()
        assert extra <= allowed, (path.name, extra)
    assert {p.name for p in files(SRC) if "agent_harness" in tops(ast.parse(p.read_text()))} == {"_harness.py"}


def test_the_bridge_is_reached_only_from_the_choke_point_inside_a_function():
    for path in files(SRC):
        tree = ast.parse(path.read_text())
        assert ("redevops_qa_bridge" in tops(tree)) == (path.name == "_harness.py")
        assert not any(isinstance(n, (ast.Import, ast.ImportFrom)) and "redevops_qa_bridge" in ast.dump(n) for n in tree.body)


def test_no_module_imports_contracts_context_runtime_a_browser_library_or_a_network_client():
    banned = {"runtime_contracts", "context_runtime", "redevops_qa", "playwright", "requests", "httpx", "aiohttp", "urllib3", "ssl"}
    for path in files(SRC):
        assert not (banned & tops(ast.parse(path.read_text()))), path.name


def test_the_package_has_no_runtime_dependency_and_a_console_entry_point():
    meta = tomllib.loads((PKG / "pyproject.toml").read_text())
    assert meta["project"]["dependencies"] == [] and meta["project"]["scripts"] == {"redevops-qa-egress": "qa_egress.__main__:main"}


def test_the_only_name_resolution_in_the_package_is_the_system_resolver():
    for path in files(SRC):
        text = path.read_text()
        if path.name != "resolver.py":
            assert "getaddrinfo" not in text and "gethostbyname" not in text, path.name


def test_the_egress_policy_is_consumed_from_the_harness_not_copied():
    text = "\n".join(p.read_text() for p in files(SRC))
    for copied in ("169.254.169.254", "fd00:ec2", "metadata.google.internal", "100.100.100.200", "168.63.129.16"):
        assert copied not in text, f"{copied} is the harness policy's to know"


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
