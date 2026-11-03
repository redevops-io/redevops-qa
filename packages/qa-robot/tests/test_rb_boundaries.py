# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Boundaries of the Robot package: Robot Framework is never imported by the adapter, nothing is installed, licence matrix linkage."""
import ast
import importlib.util
import subprocess
import sys
import tomllib
from pathlib import Path

import yaml

PKG = Path(__file__).resolve().parents[1]
ROOT = PKG.parents[1]
SRC = PKG / "src" / "qa_robot"
FILES = sorted(SRC.rglob("*.py"))
MATRIX = yaml.safe_load((ROOT / "third_party" / "adapter-license-matrix.yaml").read_text(encoding="utf-8"))
ROBOT = next(c for c in MATRIX["components"] if c["id"] == "robotframework")
_SPEC = importlib.util.spec_from_file_location("check_adapter_licenses", ROOT / "tools" / "check_adapter_licenses.py")
chk = importlib.util.module_from_spec(_SPEC)
sys.modules["check_adapter_licenses"] = chk
_SPEC.loader.exec_module(chk)


def roots(path):
    out = set()
    for n in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(n, ast.Import):
            out |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
            out.add(n.module.split(".")[0])
    return out


def test_the_adapter_never_imports_robot_framework_or_any_third_party_package():
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    for path in FILES:
        extra = roots(path) - stdlib - {"qa_adapter_kit", "qa_robot"}
        assert extra == set(), f"{path.name} imports {sorted(extra)}"


def test_importing_the_package_does_not_import_robot_even_when_it_is_installed():
    code = ("import sys; sys.path[:0] = [%r, %r]; import qa_robot; bad = [m for m in sys.modules if m == 'robot' or m.startswith('robot.')]; assert not bad, bad"
            % (str(SRC.parent), str(ROOT / "packages/qa-adapter-kit/src")))
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_no_code_path_installs_a_package_or_uses_a_shell_or_the_network():
    for path in FILES:
        t = path.read_text(encoding="utf-8")
        for word in ("pip install", "ensurepip", "subprocess", "os.system(", "shell=True", "urllib.request", "socket", "requests"):
            assert word not in t, f"{path.name}: {word}"


def test_the_command_is_built_only_from_the_manifests_python_and_the_robot_module():
    t = (SRC / "suite.py").read_text(encoding="utf-8")
    assert '_DEFAULT_LAUNCHER = ("-m", "robot")' in t and '"-I"' in t


def test_the_manifest_names_the_matrix_component_at_its_pinned_release():
    from qa_robot import suite_manifest
    m = suite_manifest(sys.executable)
    assert m.framework.license_component == ROBOT["id"] and m.framework.pinned_release == ROBOT["pinned_release"] and m.framework.name == "robotframework"


def test_the_extra_pins_the_robot_release_the_matrix_records_and_nothing_else_is_depended_on():
    data = tomllib.loads((PKG / "pyproject.toml").read_text())
    assert data["project"]["optional-dependencies"]["robot"] == [f"robotframework=={ROBOT['pinned_release']}"] and data["project"]["dependencies"] == []


def test_the_licence_check_accepts_the_repository_with_this_package():
    assert chk.run(ROOT / "third_party" / "adapter-license-matrix.yaml", ROOT) == []


def test_the_matrix_records_robot_as_shipped_unmodified_for_private_staging_only_with_unverified_bundled_assets():
    assert ROBOT["redistribution"]["status"] == "staged_unmodified" and ROBOT["redistribution"]["public_distribution"] == "owner_decision_required"
    assert "PRIVATE STAGING ONLY" in ROBOT["redistribution"]["reason"]
    unverified = [d for d in ROBOT["bundled_deps"] if d["spdx"] == "unverified"]
    assert len(unverified) == 2 and all("robot/htmldata/lib/" in d["name"] for d in unverified)


def test_the_default_allowlist_matches_the_documented_one():
    from qa_robot import DEFAULT_ALLOWED_LIBRARIES, STANDARD_LIBRARIES
    assert DEFAULT_ALLOWED_LIBRARIES < STANDARD_LIBRARIES
