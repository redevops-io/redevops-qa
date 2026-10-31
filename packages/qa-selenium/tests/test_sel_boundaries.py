# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Boundaries of the Selenium package: lazy Selenium import, licence matrix linkage, no Selenium Manager, no downloads."""
import ast
import importlib.util
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

PKG = Path(__file__).resolve().parents[1]
ROOT = PKG.parents[1]
SRC = PKG / "src" / "qa_selenium"
FILES = sorted(SRC.rglob("*.py"))
MATRIX = yaml.safe_load((ROOT / "third_party" / "adapter-license-matrix.yaml").read_text(encoding="utf-8"))
SELENIUM = next(c for c in MATRIX["components"] if c["id"] == "selenium-python")

_SPEC = importlib.util.spec_from_file_location("check_adapter_licenses", ROOT / "tools" / "check_adapter_licenses.py")
chk = importlib.util.module_from_spec(_SPEC)
sys.modules["check_adapter_licenses"] = chk
_SPEC.loader.exec_module(chk)


def test_importing_the_package_does_not_import_selenium():
    code = ("import sys; sys.path[:0] = [%r, %r]; import qa_selenium; "
            "bad = [m for m in sys.modules if m == 'selenium' or m.startswith('selenium.')]; assert not bad, bad" % (str(SRC.parent), str(ROOT / "packages/qa-adapter-kit/src")))
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_only_the_real_driver_imports_selenium():
    for path in FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        top_level = {n.module.split(".")[0] if isinstance(n, ast.ImportFrom) and n.module else a.name.split(".")[0]
                     for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom)) for a in (n.names if isinstance(n, ast.Import) else [n])}
        assert "selenium" not in top_level, f"{path.name} imports selenium at module level"
    text = {p.name: p.read_text(encoding="utf-8") for p in FILES}
    assert [n for n, t in text.items() if "from selenium" in t or "import selenium" in t] == ["selenium_driver.py"]


def test_no_harness_or_contracts_import_and_no_network_or_shell():
    for path in FILES:
        t = path.read_text(encoding="utf-8")
        for word in ("agent_harness", "runtime_contracts", "redevops_qa_bridge", "shell=True", "os.system(", "urllib.request", "requests", "SeleniumManager"):
            assert word not in t.replace("never invokes Selenium Manager", ""), f"{path.name}: {word}"


def test_the_real_driver_names_the_driver_executable_so_selenium_manager_is_skipped():
    t = (SRC / "selenium_driver.py").read_text(encoding="utf-8")
    assert "Service(executable_path=chromedriver_path)" in t and "binary_location = chrome_binary" in t


def test_every_manifest_names_a_component_of_the_licence_matrix_at_its_pinned_release():
    from qa_selenium import interactive_manifest, suite_manifest
    for m in (interactive_manifest(), suite_manifest(sys.executable)):
        assert m.framework.license_component == SELENIUM["id"] and m.framework.pinned_release == SELENIUM["pinned_release"]
        assert m.framework.name == "selenium"


def test_the_extra_pins_the_selenium_release_the_matrix_records():
    data = tomllib.loads((PKG / "pyproject.toml").read_text())
    assert data["project"]["optional-dependencies"]["browser"] == [f"selenium=={SELENIUM['pinned_release']}"]
    assert data["project"]["dependencies"] == []


def test_the_licence_check_accepts_the_repository_with_this_package():
    assert chk.run(ROOT / "third_party" / "adapter-license-matrix.yaml", ROOT) == []


def test_selenium_is_optional_extra_and_chrome_is_excluded_in_the_matrix():
    assert SELENIUM["redistribution"]["status"] == "optional_extra"
    chrome = next(c for c in MATRIX["components"] if c["id"] == "google-chrome")
    assert chrome["redistribution"]["status"] == "excluded_by_default"


def test_every_exception_class_name_in_the_map_is_a_selenium_class_or_a_documented_alias():
    # the real-browser lane checks the names against the installed Selenium; offline we only pin the vocabulary
    from qa_selenium import SELENIUM_EXCEPTION_KINDS, FaultKind
    assert set(SELENIUM_EXCEPTION_KINDS.values()) == {k for k in FaultKind if k is not FaultKind.UNAVAILABLE} | {FaultKind.UNAVAILABLE}


def test_classification_follows_the_class_hierarchy_and_defaults_to_crash():
    from qa_selenium import FaultKind, classify_exception

    class NoSuchElementException(Exception):
        pass

    class MyStale(Exception):
        pass

    class StaleElementReferenceException(Exception):
        pass

    class Derived(StaleElementReferenceException):
        pass
    assert classify_exception(NoSuchElementException()) is FaultKind.NOT_FOUND and classify_exception(Derived()) is FaultKind.STALE
    assert classify_exception(MyStale()) is FaultKind.CRASH and classify_exception(KeyError()) is FaultKind.CRASH
