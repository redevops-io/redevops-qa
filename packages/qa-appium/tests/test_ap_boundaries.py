# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Boundaries of the Appium package: lazy client import, no Apple or Google tooling, matrix linkage, nothing installed."""
import ast
import importlib.util
import subprocess
import sys
import tomllib
from pathlib import Path

import yaml

PKG = Path(__file__).resolve().parents[1]
ROOT = PKG.parents[1]
SRC = PKG / "src" / "qa_appium"
FILES = sorted(SRC.rglob("*.py"))
MATRIX = yaml.safe_load((ROOT / "third_party" / "adapter-license-matrix.yaml").read_text(encoding="utf-8"))
BY_ID = {c["id"]: c for c in MATRIX["components"]}
_SPEC = importlib.util.spec_from_file_location("check_adapter_licenses", ROOT / "tools" / "check_adapter_licenses.py")
chk = importlib.util.module_from_spec(_SPEC)
sys.modules["check_adapter_licenses"] = chk
_SPEC.loader.exec_module(chk)


def toplevel_imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = set()
    for n in tree.body:
        if isinstance(n, ast.Import):
            out |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
            out.add(n.module.split(".")[0])
    return out


def test_no_module_imports_the_appium_client_or_selenium_at_module_level():
    for path in FILES:
        assert not toplevel_imports(path) & {"appium", "selenium"}, path.name


def test_importing_the_package_imports_neither_appium_nor_selenium_even_when_installed():
    code = ("import sys; sys.path[:0] = [%r, %r, %r]; import qa_appium; bad = [m for m in sys.modules if m.split('.')[0] in ('appium', 'selenium')]; assert not bad, bad"
            % (str(SRC.parent), str(ROOT / "packages/qa-adapter-kit/src"), str(ROOT / "packages/qa-selenium/src")))
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_nothing_in_the_package_installs_downloads_or_shells_out():
    for path in FILES:
        t = path.read_text(encoding="utf-8")
        for word in ("pip install", "npm ", "npx", "subprocess", "os.system(", "shell=True", "urllib.request", "mobile: shell", "adb ", "sdkmanager", "avdmanager",
                     "xcrun", "xcodebuild", "simctl", "xcuitest", "XCUITest"):
            assert word not in t.replace("XCUITest driver needs", "").replace("Appium's XCUITest driver needs", ""), f"{path.name}: {word}"


def test_the_ios_module_does_not_import_or_start_anything_apple():
    t = (SRC / "ios.py").read_text(encoding="utf-8")
    assert "import" in t and not (toplevel_imports(SRC / "ios.py") & {"appium", "subprocess", "selenium"})


def test_the_manifests_name_the_appium_matrix_component_at_its_pinned_release():
    from qa_appium import interactive_manifest
    m = interactive_manifest("appium-android-interactive")
    assert m.framework.license_component == "appium-server" and m.framework.pinned_release == BY_ID["appium-server"]["pinned_release"]


def test_the_extra_pins_the_client_release_the_matrix_records_and_nothing_else_is_depended_on():
    data = tomllib.loads((PKG / "pyproject.toml").read_text())
    assert data["project"]["optional-dependencies"]["android"] == [f"Appium-Python-Client=={BY_ID['appium-python-client']['pinned_release']}"]
    assert data["project"]["dependencies"] == []


def test_the_licence_check_accepts_the_repository_with_this_package():
    assert chk.run(ROOT / "third_party" / "adapter-license-matrix.yaml", ROOT) == []


def test_the_commercial_toolchains_stay_excluded_and_the_xcuitest_driver_requires_the_apple_one():
    for cid in ("android-sdk-and-emulator", "apple-toolchain"):
        assert BY_ID[cid]["redistribution"]["status"] == "excluded_by_default" and BY_ID[cid]["redistribution"]["default_enabled"] is False
    assert "apple-toolchain" in BY_ID["appium-xcuitest-driver"]["requires"] and BY_ID["appium-xcuitest-driver"]["redistribution"]["status"] == "excluded_by_default"


def test_the_pinned_client_and_server_versions_match_the_driver_constants():
    from qa_appium.android import APPIUM_CLIENT_RELEASE
    from qa_appium import APPIUM_RELEASE
    assert APPIUM_CLIENT_RELEASE == BY_ID["appium-python-client"]["pinned_release"] and APPIUM_RELEASE == BY_ID["appium-server"]["pinned_release"]
