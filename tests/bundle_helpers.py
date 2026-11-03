# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Helpers of the bundle tests: the two tools loaded as modules, a target that is this host, and a small bundle of synthetic wheels that goes through the real
builder functions, the real scripts and the real pip, so the install, uninstall, rollback and refusal paths are tested without the network and without Playwright."""
from __future__ import annotations

import importlib.util
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Sequence

ROOT = Path(__file__).resolve().parents[1]


def load_tool(name: str):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


bb = load_tool("build_bundle")
cb = load_tool("check_bundle")


def host_target(python: str = "") -> Dict[str, str]:
    """The target install.sh computes for this host (the same normalisation), so a test bundle is for the machine the test runs on."""
    major, minor = sys.version_info[:2]
    machine = platform.machine().lower().replace("amd64", "x86_64").replace("aarch64", "arm64")
    return {"python": python or f"{major}.{minor}", "python_tag": f"cp{major}{minor}", "platform": sys.platform.replace("darwin", "macos") + "-" + machine}


def make_wheel(directory: Path, version: str, *, name: str = "redevops_qa_testpkg", marker: str = "ok", licences: bool = True) -> Path:
    dist = f"{name}-{version}"
    files = {
        f"{name}/__init__.py": (f"import os, sys\n\ndef main():\n    print('testpkg {version} {marker}', os.environ.get('PLAYWRIGHT_BROWSERS_PATH', 'unset'))\n    return 0\n").encode(),
        f"{dist}.dist-info/METADATA": f"Metadata-Version: 2.1\nName: {name.replace('_', '-')}\nVersion: {version}\n".encode(),
        f"{dist}.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{dist}.dist-info/entry_points.txt": f"[console_scripts]\nredevops-qa = {name}:main\n".encode(),
        f"{dist}.dist-info/top_level.txt": f"{name}\n".encode(),
    }
    if licences:
        for lic in ("LICENSE.md", "LICENSE", "LICENSE-COMMONS-CLAUSE"):
            files[f"{dist}.dist-info/licenses/{lic}"] = f"licence text {lic}\n".encode()
    files[f"{dist}.dist-info/RECORD"] = ("\n".join(bb.record_line(n, d) for n, d in sorted(files.items())) + f"\n{dist}.dist-info/RECORD,,\n").encode()
    out = directory / f"{dist}-py3-none-any.whl"
    bb.write_wheel(out, files, 1_700_000_000)
    return out


def make_mini_bundle(out_dir: Path, version: str = "1.0", *, target: Dict[str, str] | None = None, label: str = "", name: str = "redevops-qa-bundle-test") -> Path:
    """A bundle of one synthetic wheel, built by ``assemble``. Its target is this host unless given."""
    wheels = out_dir / f"wheels-{version}"
    wheels.mkdir(parents=True)
    entry = bb.WheelEntry(make_wheel(wheels, version), "first-party", "test")
    return bb.assemble(out_dir, name=name, entries=[entry], target=target or host_target(), epoch=1_700_000_000, label=label, version=version, commit="0" * 40, pins_info=None,
                       licences_from={}, build_tools={}, readme_template=(ROOT / "bundle" / "README.md").read_text(encoding="utf-8"))


def clean_env(home: Path) -> Dict[str, str]:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def run_script(bundle: Path, script: str, args: Sequence[str], home: Path, *, python: str | None = sys.executable) -> subprocess.CompletedProcess:
    argv = ["bash", str(bundle / script), *args]
    if script == "install.sh" and python:
        argv += ["--python", python]
    return subprocess.run(argv, env=clean_env(home), cwd=str(home), capture_output=True, text=True, timeout=300)


def resum(bundle: Path) -> None:
    """Rewrite SHA256SUMS for whatever the directory holds now (what someone who tampers with a bundle and wants the first check to pass would do)."""
    (bundle / "SHA256SUMS").write_text(bb.sha256sums_text(bundle), encoding="utf-8")


def tree_listing(root: Path) -> List[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))
