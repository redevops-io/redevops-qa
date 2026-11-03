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


def make_kit_wheel(directory: Path, paths_text: str | None = None, version: str = "1.0") -> Path:
    """A wheel named like the adapter kit's, holding qa_adapter_kit/paths.py: the real file by default (the installer reads the path policy from it), or the text given."""
    name = "redevops_qa_adapter_kit"
    text = paths_text if paths_text is not None else (ROOT / "packages" / "qa-adapter-kit" / "src" / "qa_adapter_kit" / "paths.py").read_text(encoding="utf-8")
    dist = f"{name}-{version}"
    files = {"qa_adapter_kit/__init__.py": b"", "qa_adapter_kit/paths.py": text.encode(),
             f"{dist}.dist-info/METADATA": f"Metadata-Version: 2.1\nName: {name.replace('_', '-')}\nVersion: {version}\n".encode(),
             f"{dist}.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
    for lic in ("LICENSE.md", "LICENSE", "LICENSE-COMMONS-CLAUSE"):
        files[f"{dist}.dist-info/licenses/{lic}"] = f"licence text {lic}\n".encode()
    files[f"{dist}.dist-info/RECORD"] = ("\n".join(bb.record_line(n, d) for n, d in sorted(files.items())) + f"\n{dist}.dist-info/RECORD,,\n").encode()
    out = directory / f"{dist}-py3-none-any.whl"
    bb.write_wheel(out, files, 1_700_000_000)
    return out


def make_third_party_wheel(directory: Path, name: str = "thirdlib", version: str = "2.0", licence_text: bytes = b"Permission is hereby granted, free of charge, to any person: the licence text of thirdlib\n") -> Path:
    """A synthetic third-party wheel that carries one licence file (what the real ones do), so the notices of a test bundle have a wheel to come from."""
    dist = f"{name}-{version}"
    files = {f"{name}/__init__.py": b"", f"{dist}.dist-info/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nLicense: MIT\n".encode(),
             f"{dist}.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n", f"{dist}.dist-info/licenses/LICENSE": licence_text}
    files[f"{dist}.dist-info/RECORD"] = ("\n".join(bb.record_line(n, d) for n, d in sorted(files.items())) + f"\n{dist}.dist-info/RECORD,,\n").encode()
    out = directory / f"{dist}-py3-none-any.whl"
    bb.write_wheel(out, files, 1_700_000_000)
    return out


def make_notices(out_dir: Path, wheel: Path) -> tuple:
    """(lock, root, notices): a notices lock for a tiny repository tree (one upstream text and the authored README) and the licence file of ``wheel``, and the tree bb.build_notices makes of it."""
    import json
    import zipfile
    root = out_dir / "repo"
    (root / "third_party" / "notices" / "upstream" / "x-1").mkdir(parents=True)
    up = root / "third_party" / "notices" / "upstream" / "x-1" / "LICENSE"
    up.write_bytes(b"upstream licence text of x 1\n")
    readme = root / "third_party" / "notices" / "README.md"
    readme.write_bytes(b"# THIRD_PARTY_NOTICES\n")
    name, version = bb.wheel_name_version(wheel.name)
    member = f"{name.replace('-', '_')}-{version}.dist-info/licenses/LICENSE"
    with zipfile.ZipFile(wheel) as zf:
        wheel_sha = bb.sha256_bytes(zf.read(member))
    lock = {"schema": "redevops-qa/third-party-notices-lock", "version": 1, "files": [
        {"id": "readme", "dest": "README.md", "sha256": bb.sha256_file(readme), "origin": {"kind": "authored", "path": "third_party/notices/README.md"}, "covers": []},
        {"id": "x-license", "dest": "upstream/x-1/LICENSE", "sha256": bb.sha256_file(up), "origin": {"kind": "upstream", "path": "third_party/notices/upstream/x-1/LICENSE", "url": "https://example.org/x/LICENSE", "retrieved_on": "2026-11-03"}, "covers": ["x"]},
        {"id": "thirdlib-license", "dest": f"wheels/{name}-{version}/{member}", "sha256": wheel_sha, "origin": {"kind": "wheel", "wheel": name, "version": version, "member": member}, "covers": []}]}
    (root / "third_party" / "notices" / "notices.lock.json").write_text(json.dumps(lock))
    return lock, root, bb.build_notices(lock, {f"{name}=={version}": wheel}, root)


def make_mini_bundle(out_dir: Path, version: str = "1.0", *, target: Dict[str, str] | None = None, label: str = "", name: str = "redevops-qa-bundle-test",
                     kit_paths_text: str | None = None, with_kit: bool = True, with_notices: bool = False) -> Path:
    """A bundle of one synthetic wheel, built by ``assemble``. Its target is this host unless given. With ``with_notices`` it also holds a synthetic third-party wheel, the notices built from it and
    the notices wheel (the shape of a real bundle)."""
    wheels = out_dir / f"wheels-{version}"
    wheels.mkdir(parents=True)
    entries = [bb.WheelEntry(make_wheel(wheels, version), "first-party", "test")]
    if with_kit:                    # the installer reads the path policy from the adapter-kit wheel and refuses a bundle without one
        entries.append(bb.WheelEntry(make_kit_wheel(wheels, kit_paths_text), "first-party", "test"))
    notices = None
    if with_notices:
        third = make_third_party_wheel(wheels)
        entries.append(bb.WheelEntry(third, "third-party", "MIT"))
        _lock, _root, notices = make_notices(out_dir / f"notices-{version}", third)
        entries.append(bb.WheelEntry(bb.build_notices_wheel(notices, version, 1_700_000_000, wheels), "notices", "test"))
    return bb.assemble(out_dir, name=name, entries=entries, target=target or host_target(), epoch=1_700_000_000, label=label, version=version, commit="0" * 40, pins_info=None,
                       licences_from={}, build_tools={}, readme_template=(ROOT / "bundle" / "README.md").read_text(encoding="utf-8"), notices=notices)


def clean_env(home: Path) -> Dict[str, str]:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def run_script(bundle: Path, script: str, args: Sequence[str], home: Path, *, python: str | None = sys.executable) -> subprocess.CompletedProcess:
    argv = ["bash", str(bundle / script), *args]
    if script == "install.sh" and python:
        argv += ["--python", python]
    return subprocess.run(argv, env=clean_env(home), cwd=str(home), capture_output=True, text=True, timeout=300)


def synthetic_wheel(bundle: Path) -> Path:
    """The synthetic wheel of a mini bundle (not the adapter-kit wheel, which sits in the same wheelhouse; the directory order of two files is not the same on every file system)."""
    return next((bundle / "wheelhouse").glob("redevops_qa_testpkg-*.whl"))


def resum(bundle: Path) -> None:
    """Rewrite SHA256SUMS for whatever the directory holds now (what someone who tampers with a bundle and wants the first check to pass would do)."""
    (bundle / "SHA256SUMS").write_text(bb.sha256sums_text(bundle), encoding="utf-8")


def restore_default_signals() -> None:
    """For ``preexec_fn``: put INT, TERM and HUP back to their default disposition in a child that is about to exec a script. A signal that the test process itself ignores (pytest started with
    nohup, or as a background job of a non-interactive shell) stays ignored across exec, and a shell script cannot trap a signal that was ignored when it started: a test that signals a script
    must not depend on how pytest was launched."""
    import signal
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, signal.SIG_DFL)


def tree_listing(root: Path) -> List[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))
