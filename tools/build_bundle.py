#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Build the redevops-qa pinned bundle: a wheelhouse, a hash-locked requirements file, checksums and the install scripts, as one archive.

    python tools/build_bundle.py build --out DIR [--label TEXT] [--pinned-root DIR] [--download-cache DIR]
    python tools/build_bundle.py lock-third-party [--out FILE]

What the bundle is (see ``bundle/README.md``, which is shipped inside it): the repository's own packages built as wheels, one wheel that carries the pinned
upstream source trees (runtime-contracts and agent-harness at the commits ``pins.toml`` names, with the vector files the pin check reads), and the third-party
wheels of ``bundle/third-party.lock.json`` for ONE Python minor and ONE platform (CPython 3.12, Linux x86_64). ``requirements.lock`` names every wheel with its
sha256; ``install.sh`` installs with ``pip install --no-index --find-links wheelhouse --require-hashes -r requirements.lock``. Chromium is not in the bundle: it is
downloaded when the browser step runs, and it is recorded in ``BUNDLE.json``, not hashed by this builder.

What this builder does not do: it publishes nothing, creates no tag or release and needs no credential. Network use: ``pip download`` of the pinned, hashed
third-party wheels and of the pinned build tool from the package index, nothing else. The pinned upstream trees are not fetched here: pass the directory the CI jobs
fetch them into (``--pinned-root``, default ``.pinned``); they are verified against ``pins.toml`` (commit when a checkout, tree digest, vector files) before use.

Reproducibility: every file this builder writes is deterministic (entries sorted, fixed timestamps taken from the source commit, wheels stored without compression,
a plain tar with fixed owners and modes). Whether two builds are byte-identical on the machines that matter is a fact to measure, not to assume: build twice and
compare ``SHA256SUMS`` (the ``bundle`` CI job does, and prints the result).
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_SRC = ROOT / "bundle"
SCHEMA = "redevops-qa/bundle"
SCHEMA_VERSION = "1.0"
LOCK_SCHEMA = "redevops-qa/bundle-third-party-lock"

#: the repository packages that are part of the bundle (Selenium and Appium are outside the release claim and are not shipped)
FIRST_PARTY = ("qa-adapter-kit", "qa-bridge", "qa-checks", "qa-egress", "qa-evidence", "qa-fixture-app", "qa-playwright", "qa-robot", "qa-runner")
PINNED_DIST = "redevops-qa-pinned-upstreams"
#: the one target a bundle is built for. A test bundle may name another target; the release bundle never does.
TARGET = {"python": "3.12", "python_tag": "cp312", "platform": "linux-x86_64"}
PIP_PLATFORMS = ("manylinux_2_28_x86_64", "manylinux_2_27_x86_64", "manylinux_2_26_x86_64", "manylinux_2_24_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64",
                 "manylinux_2_12_x86_64", "manylinux2010_x86_64", "manylinux_2_5_x86_64", "manylinux1_x86_64", "linux_x86_64")
SCRIPTS = ("install.sh", "install-browser.sh", "uninstall.sh")
SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache"}          # the same walk as redevops_qa_bridge.pins.tree_digest
SKIP_SUFFIXES = {".pyc", ".pyo"}
LICENCE_FILES = {"redevops-qa": ("LICENSE.md", "LICENSE", "LICENSE-COMMONS-CLAUSE"), "runtime-contracts": ("LICENSE.md", "LICENSE", "LICENSE-COMMONS-CLAUSE"),
                 "agent-harness": ("LICENSE",)}
FETCH_ENV_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "PIP_CERT")


class BuildError(Exception):
    pass


# ------------------------------------------------------------------------------------------------------------------------------ small helpers
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def wheel_name_version(filename: str) -> Tuple[str, str]:
    """(normalised distribution name, version) from a wheel file name."""
    m = re.fullmatch(r"([A-Za-z0-9_.]+)-([A-Za-z0-9_.!+]+)-([A-Za-z0-9_.]+)-([A-Za-z0-9_.]+)-([A-Za-z0-9_.]+)\.whl", filename)
    if not m:
        raise BuildError(f"not a wheel file name: {filename!r}")
    return canonical_name(m.group(1)), m.group(2)


def runner_version(root: Path = ROOT) -> str:
    text = (root / "packages" / "qa-runner" / "src" / "qa_runner" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if not m:
        raise BuildError("cannot read __version__ of qa_runner")
    return m.group(1)


def git(root: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise BuildError(f"git {' '.join(args)} failed: {done.stderr.strip()[:200]}")
    return done.stdout.strip()


def source_state(root: Path = ROOT) -> Tuple[str, int]:
    """(commit, commit time). The tree must be clean: a bundle names the commit it was built from and nothing else."""
    if git(root, "status", "--porcelain"):
        raise BuildError("the working tree is not clean: a bundle is built from a commit, with nothing uncommitted or untracked (ignored files such as .pinned are fine)")
    return git(root, "rev-parse", "HEAD"), int(git(root, "log", "-1", "--format=%ct"))


def child_env(home: Path, epoch: int, *, network: bool = False) -> Dict[str, str]:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(home), "LC_ALL": "C", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1", "SOURCE_DATE_EPOCH": str(epoch),
           "PIP_CONFIG_FILE": os.devnull, "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1", "PIP_NO_CACHE_DIR": "1"}
    if network:
        env.update({k: os.environ[k] for k in FETCH_ENV_KEYS if k in os.environ})
    return env


def run(argv: Sequence[str], env: Dict[str, str], cwd: Optional[Path] = None, what: str = "") -> str:
    done = subprocess.run(list(argv), env=env, cwd=str(cwd) if cwd else None, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        tail = (done.stderr or done.stdout).strip().splitlines()[-12:]
        raise BuildError(f"{what or argv[0]} failed (exit {done.returncode}):\n" + "\n".join(tail))
    return done.stdout


# --------------------------------------------------------------------------------------------------------- deterministic archives
def _zip_info(name: str, epoch: int, mode: int = 0o644) -> zipfile.ZipInfo:
    t = time.gmtime(max(epoch, 315532800))              # a zip cannot hold a date before 1980
    zi = zipfile.ZipInfo(name, (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec - t.tm_sec % 2))
    zi.compress_type = zipfile.ZIP_STORED
    zi.create_system = 3
    zi.external_attr = (0o100000 | mode) << 16
    return zi


def write_wheel(dst: Path, files: Dict[str, bytes], epoch: int) -> None:
    """Write ``files`` as a wheel: sorted, RECORD last, stored, fixed timestamps. The RECORD of the input (if any) is kept as it is."""
    names = sorted(files, key=lambda n: (n.endswith(".dist-info/RECORD"), n))
    with zipfile.ZipFile(dst, "w") as zf:
        for name in names:
            zf.writestr(_zip_info(name, epoch), files[name])


def normalise_wheel(src: Path, dst: Path, epoch: int) -> None:
    """Repack a wheel with the entries of the original byte for byte, but in a fixed order, uncompressed, with one timestamp and no directory entries."""
    files: Dict[str, bytes] = {}
    with zipfile.ZipFile(src) as zf:
        for info in zf.infolist():
            if info.filename.endswith("/"):
                continue
            if info.filename in files:
                raise BuildError(f"{src.name}: duplicate entry {info.filename}")
            files[info.filename] = zf.read(info.filename)
    write_wheel(dst, files, epoch)


def record_line(path: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    return f"{path},sha256={digest},{len(data)}"


def write_tar(src_dir: Path, dst: Path, epoch: int, executable: Iterable[str] = SCRIPTS) -> None:
    """A plain (uncompressed) tar of ``src_dir`` under its own name: sorted, owner 0, fixed time, modes 0644/0755. No compression, so no dependence on a zlib version."""
    exe = set(executable)
    top = src_dir.name
    entries: List[Tuple[str, Optional[Path]]] = [(top, None)]
    for p in sorted(src_dir.rglob("*"), key=lambda q: q.relative_to(src_dir).as_posix()):
        entries.append((f"{top}/{p.relative_to(src_dir).as_posix()}", p))
    with tarfile.open(dst, "w", format=tarfile.GNU_FORMAT) as tf:
        for arcname, path in entries:
            if path is None or path.is_dir():
                ti = tarfile.TarInfo(arcname + "/")
                ti.type, ti.mode, ti.size = tarfile.DIRTYPE, 0o755, 0
                data = None
            else:
                data = path.read_bytes()
                ti = tarfile.TarInfo(arcname)
                ti.size = len(data)
                ti.mode = 0o755 if path.name in exe and path.parent == src_dir else 0o644
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            ti.mtime = epoch
            tf.addfile(ti, io.BytesIO(data) if data is not None else None)


def sha256sums_text(directory: Path, exclude: Sequence[str] = ("SHA256SUMS",)) -> str:
    lines = []
    for p in sorted((q for q in directory.rglob("*") if q.is_file()), key=lambda q: q.relative_to(directory).as_posix()):
        rel = p.relative_to(directory).as_posix()
        if rel not in exclude:
            lines.append(f"{sha256_file(p)}  {rel}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------------------------------------------------- pinned upstreams
def load_pins(pins_file: Path):
    sys.path.insert(0, str(ROOT / "packages" / "qa-bridge" / "src"))
    try:
        from redevops_qa_bridge import deps, pins as pinmod         # noqa: PLC0415
    finally:
        sys.path.pop(0)
    for var in ("QA_PIN_CONTRACTS_PATH", "QA_PIN_HARNESS_QA_PATH", "REDEVOPS_QA_PIN_SET", "REDEVOPS_QA_PINS"):
        os.environ.pop(var, None)                    # the bundle is built for the file's default set, from the trees named here
    return pinmod.load_pins(pins_file), deps, pinmod


def pinned_trees(pins, deps, pinned_root: Path, pins_file: Path):
    """Both pinned trees under ``pinned_root`` (the directory a checkout of the repository calls ``.pinned``), verified against pins.toml. Returns {name: (dep, tree)}."""
    out = {}
    problems: List[str] = []
    for dep in (pins.contracts, pins.harness_qa):
        rel = PurePosixPath(dep.source_path)
        if not rel.parts or rel.parts[0] != ".pinned":
            raise BuildError(f"{dep.name}: source_path {dep.source_path!r} is not under .pinned")
        tree = pinned_root.joinpath(*rel.parts[1:])
        replaced = dataclasses.replace(dep, resolved_path=tree)
        problems += [f"{code}: {msg}" for code, msg in deps.pin_problems(replaced)]
        out[dep.name] = (replaced, tree)
    if problems:
        raise BuildError("the pinned upstream trees are not the pinned ones:\n  " + "\n  ".join(problems))
    return out


def tree_files(tree: Path, dirs: Sequence[str]) -> List[str]:
    found: List[str] = []
    for rel in dirs:
        base = tree / rel
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                p = Path(dirpath) / name
                if p.suffix not in SKIP_SUFFIXES:
                    found.append(p.relative_to(tree).as_posix())
    return found


def build_pinned_wheel(pins_file: Path, trees: Dict[str, tuple], deps, version: str, epoch: int, dst_dir: Path) -> Path:
    """One wheel that installs ``<prefix>/share/redevops-qa/pins.toml`` and the pinned trees below ``.pinned`` next to it, laid out as ``pins.toml`` expects:
    the distribution directories, the vector files, ``pyproject.toml`` (the version the tree declares) and the licence files. Not an installable ``agent-harness``
    or ``runtime-contracts`` distribution: no import path is added to the environment, ``redevops-qa`` puts the trees on ``sys.path`` itself, as it does in a checkout."""
    dist = PINNED_DIST.replace("-", "_")
    info = f"{dist}-{version}.dist-info"
    data_root = f"{dist}-{version}.data/data/share/redevops-qa"
    files: Dict[str, bytes] = {f"{data_root}/pins.toml": pins_file.read_bytes()}
    for name, (dep, tree) in sorted(trees.items()):
        rels = set(tree_files(tree, dep.distribution_paths)) | set(dep.vector_files) | set(deps.addendum_files(dep)) | {"pyproject.toml"}
        repo = dep.repo.rsplit("/", 1)[-1]
        rels |= {f for f in LICENCE_FILES.get(repo, ()) if (tree / f).is_file()}
        for rel in sorted(rels):
            files[f"{data_root}/{dep.source_path}/{rel}"] = (tree / rel).read_bytes()
    metadata = (f"Metadata-Version: 2.1\nName: {PINNED_DIST}\nVersion: {version}\nSummary: The pinned upstream source trees (runtime-contracts, agent-harness) that redevops-qa verifies "
                "against pins.toml, laid out under share/redevops-qa\nLicense: Two licences, not one: runtime-contracts is AGPL-3.0-or-later with the Commons Clause; agent-harness is "
                "AGPL-3.0-or-later. Their licence files are inside this wheel next to the trees.\nRequires-Python: >=3.11\n").encode()
    files[f"{info}/METADATA"] = metadata
    files[f"{info}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: redevops-qa tools/build_bundle.py\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    files[f"{info}/top_level.txt"] = b"\n"
    record = "\n".join(record_line(n, d) for n, d in sorted(files.items())) + f"\n{info}/RECORD,,\n"
    files[f"{info}/RECORD"] = record.encode()
    out = dst_dir / f"{dist}-{version}-py3-none-any.whl"
    write_wheel(out, files, epoch)
    return out


# ------------------------------------------------------------------------------------------------------------------------- own packages
def make_build_venv(work: Path, epoch: int, cache: Path) -> Path:
    """A venv holding the pinned build tool (``bundle/build-requirements.lock``, hash-checked)."""
    venv = work / "build-venv"
    run([sys.executable, "-m", "venv", str(venv)], child_env(work / "home", epoch), what="venv")
    dl = cache / "build-tools"
    dl.mkdir(parents=True, exist_ok=True)
    lock = BUNDLE_SRC / "build-requirements.lock"
    run([sys.executable, "-m", "pip", "download", "--no-deps", "--only-binary=:all:", "--require-hashes", "-r", str(lock), "--dest", str(dl)],
        child_env(work / "home", epoch, network=True), what="download of the pinned build tool")
    py = venv / "bin" / "python"
    run([str(py), "-m", "pip", "install", "--no-index", "--find-links", str(dl), "--require-hashes", "-r", str(lock)], child_env(work / "home", epoch), what="install of the pinned build tool")
    return py


def build_first_party(root: Path, packages: Sequence[str], epoch: int, work: Path, py: Path, dst_dir: Path) -> List[Path]:
    built: List[Path] = []
    raw = work / "raw-wheels"
    raw.mkdir()
    for pkg in packages:
        src = work / "src" / pkg
        shutil.copytree(root / "packages" / pkg, src, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "build", "dist", "*.egg-info", "tests", ".pytest_cache"))
        for p in [src, *src.rglob("*")]:
            os.utime(p, (epoch, epoch), follow_symlinks=False)
        run([str(py), "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--wheel-dir", str(raw), str(src)], child_env(work / "home", epoch), cwd=work, what=f"wheel of {pkg}")
    for whl in sorted(raw.glob("*.whl")):
        out = dst_dir / whl.name
        normalise_wheel(whl, out, epoch)
        built.append(out)
    if len(built) != len(packages):
        raise BuildError(f"expected {len(packages)} wheels of our own packages, built {len(built)}")
    return built


# ----------------------------------------------------------------------------------------------------------------------- third party
def read_third_party_lock(path: Path = BUNDLE_SRC / "third-party.lock.json") -> dict:
    lock = json.loads(path.read_text(encoding="utf-8"))
    if lock.get("schema") != LOCK_SCHEMA:
        raise BuildError(f"{path.name}: schema must be {LOCK_SCHEMA}")
    for w in lock["wheels"]:
        if not re.fullmatch(r"[0-9a-f]{64}", w["sha256"]):
            raise BuildError(f"{path.name}: {w['filename']}: sha256 is not 64 lowercase hex digits")
        if wheel_name_version(w["filename"]) != (canonical_name(w["name"]), w["version"]):
            raise BuildError(f"{path.name}: {w['filename']} does not match its name and version")
    return lock


def pip_platform_args(target: dict) -> List[str]:
    if target["platform"] != "linux-x86_64":
        raise BuildError("this builder fetches third-party wheels for linux-x86_64 only")
    args = ["--python-version", target["python"], "--implementation", "cp", "--abi", target["python_tag"], "--abi", "abi3", "--abi", "none"]
    for p in PIP_PLATFORMS:
        args += ["--platform", p]
    return args


def fetch_third_party(lock: dict, work: Path, epoch: int, cache: Path, dst_dir: Path) -> List[Path]:
    """The locked wheels, downloaded with ``pip --require-hashes`` and checked once more here: exactly the locked file names with exactly the locked digests."""
    dl = cache / "third-party"
    dl.mkdir(parents=True, exist_ok=True)
    req = work / "third-party.requirements"
    req.write_text("".join(f"{canonical_name(w['name'])}=={w['version']} --hash=sha256:{w['sha256']}\n" for w in lock["wheels"]), encoding="utf-8")
    need = [w for w in lock["wheels"] if not ((dl / w["filename"]).is_file() and sha256_file(dl / w["filename"]) == w["sha256"])]
    if need:
        run([sys.executable, "-m", "pip", "download", "--no-deps", "--only-binary=:all:", "--require-hashes", "-r", str(req), "--dest", str(dl), *pip_platform_args(lock["target"])],
            child_env(work / "home", epoch, network=True), what="download of the locked third-party wheels")
    out: List[Path] = []
    for w in lock["wheels"]:
        got = dl / w["filename"]
        if not got.is_file():
            raise BuildError(f"the download did not produce {w['filename']} (pip chose another file; regenerate the lock with `lock-third-party`)")
        if sha256_file(got) != w["sha256"]:
            raise BuildError(f"{w['filename']} does not have the locked sha256")
        shutil.copyfile(got, dst_dir / w["filename"])
        out.append(dst_dir / w["filename"])
    return out


def wheel_metadata(path: Path) -> Dict[str, List[str]]:
    with zipfile.ZipFile(path) as zf:
        name = next(n for n in zf.namelist() if re.fullmatch(r"[^/]+\.dist-info/METADATA", n))
        text = zf.read(name).decode("utf-8", "replace")
    out: Dict[str, List[str]] = {}
    for line in text.split("\n\n", 1)[0].splitlines():
        if ": " in line and not line.startswith(" "):
            k, v = line.split(": ", 1)
            out.setdefault(k, []).append(v)
    return out


def wheel_licence(path: Path) -> str:
    md = wheel_metadata(path)
    for key in ("License-Expression", "License"):
        if md.get(key) and md[key][0].strip() and md[key][0].strip().upper() != "UNKNOWN":
            return md[key][0].strip().splitlines()[0][:120]
    lic = [c.split("::")[-1].strip() for c in md.get("Classifier", []) if c.startswith("License ::")]
    return "; ".join(lic) if lic else "not stated in the wheel metadata"


def cmd_lock_third_party(args) -> int:
    """Resolve the direct requirements of the lock for the target and rewrite the lock with the exact files and their digests (network). Review the diff."""
    path = Path(args.out)
    lock = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"schema": LOCK_SCHEMA, "version": 1, "target": TARGET, "direct": []}
    with tempfile.TemporaryDirectory(prefix="qa-bundle-lock-") as tmp:
        work = Path(tmp)
        (work / "home").mkdir()
        dl = work / "dl"
        dl.mkdir()
        run([sys.executable, "-m", "pip", "download", "--only-binary=:all:", "--dest", str(dl), *pip_platform_args(lock["target"]), *lock["direct"]],
            child_env(work / "home", 0, network=True), what="resolution of the direct requirements")
        wheels = []
        for whl in sorted(dl.glob("*.whl")):
            name, version = wheel_name_version(whl.name)
            wheels.append({"name": name, "version": version, "filename": whl.name, "sha256": sha256_file(whl), "license": wheel_licence(whl)})
    lock["wheels"] = sorted(wheels, key=lambda w: w["name"])
    path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{path}: {len(wheels)} wheels")
    return 0


# ------------------------------------------------------------------------------------------------------------------------------- assembly
def requirements_lock_text(wheels: Sequence[Tuple[str, str, str, str]], header: str) -> str:
    """``name==version`` with ``--hash`` for every wheel, sorted by name. ``wheels`` are (filename, name, version, sha256)."""
    lines = [f"# {line}" for line in header.splitlines()]
    for _filename, name, version, digest in sorted(wheels, key=lambda w: (w[1], w[2])):
        lines.append(f"{name}=={version} \\\n    --hash=sha256:{digest}")
    return "\n".join(lines) + "\n"


def render_readme(template: str, values: Dict[str, str]) -> str:
    def sub(m):
        if m.group(1) not in values:
            raise BuildError(f"README placeholder {{{{{m.group(1)}}}}} has no value")
        return values[m.group(1)]
    return re.sub(r"\{\{([a-z_]+)\}\}", sub, template)


@dataclasses.dataclass
class WheelEntry:
    path: Path
    kind: str                  # first-party | pinned-upstreams | third-party
    licence: str


def browser_record(wheel: Optional[Path]) -> dict:
    """What the Playwright wheel says about the Chromium it installs (read from the wheel; nothing is downloaded or executed)."""
    rec = {"engine": "chromium", "installed_by": "install-browser.sh (python -m playwright install chromium)", "fetched_at_install": True, "hashed_by_this_bundle": False,
           "note": "Chromium is downloaded from the Playwright download host when the browser step runs. This bundle records which build the pinned Playwright expects; it does not hash or ship the browser, and `redevops-qa doctor` reports the build that launches."}
    if wheel is None:
        return rec
    with zipfile.ZipFile(wheel) as zf:
        data = json.loads(zf.read("playwright/driver/package/browsers.json"))
    for b in data["browsers"]:
        if b["name"] == "chromium":
            rec.update({"playwright": wheel_name_version(wheel.name)[1], "revision": str(b["revision"]), "browser_version": b.get("browserVersion", "")})
    return rec


def assemble(out_dir: Path, *, name: str, entries: Sequence[WheelEntry], target: dict, epoch: int, label: str, version: str, commit: str, pins_info: Optional[dict],
             licences_from: Dict[str, Path], build_tools: Dict[str, str], readme_template: str) -> Path:
    """Write the bundle directory ``out_dir/name`` and return it. Nothing here reads the network or a clock."""
    bdir = out_dir / name
    (bdir / "wheelhouse").mkdir(parents=True)
    wheels = []
    lock_rows = []
    for e in sorted(entries, key=lambda e: e.path.name):
        dst = bdir / "wheelhouse" / e.path.name
        shutil.copyfile(e.path, dst)
        n, v = wheel_name_version(e.path.name)
        digest = sha256_file(dst)
        wheels.append({"filename": e.path.name, "name": n, "version": v, "sha256": digest, "kind": e.kind, "license": e.licence})
        lock_rows.append((e.path.name, n, v, digest))
    (bdir / "requirements.lock").write_text(requirements_lock_text(lock_rows, f"{name}: every wheel of the wheelhouse, by sha256; installed with --no-index --require-hashes"),
                                            encoding="utf-8", newline="\n")
    for script in SCRIPTS:
        shutil.copyfile(BUNDLE_SRC / script, bdir / script)
        os.chmod(bdir / script, 0o755)
    licence_dir = bdir / "licences"
    for group, base in sorted(licences_from.items()):
        for f in LICENCE_FILES[group]:
            if (base / f).is_file():
                (licence_dir / group).mkdir(parents=True, exist_ok=True)
                shutil.copyfile(base / f, licence_dir / group / f)
    third = [w for w in wheels if w["kind"] == "third-party"]
    pw = next((e.path for e in entries if wheel_name_version(e.path.name)[0] == "playwright"), None)
    manifest = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "name": name, "bundle_version": version, "label": label,
        "source": {"repository": "redevops-io/redevops-qa", "commit": commit},
        "target": target, "pins": pins_info, "wheels": wheels, "browser": browser_record(pw), "build_tools": build_tools,
        "licences": {
            "summary": "An assembly of separately licensed parts; there is no single licence for the whole bundle.",
            "redevops_qa_packages": "source-available under the family licence (AGPL-3.0-or-later with the Commons Clause); not open source. licences/redevops-qa/",
            "runtime_contracts": "source-available under the family licence (AGPL-3.0-or-later with the Commons Clause); not open source. licences/runtime-contracts/",
            "agent_harness": "AGPL-3.0-or-later (plain, without the Commons Clause). licences/agent-harness/",
            "third_party": f"{len(third)} wheels under their own licences, unmodified, each carrying its licence files in its dist-info: " + ", ".join(f"{w['name']} {w['version']} ({w['license']})" for w in third),
            "chromium": "downloaded at install time under its own licences; not part of this bundle",
        },
        "integrity": "SHA256SUMS and requirements.lock are inside the bundle: they detect damage and partial replacement, not a replaced bundle. Compare the digest of the archive with a value obtained from somewhere the archive's producer does not control.",
        "scope": "CPython " + target["python"] + ", " + target["platform"].replace("-", " ") + ". No other Python minor or platform is claimed.",
    }
    (bdir / "BUNDLE.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    values = {"bundle_name": name, "bundle_version": version, "python": target["python"], "platform": target["platform"].replace("-", " "), "python_tag": target["python_tag"],
              "wheel_count": str(len(wheels)), "commit": commit}
    (bdir / "README.md").write_text(render_readme(readme_template, values), encoding="utf-8", newline="\n")
    (bdir / "SHA256SUMS").write_text(sha256sums_text(bdir), encoding="utf-8", newline="\n")
    return bdir


def cmd_build(args) -> int:
    root = ROOT
    commit, epoch = source_state(root)
    version = runner_version(root)
    name = f"redevops-qa-bundle-{version}-{TARGET['python_tag']}-{TARGET['platform']}"
    out_dir = Path(args.out).resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise BuildError(f"{out_dir} exists and is not empty")
    out_dir.mkdir(parents=True, exist_ok=True)
    cache = Path(args.download_cache).resolve() if args.download_cache else Path(tempfile.mkdtemp(prefix="qa-bundle-cache-"))
    cache.mkdir(parents=True, exist_ok=True)
    pins_file = root / "pins.toml"
    pins, deps, _pinmod = load_pins(pins_file)
    pinned_root = Path(args.pinned_root).resolve() if args.pinned_root else root / ".pinned"
    trees = pinned_trees(pins, deps, pinned_root, pins_file)
    with tempfile.TemporaryDirectory(prefix="qa-bundle-work-") as tmp:
        work = Path(tmp)
        (work / "home").mkdir()
        wheels_dir = work / "wheels"
        wheels_dir.mkdir()
        py = make_build_venv(work, epoch, cache)
        entries = [WheelEntry(p, "first-party", "source-available, AGPL-3.0-or-later with the Commons Clause") for p in build_first_party(root, FIRST_PARTY, epoch, work, py, wheels_dir)]
        entries.append(WheelEntry(build_pinned_wheel(pins_file, trees, deps, version, epoch, wheels_dir), "pinned-upstreams",
                                  "runtime-contracts: AGPL-3.0-or-later with the Commons Clause; agent-harness: AGPL-3.0-or-later"))
        lock = read_third_party_lock()
        if lock["target"] != TARGET:
            raise BuildError("bundle/third-party.lock.json is for another target than this builder's")
        tp_dir = work / "third-party"
        tp_dir.mkdir()
        for path in fetch_third_party(lock, work, epoch, cache, tp_dir):
            entries.append(WheelEntry(path, "third-party", next(w["license"] for w in lock["wheels"] if w["filename"] == path.name)))
        build_lock = (BUNDLE_SRC / "build-requirements.lock").read_text(encoding="utf-8")
        tools = dict(re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", build_lock, re.M))
        pins_info = {"set": pins.pin_set, "pins_toml_sha256": sha256_file(pins_file),
                     "contracts": {"version": pins.contracts.version, "tag": pins.contracts.tag, "commit": pins.contracts.commit, "distribution_sha256": pins.contracts.distribution_sha256},
                     "harness": {"version": pins.harness_qa.version, "tag": pins.harness_qa.tag, "commit": pins.harness_qa.commit, "distribution_sha256": pins.harness_qa.distribution_sha256}}
        bdir = assemble(work / "out", name=name, entries=entries, target=dict(TARGET), epoch=epoch, label=args.label, version=version, commit=commit, pins_info=pins_info,
                        licences_from={"redevops-qa": root, "runtime-contracts": trees["contracts"][1], "agent-harness": trees["harness_qa"][1]}, build_tools=tools,
                        readme_template=(BUNDLE_SRC / "README.md").read_text(encoding="utf-8"))
        shutil.copytree(bdir, out_dir / name)
    tar_path = out_dir / f"{name}.tar"
    write_tar(out_dir / name, tar_path, epoch)
    (out_dir / f"{name}.tar.sha256").write_text(f"{sha256_file(tar_path)}  {tar_path.name}\n", encoding="utf-8")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import check_bundle                                  # noqa: PLC0415
    findings = check_bundle.check_bundle(out_dir / name)
    if findings:
        raise BuildError("the bundle just built does not pass tools/check_bundle.py:\n  " + "\n  ".join(str(f) for f in findings))
    print(f"bundle: {out_dir / name}")
    print(f"archive: {tar_path}")
    print(f"archive sha256: {sha256_file(tar_path)}")
    print(f"SHA256SUMS sha256: {sha256_file(out_dir / name / 'SHA256SUMS')}")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="build_bundle.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="build the bundle directory and its archive under --out")
    b.add_argument("--out", required=True, help="an empty (or new) directory")
    b.add_argument("--label", default="", help="free text recorded in BUNDLE.json (default: none)")
    b.add_argument("--pinned-root", help="the directory holding the verified pinned trees (default: ./.pinned)")
    b.add_argument("--download-cache", help="a directory that keeps downloaded wheels between builds (every file is hash-checked on each use)")
    lk = sub.add_parser("lock-third-party", help="re-resolve bundle/third-party.lock.json from its direct requirements (network); review the diff")
    lk.add_argument("--out", default=str(BUNDLE_SRC / "third-party.lock.json"))
    args = p.parse_args(argv)
    try:
        return {"build": cmd_build, "lock-third-party": cmd_lock_third_party}[args.command](args)
    except BuildError as exc:
        print(f"build_bundle: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
