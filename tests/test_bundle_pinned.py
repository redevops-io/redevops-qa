# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The wheel that carries the pinned upstream trees: built from the trees the jobs fetch (``.pinned``), installed by real pip, and verified against pins.toml in a clean
interpreter exactly as ``redevops-qa doctor`` does. Needs the two pinned trees on disk (the CI job that runs this file fetches them; a missing tree is a failure)."""
import hashlib
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from bundle_helpers import ROOT, bb

PINS_FILE = ROOT / "pins.toml"
BRIDGE_SRC = ROOT / "packages" / "qa-bridge" / "src"


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    pins, deps, pinmod = bb.load_pins(PINS_FILE)
    trees = bb.pinned_trees(pins, deps, ROOT / ".pinned", PINS_FILE)
    out = tmp_path_factory.mktemp("pinned-wheel")
    wheel = bb.build_pinned_wheel(PINS_FILE, trees, deps, "0.1.0.dev0", 1_700_000_000, out)
    return pins, deps, pinmod, trees, wheel


@pytest.fixture(scope="module")
def installed(built, tmp_path_factory):
    _pins, _deps, _pinmod, _trees, wheel = built
    prefix = tmp_path_factory.mktemp("prefix")
    done = subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--disable-pip-version-check", "--no-input", "--prefix", str(prefix), str(wheel)],
                          capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "HOME": str(prefix), "PIP_CONFIG_FILE": "/dev/null"}, timeout=300)
    assert done.returncode == 0, done.stderr
    return prefix / "share" / "redevops-qa"


def test_the_trees_are_verified_against_the_pins_before_anything_is_packed(tmp_path):
    pins, deps, _ = bb.load_pins(PINS_FILE)
    copy_root = tmp_path / ".pinned"
    import shutil
    shutil.copytree(ROOT / ".pinned" / "c4", copy_root / "c4", ignore=shutil.ignore_patterns(".git", "__pycache__"))
    victim = copy_root / "c4" / "agent-harness" / "agent_harness" / "qa" / "__init__.py"
    victim.write_bytes(victim.read_bytes() + b"\n# changed\n")
    with pytest.raises(bb.BuildError, match="PIN_DIGEST_MISMATCH"):
        bb.pinned_trees(pins, deps, copy_root, PINS_FILE)


def test_the_wheel_installs_pins_toml_and_both_trees_under_share_next_to_each_other(installed):
    assert (installed / "pins.toml").read_bytes() == PINS_FILE.read_bytes()
    assert (installed / ".pinned" / "c4" / "runtime-contracts" / "runtime_contracts" / "__init__.py").is_file()
    assert (installed / ".pinned" / "c4" / "agent-harness" / "agent_harness" / "qa" / "__init__.py").is_file()
    assert not (installed / ".pinned" / "c3").exists()                       # only the default pin set is shipped


def test_the_installed_trees_are_exactly_the_pinned_ones(installed, built):
    _pins, deps, pinmod, _trees, _wheel = built
    pins = pinmod.load_pins(installed / "pins.toml", pin_set="c4")
    assert pins.contracts.resolved_path.resolve() == (installed / ".pinned" / "c4" / "runtime-contracts").resolve()
    problems = [p for dep in (pins.contracts, pins.harness_qa) for p in deps.pin_problems(dep)]
    assert problems == []                       # distribution digest, every vector file, no unlisted addendum file, the version the tree declares; no git checkout is needed or claimed


def test_the_licence_files_travel_with_the_trees_and_the_harness_has_only_the_plain_one(installed):
    contracts = installed / ".pinned" / "c4" / "runtime-contracts"
    harness = installed / ".pinned" / "c4" / "agent-harness"
    assert (contracts / "LICENSE").is_file() and (contracts / "LICENSE-COMMONS-CLAUSE").is_file()
    assert (harness / "LICENSE").is_file() and not (harness / "LICENSE-COMMONS-CLAUSE").exists()


def test_a_clean_interpreter_verifies_the_installed_pins_the_way_doctor_does(installed, tmp_path):
    script = ("import sys\nsys.path.insert(0, sys.argv[1])\nfrom pathlib import Path\nfrom redevops_qa_bridge import deps, pins\n"
              "p = pins.load_pins(Path(sys.argv[2]) / 'pins.toml')\ndeps.prepare_paths(p)\ndeps.verify_pins(p)\n"
              "import agent_harness.qa, runtime_contracts.qa\nprint('verified', p.pin_set, p.contracts.version, p.harness_qa.version)")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    done = subprocess.run([sys.executable, "-I", "-c", script, str(BRIDGE_SRC), str(installed)], capture_output=True, text=True, env=env, cwd=str(tmp_path))
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "verified c4 0.3.16 0.2.0"


def test_a_changed_installed_file_is_found_by_the_same_check(installed, tmp_path):
    import shutil
    copy = tmp_path / "share"
    shutil.copytree(installed, copy)
    target = copy / ".pinned" / "c4" / "runtime-contracts" / "runtime_contracts" / "__init__.py"
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    script = ("import sys\nsys.path.insert(0, sys.argv[1])\nfrom pathlib import Path\nfrom redevops_qa_bridge import deps, pins\n"
              "p = pins.load_pins(Path(sys.argv[2]) / 'pins.toml')\ndeps.prepare_paths(p)\ndeps.verify_pins(p)\nprint('verified')")
    done = subprocess.run([sys.executable, "-I", "-c", script, str(BRIDGE_SRC), str(copy)], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}, cwd=str(tmp_path))
    assert done.returncode != 0 and "PIN_DIGEST_MISMATCH" in done.stderr


def test_the_wheel_is_a_valid_wheel_with_a_record_that_lists_every_file_with_its_digest(built):
    *_, wheel = built
    import base64
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
        record = zf.read("redevops_qa_pinned_upstreams-0.1.0.dev0.dist-info/RECORD").decode().splitlines()
        rows = {line.split(",")[0]: line.split(",") for line in record}
        assert set(rows) == set(names) and names[-1].endswith(".dist-info/RECORD")
        for n in names[:-1]:
            data = zf.read(n)
            assert rows[n][1] == "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode() and rows[n][2] == str(len(data))
        metadata = zf.read("redevops_qa_pinned_upstreams-0.1.0.dev0.dist-info/METADATA").decode()
    assert "Name: redevops-qa-pinned-upstreams" in metadata
    assert "agent-harness is AGPL-3.0-or-later" in metadata and "runtime-contracts is AGPL-3.0-or-later with the Commons Clause" in metadata


def test_the_wheel_is_not_an_installable_agent_harness_or_runtime_contracts_distribution(built):
    *_, wheel = built
    with zipfile.ZipFile(wheel) as zf:
        assert not any(n.split("/")[0] in ("agent_harness", "runtime_contracts") for n in zf.namelist())      # no import path is added to the environment
        assert zf.read("redevops_qa_pinned_upstreams-0.1.0.dev0.dist-info/top_level.txt").strip() == b""


def test_building_the_wheel_twice_gives_the_same_bytes(built, tmp_path):
    pins, deps, _pinmod, trees, wheel = built
    again = bb.build_pinned_wheel(PINS_FILE, trees, deps, "0.1.0.dev0", 1_700_000_000, tmp_path)
    assert again.read_bytes() == wheel.read_bytes()
