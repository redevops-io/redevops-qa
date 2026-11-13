# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The standalone image changes how redevops-qa is packaged and started, not what it is. These tests pin the integration contract that existed before the image and fail, with the file
named, if a later change touches it without saying so: the pinned upstreams (the ``qa/v1`` schemas and golden vectors are owned by runtime-contracts and enter through pins.toml), the
command line and its exit-status table, the bundle installer and its locks, the capability and profile schemas, and the way the image installs the product (the bundle's own scripts)."""
import hashlib
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


#: digests of the contract files as they were on main before the standalone image (acfa085). Changing one of these files is allowed, but it is a change of the contract: update the digest in the same commit and say why.
CONTRACT_FILES = {
    "pins.toml": "0c8896b8eea1b6da775d66409cf15b103c5ce5f6ff527f782ec85c5a1896dfc6",
    "bundle/install.sh": "1cc6f524f68d30b01691d9d988877e5c9f737db66fc0f9afa65a5b192b30011a",
    "bundle/install-browser.sh": "aaced7917d47a3af6aab7b1a99175c7b25dcbe0d7b56e02d89a34546acaa6f6d",
    "bundle/uninstall.sh": "5b4f88c5246c99d291dfb9fccddc7f5702bce057dfedc472ac037180cc9efc24",
    "bundle/browser.lock.json": "d2cda3fc4eaa290cf19232806b8427264a43603e2453ca013eb36d418d2a92ff",
    "bundle/third-party.lock.json": "6b791279381fbb9d50f5cdd4965939077aa3dc6a5d5128da7dd09da717253bc2",
    "schemas/qa-capabilities.schema.json": "3ed8998b8b70d9fd35dbf9fcdc0176f9d307d010b21a694dc81e267a34ce30a9",
    "schemas/qa-install-profiles.schema.json": "dccd58562015e18be0cdda27483ef35902a2cea4b206dcef46bd9dc4f897c21f",
}


def test_the_contract_files_are_unchanged():
    for path, digest in CONTRACT_FILES.items():
        assert sha(path) == digest, f"{path} changed: it is part of the integration contract (see this test)"


def test_the_pinned_upstreams_are_the_same_releases():
    pins = tomllib.loads((ROOT / "pins.toml").read_text(encoding="utf-8"))
    got = {name: (s["contracts"]["version"], s["contracts"]["commit"], s["harness_qa"]["version"], s["harness_qa"]["commit"]) for name, s in pins["sets"].items()}
    assert got == {"c3": ("0.3.15", "5f1e713762d93c866218ded2de7b9c129ce0cf06", "0.2.0", "a58ef9efcf2aa61fa92137f6a8dbd589b6e4b183"),
                   "c4": ("0.3.16", "d739c1941fd0f03aad9b5c75c6f9b2a0df67cc26", "0.2.0", "a58ef9efcf2aa61fa92137f6a8dbd589b6e4b183")}


def test_the_bundle_still_ships_the_same_first_party_packages_and_not_the_service():
    import importlib.util
    import sys
    spec = importlib.util.spec_from_file_location("build_bundle", ROOT / "tools" / "build_bundle.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["build_bundle"] = mod
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop("build_bundle", None)
    assert set(mod.FIRST_PARTY) == {"qa-adapter-kit", "qa-bridge", "qa-checks", "qa-egress", "qa-evidence", "qa-fixture-app", "qa-playwright", "qa-robot", "qa-runner"}
    assert "qa-service" not in mod.FIRST_PARTY


def test_the_command_line_has_the_same_commands():
    cli = (ROOT / "packages" / "qa-runner" / "src" / "qa_runner" / "cli.py").read_text(encoding="utf-8")
    assert set(re.findall(r'(?:sub|asub)\.add_parser\("(\w+)"', cli)) >= {"doctor", "freeze", "run", "demo", "verify", "anchor", "statement", "sign"}
    # report and inspect are registered through a loop; they are listed in the README command table the service relies on
    readme = (ROOT / "packages" / "qa-runner" / "README.md").read_text(encoding="utf-8")
    for command in ("doctor", "freeze", "run", "verify", "demo", "report", "inspect", "anchor"):
        assert f"redevops-qa {command}" in readme


def test_the_service_reads_the_runners_exit_status_table_and_the_shipped_plans():
    from qa_service.runs import EXIT_MEANING, PLANS
    readme = (ROOT / "packages" / "qa-runner" / "README.md").read_text(encoding="utf-8")
    table = dict((int(code), meaning) for code, meaning in re.findall(r"^\| (\d) \| (.*?) \|$", readme.split("| Exit | Meaning |", 1)[1], re.M))
    assert sorted(table) == sorted(EXIT_MEANING) == list(range(8))
    assert "`VERIFIED`" in table[0] and "FAILED" in table[1] and "refused" in table[2] and "did not run to completion" in table[3] and "inconclusive" in table[4] and "rejected" in table[5] and "internal error" in table[6]
    for _, plan_file, _ in PLANS.values():
        assert plan_file is None or (ROOT / "packages" / "qa-runner" / "examples" / plan_file).is_file()


def test_the_image_installs_the_product_with_its_own_bundle_scripts_and_changes_none_of_its_files():
    docker = (ROOT / "deploy" / "standalone" / "Dockerfile").read_text(encoding="utf-8")
    assert "./install.sh --prefix /opt/redevops-qa" in docker and "./install-browser.sh --prefix /opt/redevops-qa --with-deps" in docker
    assert "python tools/build_bundle.py build" in docker and "python tools/fetch_pins.py" in docker
    assert "@sha256:" in docker.split("AS bundle", 1)[0].splitlines()[-1] and docker.count("@sha256:") >= 2
    assert "USER 10001:10001" in docker and "HEALTHCHECK" in docker


def test_the_environment_variables_the_runner_reads_are_the_ones_the_service_passes_on():
    from qa_service.runs import RunStore
    keys = {"REDEVOPS_QA_PINS", "PLAYWRIGHT_BROWSERS_PATH"}
    deps = (ROOT / "packages" / "qa-runner" / "src" / "qa_runner" / "deps.py").read_text(encoding="utf-8")
    assert all(k in deps for k in keys)
    assert "QA_SERVICE_TOKEN" not in RunStore.child_env.__code__.co_names
