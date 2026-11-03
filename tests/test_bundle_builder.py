# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The bundle builder's pure parts, the committed locks, and the bundle checker against a bundle and against mutations of it. Offline; no pinned tree, no browser."""
import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import zipfile
from pathlib import Path

import pytest

from bundle_helpers import ROOT, bb, cb, host_target, make_mini_bundle, make_wheel, resum

LOCK = json.loads((ROOT / "bundle" / "third-party.lock.json").read_text(encoding="utf-8"))


# ----------------------------------------------------------------------------------------------------------------------- determinism of the parts
def _zip(path, entries, *, date, compress):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED) as zf:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date)
            info.compress_type = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
            zf.writestr(info, data)


def test_a_normalised_wheel_does_not_depend_on_entry_order_timestamps_or_compression(tmp_path):
    entries = [("pkg/b.py", b"b = 2\n"), ("pkg-1.dist-info/RECORD", b"r\n"), ("pkg/a.py", b"a = 1\n"), ("pkg-1.dist-info/METADATA", b"Name: pkg\n")]
    _zip(tmp_path / "one.whl", entries, date=(2001, 2, 3, 4, 5, 6), compress=True)
    _zip(tmp_path / "two.whl", list(reversed(entries)), date=(2020, 12, 31, 23, 59, 58), compress=False)
    bb.normalise_wheel(tmp_path / "one.whl", tmp_path / "n1.whl", 1_700_000_000)
    bb.normalise_wheel(tmp_path / "two.whl", tmp_path / "n2.whl", 1_700_000_000)
    assert (tmp_path / "n1.whl").read_bytes() == (tmp_path / "n2.whl").read_bytes()
    with zipfile.ZipFile(tmp_path / "n1.whl") as zf:
        names = zf.namelist()
        assert names[-1] == "pkg-1.dist-info/RECORD" and names[:-1] == sorted(names[:-1])
        assert {i.compress_type for i in zf.infolist()} == {zipfile.ZIP_STORED} and len({i.date_time for i in zf.infolist()}) == 1
        assert {n: zf.read(n) for n in names} == dict(entries)                      # the contents are the input's, byte for byte


def test_a_normalised_wheel_refuses_a_duplicate_entry(tmp_path):
    with zipfile.ZipFile(tmp_path / "d.whl", "w") as zf:
        zf.writestr("a.py", b"1")
        with pytest.warns(UserWarning):
            zf.writestr("a.py", b"2")
    with pytest.raises(bb.BuildError, match="duplicate entry"):
        bb.normalise_wheel(tmp_path / "d.whl", tmp_path / "o.whl", 1_700_000_000)


def test_the_archive_is_a_plain_tar_that_does_not_depend_on_file_times_owners_or_creation_order(tmp_path):
    def tree(root: Path, times: int) -> Path:
        d = root / "bundle-x"
        (d / "wheelhouse").mkdir(parents=True)
        for rel, data in (("wheelhouse/b.whl", b"B"), ("README.md", b"r"), ("install.sh", b"#!/bin/sh\n"), ("wheelhouse/a.whl", b"A")):
            (d / rel).write_bytes(data)
            os.utime(d / rel, (times, times))
        return d
    one, two = tree(tmp_path / "one", 1_000_000_000), tree(tmp_path / "two", 1_600_000_000)
    bb.write_tar(one, tmp_path / "1.tar", 1_700_000_000)
    bb.write_tar(two, tmp_path / "2.tar", 1_700_000_000)
    assert (tmp_path / "1.tar").read_bytes() == (tmp_path / "2.tar").read_bytes()
    with tarfile.open(tmp_path / "1.tar") as tf:
        members = tf.getmembers()
        assert [m.name for m in members] == sorted(m.name for m in members) or members[0].name == "bundle-x/"
        assert {(m.uid, m.gid, m.uname, m.gname, m.mtime) for m in members} == {(0, 0, "", "", 1_700_000_000)}
        modes = {m.name: m.mode for m in members if m.isfile()}
        assert modes["bundle-x/install.sh"] == 0o755 and modes["bundle-x/README.md"] == 0o644 and modes["bundle-x/wheelhouse/a.whl"] == 0o644
    assert not (tmp_path / "1.tar").read_bytes().startswith(b"\x1f\x8b")           # not gzip: a compressed archive would depend on a zlib build


def test_sha256sums_lists_every_file_but_itself_in_sorted_order_in_the_sha256sum_format(tmp_path):
    (tmp_path / "w").mkdir()
    (tmp_path / "w" / "b").write_bytes(b"b")
    (tmp_path / "a").write_bytes(b"a")
    (tmp_path / "SHA256SUMS").write_text("stale\n")
    text = bb.sha256sums_text(tmp_path)
    assert text == f"{hashlib.sha256(b'a').hexdigest()}  a\n{hashlib.sha256(b'b').hexdigest()}  w/b\n"


def test_the_requirements_lock_pins_every_wheel_by_name_version_and_hash():
    text = bb.requirements_lock_text([("b-2-py3-none-any.whl", "b", "2", "b" * 64), ("a-1-py3-none-any.whl", "a", "1", "a" * 64)], "header\nsecond line")
    assert text.splitlines()[:2] == ["# header", "# second line"]
    assert text.index("a==1") < text.index("b==2")
    assert re.findall(r"^(\S+==\S+) \\$", text, re.M) == ["a==1", "b==2"] and text.count("--hash=sha256:") == 2


def test_the_readme_template_renders_with_every_placeholder_and_refuses_an_unknown_one():
    template = (ROOT / "bundle" / "README.md").read_text(encoding="utf-8")
    assert set(re.findall(r"\{\{([a-z_]+)\}\}", template)) <= {"bundle_name", "bundle_version", "python", "platform", "python_tag", "wheel_count", "commit"}
    with pytest.raises(bb.BuildError, match="no value"):
        bb.render_readme("{{nothing}}", {})


# ------------------------------------------------------------------------------------------------------------------------------- the locks
def test_the_third_party_lock_is_for_the_one_target_and_every_wheel_is_pinned_by_a_digest_that_matches_its_name():
    lock = bb.read_third_party_lock()
    assert lock["target"] == bb.TARGET == {"python": "3.12", "python_tag": "cp312", "platform": "linux-x86_64"}
    names = {w["name"] for w in lock["wheels"]}
    assert {"playwright", "robotframework", "pyyaml", "greenlet", "pyee", "typing-extensions"} == names
    for w in lock["wheels"]:
        assert re.fullmatch(r"[0-9a-f]{64}", w["sha256"]) and w["filename"].endswith(".whl")
        if w["name"] in ("greenlet", "pyyaml"):
            assert "cp312" in w["filename"] and "x86_64" in w["filename"]          # the compiled wheels are for this one Python and this one platform
        if w["name"] == "playwright":
            assert "x86_64" in w["filename"]


def test_the_engine_pins_of_the_lock_are_the_ones_doctor_and_the_ci_jobs_use():
    doctor = (ROOT / "packages" / "qa-runner" / "src" / "qa_runner" / "doctor.py").read_text(encoding="utf-8")
    pw, robot = re.search(r'PLAYWRIGHT_PIN = "([^"]+)"', doctor).group(1), re.search(r'ROBOT_PIN = "([^"]+)"', doctor).group(1)
    by_name = {w["name"]: w["version"] for w in LOCK["wheels"]}
    assert (by_name["playwright"], by_name["robotframework"]) == (pw, robot)
    assert f"playwright=={pw}" in LOCK["direct"] and f"robotframework=={robot}" in LOCK["direct"]


def test_the_lock_matches_the_matrix_for_the_wheel_the_matrix_hashes():
    matrix = (ROOT / "third_party" / "adapter-license-matrix.yaml").read_text(encoding="utf-8")
    robot = next(w for w in LOCK["wheels"] if w["name"] == "robotframework")
    assert robot["sha256"] in matrix                  # the licence matrix recorded the same file


def test_the_build_tool_is_pinned_with_a_hash_and_nothing_else_is_installed_to_build():
    text = (ROOT / "bundle" / "build-requirements.lock").read_text(encoding="utf-8")
    reqs = [l for l in text.replace("\\\n", " ").splitlines() if l.strip() and not l.startswith("#")]
    assert len(reqs) == 1 and re.fullmatch(r"setuptools==\d+(\.\d+)+ +--hash=sha256:[0-9a-f]{64}", reqs[0])


def test_the_bundle_holds_the_packages_of_the_release_claim_and_not_selenium_or_appium():
    assert set(bb.FIRST_PARTY) == {"qa-adapter-kit", "qa-bridge", "qa-checks", "qa-egress", "qa-evidence", "qa-fixture-app", "qa-playwright", "qa-robot", "qa-runner"}
    assert all((ROOT / "packages" / p / "pyproject.toml").is_file() for p in bb.FIRST_PARTY)


def test_the_runner_wheel_carries_the_reviewed_robot_suite():
    pyproject = (ROOT / "packages" / "qa-runner" / "pyproject.toml").read_text(encoding="utf-8")
    assert '"qa_runner.robot_suite" = ["*.robot"]' in pyproject
    assert (ROOT / "packages" / "qa-runner" / "src" / "qa_runner" / "robot_suite" / "order_discount.robot").is_file()


# ----------------------------------------------------------------------------------------------------------------------------- the checker
@pytest.fixture(scope="module")
def mini(tmp_path_factory):
    return make_mini_bundle(tmp_path_factory.mktemp("mini"))


def codes(bundle, **kw):
    return {f.code for f in cb.check_bundle(bundle, allow_test_target=True, **kw)}


@pytest.fixture()
def copy(mini, tmp_path):
    dst = tmp_path / mini.name
    shutil.copytree(mini, dst)
    return dst


def test_a_bundle_built_by_the_builder_passes_the_checker(mini):
    assert cb.check_bundle(mini, allow_test_target=True) == []


def test_a_test_bundle_is_not_a_release_bundle(mini):
    found = {f.code for f in cb.check_bundle(mini)}
    assert "WHEEL_KINDS" in found or "TARGET" in found           # only the real target, with the three kinds of wheel and a pins record, passes without the test switch


def test_the_checker_runs_as_a_script_and_exits_nonzero_on_a_finding(mini, tmp_path):
    import subprocess
    import sys
    ok = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "check_bundle.py"), str(mini), "--allow-test-target"], capture_output=True, text=True, cwd=str(tmp_path))
    assert ok.returncode == 0 and "check_bundle: OK" in ok.stdout
    bad = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "check_bundle.py"), str(tmp_path / "nothing")], capture_output=True, text=True, cwd=str(tmp_path))
    assert bad.returncode == 1 and subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "check_bundle.py")], capture_output=True, text=True).returncode == 2


def test_a_changed_wheel_is_found_by_the_sums_the_manifest_and_the_lock(copy):
    wheel = next((copy / "wheelhouse").glob("*.whl"))
    wheel.write_bytes(wheel.read_bytes() + b"x")
    assert {"SUMS_MISMATCH", "WHEEL_DIGEST", "LOCK_DIGEST"} <= codes(copy)
    resum(copy)
    assert {"WHEEL_DIGEST", "LOCK_DIGEST"} <= codes(copy) and "SUMS_MISMATCH" not in codes(copy)           # re-signing the sums does not hide it from the other two records


def test_an_unlisted_missing_or_extra_file_is_found(copy):
    (copy / "extra.txt").write_text("x")
    assert "SUMS_UNLISTED" in codes(copy)
    (copy / "extra.txt").unlink()
    (copy / "uninstall.sh").unlink()
    assert "MISSING_FILE" in codes(copy)


def test_a_wheel_that_is_not_in_the_manifest_or_the_lock_is_found(copy, tmp_path):
    extra = make_wheel(copy / "wheelhouse", "9.9", name="other_pkg")
    resum(copy)
    assert {"WHEEL_UNLISTED"} <= codes(copy)
    extra.unlink()
    lock = (copy / "requirements.lock").read_text(encoding="utf-8") + "other-pkg==9.9 \\\n    --hash=sha256:" + "0" * 64 + "\n"
    (copy / "requirements.lock").write_text(lock, encoding="utf-8")
    resum(copy)
    assert "LOCK_EXTRA" in codes(copy)


def test_a_requirement_without_a_hash_is_found(copy):
    (copy / "requirements.lock").write_text((copy / "requirements.lock").read_text(encoding="utf-8") + "requests\n", encoding="utf-8")
    resum(copy)
    assert "LOCK_LINE" in codes(copy)


@pytest.mark.parametrize("text", ["pip install agent-harness", "this is tamper-proof", "a reproducible build", "SOC 2 ready", "see the QA demo site"])
def test_text_the_release_does_not_support_is_found(copy, text):
    (copy / "README.md").write_text((copy / "README.md").read_text(encoding="utf-8") + "\n" + text + "\n", encoding="utf-8")
    resum(copy)
    assert "FORBIDDEN_TEXT" in codes(copy)


def test_calling_the_bundle_open_source_is_found_but_not_open_source_is_fine(copy):
    readme = copy / "README.md"
    original = readme.read_text(encoding="utf-8")
    assert "not open source" in original and cb.check_bundle(copy, allow_test_target=True) == []
    readme.write_text(original.replace("not open source", "an open-source bundle"), encoding="utf-8")
    resum(copy)
    assert "FORBIDDEN_TEXT" in codes(copy)


@pytest.mark.parametrize("phrase", ["AGPL-3.0-or-later with the Commons Clause", "plain AGPL-3.0-or-later", "not hashed", "not open source"])
def test_the_readme_must_state_the_licences_and_the_browser_limit(copy, phrase):
    readme = copy / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8").replace(phrase, "REDACTED"), encoding="utf-8")
    resum(copy)
    assert "README_MISSING_TEXT" in codes(copy)


def test_a_manifest_that_claims_a_hashed_browser_is_found(copy):
    path = copy / "BUNDLE.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["browser"]["hashed_by_this_bundle"] = True
    path.write_text(json.dumps(doc), encoding="utf-8")
    resum(copy)
    assert "BROWSER_RECORD" in codes(copy)


def test_the_manifest_states_the_mixed_licence_and_the_scope(mini):
    doc = json.loads((mini / "BUNDLE.json").read_text(encoding="utf-8"))
    lic = doc["licences"]
    assert "no single licence" in lic["summary"]
    assert "AGPL-3.0-or-later with the Commons Clause" in lic["runtime_contracts"] and "not open source" in lic["runtime_contracts"]
    assert lic["agent_harness"].startswith("AGPL-3.0-or-later (plain") and "Commons Clause" in lic["agent_harness"] and "without" in lic["agent_harness"]
    assert "No other Python minor or platform is claimed" in doc["scope"]
    assert doc["browser"]["fetched_at_install"] is True and doc["browser"]["hashed_by_this_bundle"] is False
    assert "not a replaced bundle" in doc["integrity"]


def test_the_manifest_carries_nothing_that_varies_between_builds_of_one_commit(mini):
    text = (mini / "BUNDLE.json").read_text(encoding="utf-8")
    assert not re.search(r"\d{4}-\d{2}-\d{2}T", text) and str(Path.home()) not in text and "/tmp" not in text and "/private" not in text


def test_two_builds_of_the_same_inputs_have_the_same_sums(tmp_path):
    a = make_mini_bundle(tmp_path / "a")
    b = make_mini_bundle(tmp_path / "b")
    assert (a / "SHA256SUMS").read_bytes() == (b / "SHA256SUMS").read_bytes()
    c = make_mini_bundle(tmp_path / "c", label="other")
    assert (a / "SHA256SUMS").read_bytes() != (c / "SHA256SUMS").read_bytes()


def test_the_host_target_matches_what_the_install_script_computes(tmp_path):
    import subprocess
    import sys
    script = "import platform, sys\nm = platform.machine().lower().replace('amd64', 'x86_64').replace('aarch64', 'arm64')\nprint('%d.%d' % sys.version_info[:2], sys.platform.replace('darwin', 'macos') + '-' + m)"
    out = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, text=True, check=True).stdout.split()
    assert out == [host_target()["python"], host_target()["platform"]]
    assert "platform.machine().lower().replace(\"amd64\", \"x86_64\").replace(\"aarch64\", \"arm64\")" in (ROOT / "bundle" / "install.sh").read_text(encoding="utf-8")


# ------------------------------------------------------------------------------------------------------------- the family licence travels in every first-party wheel
def test_every_first_party_package_declares_the_licence_files_and_a_backend_that_reads_them():
    import tomllib
    for pkg in bb.FIRST_PARTY:
        data = tomllib.loads((ROOT / "packages" / pkg / "pyproject.toml").read_text(encoding="utf-8"))
        assert data["project"]["license"] == "LicenseRef-AGPL-3.0-or-later-with-Commons-Clause" and data["project"]["license-files"] == ["LICENSE*"], pkg
        assert int(data["build-system"]["requires"][0].split(">=")[1]) >= 77, pkg                  # license-files and an SPDX string need setuptools 77 or newer


def test_the_builder_puts_the_family_licence_texts_next_to_each_package_before_it_builds():
    src = (ROOT / "tools" / "build_bundle.py").read_text(encoding="utf-8")
    assert 'for name in LICENCE_FILES["redevops-qa"]:' in src and "shutil.copyfile(root / name, src / name)" in src
    assert all((ROOT / n).is_file() for n in bb.LICENCE_FILES["redevops-qa"])


def test_a_first_party_wheel_without_the_family_licence_texts_is_found(mini, tmp_path):
    bad = tmp_path / mini.name
    shutil.copytree(mini, bad)
    wheel = next((bad / "wheelhouse").glob("*.whl"))
    make_wheel(tmp_path, "1.0", licences=False)
    wheel.write_bytes(next(tmp_path.glob("*.whl")).read_bytes())
    # keep every other record consistent so that only the licence finding remains
    import hashlib as h
    digest = h.sha256(wheel.read_bytes()).hexdigest()
    old = json.loads((bad / "BUNDLE.json").read_text())
    old["wheels"][0]["sha256"] = digest
    (bad / "BUNDLE.json").write_text(json.dumps(old, indent=2, sort_keys=True) + "\n")
    lock = (bad / "requirements.lock").read_text()
    (bad / "requirements.lock").write_text(re.sub(r"--hash=sha256:[0-9a-f]{64}", "--hash=sha256:" + digest, lock))
    resum(bad)
    found = [f for f in cb.check_bundle(bad, allow_test_target=True)]
    assert [f.code for f in found] == ["WHEEL_LICENCE"] and "LICENSE-COMMONS-CLAUSE" in found[0].message


# ------------------------------------------------------------------------------------------------------ what the manifest says about the third-party wheels
def test_the_manifest_says_third_party_wheels_are_private_staging_only_and_describes_what_the_playwright_wheel_contains(mini):
    lic = json.loads((mini / "BUNDLE.json").read_text(encoding="utf-8"))["licences"]
    assert "PRIVATE STAGING ONLY" in lic["third_party_staging"] and "owner decision" in lic["third_party_staging"]
    note = lic["third_party_notes"]["playwright"]
    assert "Node.js runtime binary" in note and "npm packages" in note and "libwebp" in note and "does not describe them" in note
    assert "Node.js" in (mini / "README.md").read_text(encoding="utf-8") and "private staging only" in (mini / "README.md").read_text(encoding="utf-8")


def test_a_manifest_that_drops_the_staging_caveat_or_the_node_note_is_found(copy):
    path = copy / "BUNDLE.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["licences"]["third_party_staging"] = "shipped"
    path.write_text(json.dumps(doc), encoding="utf-8")
    resum(copy)
    assert "LICENCES" in codes(copy)
    doc["licences"]["third_party_staging"] = "private staging only; public distribution requires an owner decision"
    doc["wheels"].append({"filename": "playwright-1-py3-none-any.whl", "name": "playwright", "version": "1", "sha256": "0" * 64, "kind": "third-party", "license": "Apache-2.0"})
    doc["licences"]["third_party_notes"] = {}
    path.write_text(json.dumps(doc), encoding="utf-8")
    resum(copy)
    found = [f for f in cb.check_bundle(copy, allow_test_target=True) if f.code == "LICENCES"]
    assert any("Node.js runtime" in f.message for f in found)

def test_the_readme_says_what_uninstall_needs_and_what_it_refuses():
    text = (ROOT / "bundle" / "README.md").read_text(encoding="utf-8")
    assert "needs a Python (`python3.12` or `python3`) on `PATH`" in text
    assert "moved, or is reached through another mount path, is refused" in text and "remove such a directory by hand" in text


def test_a_release_bundle_without_the_adapter_kit_wheel_is_found_because_the_installer_reads_the_path_policy_from_it(mini):
    found = {f.code for f in cb.check_bundle(mini)}
    assert "PATH_POLICY_SOURCE" in found                      # the mini bundle has no kit wheel (and is a test bundle, so this is only the release view of it)


def test_the_readme_tells_root_to_use_a_prefix_outside_root_and_says_what_doctor_checks():
    text = (ROOT / "bundle" / "README.md").read_text(encoding="utf-8")
    assert "As root (HOME=/root), use a prefix outside `/root`, for example `/opt/redevops-qa`" in text and "exit status 2" in text and "PROHIBITED_PATH" in text
    assert "`TMPDIR`" in text and "`HOME` and the evidence directory (`--out`) may be anywhere" in text and "read from the adapter kit inside the bundle" in text
    assert "`run` and `demo` make the same check and do not start otherwise" in text and "is not relaxed" in text
