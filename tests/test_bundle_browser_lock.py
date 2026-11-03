# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The bundle's browser pin at build and check time: the builder refuses a lock that is not for the Playwright wheel it is bundling (revision, browser version, browsers.json digest, Playwright
version), carries the lock into the bundle and records it in BUNDLE.json; the standalone checker finds a lock that was edited, a record that was edited and a lock that is for another wheel."""
import hashlib
import json
import shutil
import zipfile

import pytest

import browser_helpers as bh
from bundle_helpers import bb, cb, resum, host_target, make_kit_wheel, make_wheel
from qr_browser_fake import REGISTRY, make_lock_doc

import qa_runner.browser_pin as bp


def playwright_wheel(directory, version="1.0.0", registry=REGISTRY):
    name = "playwright"
    dist = f"{name}-{version}"
    files = {"playwright/__init__.py": b"", "playwright/driver/package/browsers.json": registry,
             f"{dist}.dist-info/METADATA": f"Metadata-Version: 2.1\nName: playwright\nVersion: {version}\n".encode(),
             f"{dist}.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-manylinux1_x86_64\n"}
    files[f"{dist}.dist-info/RECORD"] = ("\n".join(bb.record_line(n, d) for n, d in sorted(files.items())) + f"\n{dist}.dist-info/RECORD,,\n").encode()
    out = directory / f"{dist}-py3-none-manylinux1_x86_64.whl"
    bb.write_wheel(out, files, 1_700_000_000)
    return out


def bundle_with(tmp_path, fake, *, lock_bytes=None, registry=REGISTRY, version="1.0.0"):
    wheels = tmp_path / "w"
    wheels.mkdir()
    entries = [bb.WheelEntry(make_wheel(wheels, "1.0"), "first-party", "test"), bb.WheelEntry(make_kit_wheel(wheels), "first-party", "test"),
               bb.WheelEntry(playwright_wheel(wheels, version, registry), "third-party", "Apache-2.0")]
    return bb.assemble(tmp_path / "out", name="redevops-qa-bundle-test", entries=entries, target=host_target(), epoch=1_700_000_000, label="", version="1.0", commit="0" * 40, pins_info=None,
                       licences_from={}, build_tools={}, readme_template=(bh.ROOT / "bundle" / "README.md").read_text(encoding="utf-8"), browser_lock=lock_bytes or fake.lock_bytes)


@pytest.fixture(scope="module")
def fake(tmp_path_factory):
    return bh.make_fake_browser(tmp_path_factory.mktemp("f"))


def findings(bundle):
    return [(f.code, f.message) for f in cb.check_bundle(bundle, allow_test_target=True)]


# ------------------------------------------------------------------------------------------------------------------------------ the builder
def test_the_builder_carries_the_lock_into_the_bundle_and_records_it(tmp_path, fake):
    bundle = bundle_with(tmp_path, fake)
    rec = json.loads((bundle / "BUNDLE.json").read_text(encoding="utf-8"))["browser"]
    assert (bundle / "browser.lock.json").read_bytes() == fake.lock_bytes and "browser.lock.json" in (bundle / "SHA256SUMS").read_text(encoding="utf-8")
    assert rec["lock_sha256"] == hashlib.sha256(fake.lock_bytes).hexdigest() and rec["shipped_in_bundle"] is False and rec["pinned_by_this_bundle"] is True and rec["fetched_at_install"] is True
    assert rec["revision"] == "1000" and rec["browser_version"] == "9.9.9.9" and rec["playwright"] == "1.0.0" and rec["tree_sha256"] == fake.lock.tree_sha256
    assert [a["file"] for a in rec["archives"]] == [a.file for a in fake.lock.archives] and all(len(a["sha256"]) == 64 for a in rec["archives"])
    assert rec["tree_files"] == len(fake.lock.files)
    assert any("operating system libraries" in n for n in rec["not_covered"]) and any("download host" in n for n in rec["not_covered"])
    assert cb.check_bundle(bundle, allow_test_target=True) == []


def test_the_readme_of_the_bundle_says_what_is_verified_and_what_is_not(tmp_path, fake):
    text = " ".join((bundle_with(tmp_path, fake) / "README.md").read_text(encoding="utf-8").split())            # the README is wrapped: compare words, not line breaks
    assert "not hashed" not in text and "recorded, not hashed" not in text
    for phrase in ("browser.lock.json", "before** it unpacks that archive", "<prefix>/browsers/.staging-<pid>", "SIGKILL or a power loss", "recorded in `INSTALL.json`", "source checkout there is no pin", "does not guard the files", "docs/QA_BROWSER_PIN.md", "the sha256 and the size of the three archives", "operating system libraries Chromium loads", "availability of the Playwright download host",
                   "a change made to the tree after a check", "not a signature from the browser's publisher", "Playwright 1.0.0", "revision 1000 (Chromium 9.9.9.9)"):
        assert phrase in text, phrase


@pytest.mark.parametrize("what,kw", [
    ("another revision", {"registry": json.dumps({"browsers": [{"name": "chromium", "revision": "1001", "browserVersion": "9.9.9.9"}]}).encode()}),
    ("another browser version", {"registry": json.dumps({"browsers": [{"name": "chromium", "revision": "1000", "browserVersion": "9.9.9.10"}]}).encode()}),
    ("another playwright version", {"version": "1.0.1"}),
    ("a registry with the same revision but other bytes", {"registry": json.dumps({"browsers": [{"name": "chromium", "revision": "1000", "browserVersion": "9.9.9.9"}], "x": 1}).encode()}),
])
def test_the_builder_refuses_a_lock_that_is_not_for_the_playwright_wheel_it_bundles(tmp_path, fake, what, kw):
    with pytest.raises(bb.BuildError, match="not for the Playwright wheel"):
        bundle_with(tmp_path, fake, **kw)


# ------------------------------------------------------------------------------------------------------------------------------ the checker
def test_the_checker_passes_a_consistent_bundle_and_requires_the_lock_file(tmp_path, fake):
    bundle = bundle_with(tmp_path, fake)
    assert findings(bundle) == []
    (bundle / "browser.lock.json").unlink()
    resum(bundle)
    assert ("MISSING_FILE", "a bundle has this file") in findings(bundle)


def edit_lock(bundle, edit):
    path = bundle / "browser.lock.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    edit(doc)
    path.write_text(json.dumps(doc), encoding="utf-8")
    resum(bundle)


@pytest.mark.parametrize("name,edit", [
    ("revision", lambda d: d["browser"].update({"revision": "1001"})),
    ("browser version", lambda d: d["browser"].update({"browser_version": "9.9.9.10"})),
    ("registry digest", lambda d: d["playwright"].update({"browsers_json_sha256": "0" * 64})),
    ("playwright version", lambda d: d["playwright"].update({"version": "1.0.1"})),
])
def test_the_checker_finds_a_lock_that_is_for_another_revision_or_wheel_than_the_one_in_the_bundle(tmp_path, fake, name, edit):
    bundle = bundle_with(tmp_path, fake)
    edit_lock(bundle, edit)
    assert any(c == "BROWSER_LOCK" for c, _m in findings(bundle)), name


def test_the_checker_finds_a_lock_whose_tree_was_edited_without_its_digest(tmp_path, fake):
    bundle = bundle_with(tmp_path, fake)
    edit_lock(bundle, lambda d: d["tree"]["files"]["ffmpeg-1000/ffmpeg-linux"].__setitem__(2, "1" * 64))
    assert any(c == "BROWSER_LOCK" and "not a well formed" in m for c, m in findings(bundle))


def test_the_checker_finds_a_lock_that_is_not_a_lock(tmp_path, fake):
    bundle = bundle_with(tmp_path, fake)
    (bundle / "browser.lock.json").write_text("{}")
    resum(bundle)
    assert any(c == "BROWSER_LOCK" for c, _m in findings(bundle))


def test_the_checker_finds_a_record_that_no_longer_matches_the_lock_file(tmp_path, fake):
    bundle = bundle_with(tmp_path, fake)
    edit_lock(bundle, lambda d: d["archives"][0].update({"size": d["archives"][0]["size"] + 1}))
    got = findings(bundle)
    assert any(c == "BROWSER_RECORD" for c, _m in got)


def test_a_release_bundle_needs_the_playwright_wheel_the_lock_is_checked_against(tmp_path, fake):
    wheels = tmp_path / "w"
    wheels.mkdir()
    entries = [bb.WheelEntry(make_wheel(wheels, "1.0"), "first-party", "test"), bb.WheelEntry(make_kit_wheel(wheels), "first-party", "test")]
    bundle = bb.assemble(tmp_path / "out", name="redevops-qa-bundle-test", entries=entries, target=host_target(), epoch=1_700_000_000, label="", version="1.0", commit="0" * 40, pins_info=None,
                         licences_from={}, build_tools={}, readme_template=(bh.ROOT / "bundle" / "README.md").read_text(encoding="utf-8"), browser_lock=fake.lock_bytes)
    assert cb.check_bundle(bundle, allow_test_target=True) == []
    assert ("BROWSER_LOCK", "a release bundle holds the Playwright wheel the lock is checked against") in [(f.code, f.message) for f in cb.check_bundle(bundle)]


def test_the_committed_lock_is_the_one_a_real_build_would_carry():
    lock = bh.ROOT / "bundle" / "browser.lock.json"
    parsed = bp.load_lock(lock)
    third = json.loads((bh.ROOT / "bundle" / "third-party.lock.json").read_text(encoding="utf-8"))
    assert f"playwright=={parsed.playwright_version}" in third["direct"]
    assert any(w["name"] == "playwright" and w["version"] == parsed.playwright_version for w in third["wheels"])
    rec = bb.browser_record(None, lock.read_bytes())
    assert rec["revision"] == parsed.revision and rec["lock_sha256"] == hashlib.sha256(lock.read_bytes()).hexdigest()


def test_the_maintainer_procedure_names_when_where_how_and_what_evidence_and_the_review_rule():
    text = " ".join((bh.ROOT / "docs" / "QA_BROWSER_PIN.md").read_text(encoding="utf-8").split())
    for fragment in ("Every time the pinned Playwright version changes", "the browser step fails closed", "Linux x86_64 host", "playwright install --dry-run chromium", "tools/make_browser_lock.py",
                     'cmp "$W/lock-1.json" "$W/lock-2.json"', "two independent fresh installs", "browser_pin.py urls --lock bundle/browser.lock.json", "CI run id", "SHA256SUMS", "read by a human reviewer",
                     "not edited by hand", "builder refuses a lock that is not for the Playwright wheel", "check_bundle.py", "not a publisher signature"):
        assert fragment in text, fragment
    assert "docs/QA_BROWSER_PIN.md" in (bh.ROOT / "bundle" / "README.md").read_text(encoding="utf-8")
