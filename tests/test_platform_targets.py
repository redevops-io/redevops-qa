# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""One bundle per release platform (linux-x86_64, linux-arm64), each with its own locks: the builder's targets, the committed locks of both platforms, and the checker's refusal of a bundle
whose browser lock is for the other platform. Offline; no pinned tree, no browser."""
import json
import sys

import pytest

from bundle_helpers import ROOT, bb, cb

sys.path.insert(0, str(ROOT / "packages" / "qa-runner" / "src"))
from qa_runner import browser_pin as bp        # noqa: E402

X86, ARM = "linux-x86_64", "linux-arm64"


def third_party(platform):
    return json.loads(bb.third_party_lock_path(platform).read_text(encoding="utf-8"))


def browser(platform):
    return bb.browser_lock_path(platform).read_bytes()


def test_the_release_targets_are_the_two_platforms_and_the_first_one_keeps_its_file_names():
    assert sorted(bb.TARGETS) == [ARM, X86] and bb.TARGETS[X86] == bb.TARGET
    assert all(t == {"python": "3.12", "python_tag": "cp312", "platform": p} for p, t in bb.TARGETS.items())
    assert bb.third_party_lock_path().name == bb.third_party_lock_path(X86).name == "third-party.lock.json"
    assert bb.browser_lock_path().name == bb.browser_lock_path(X86).name == "browser.lock.json"
    assert bb.third_party_lock_path(ARM).name == "third-party.lock.linux-arm64.json" and bb.browser_lock_path(ARM).name == "browser.lock.linux-arm64.json"
    assert tuple(sorted(cb.RELEASE_PLATFORMS)) == tuple(sorted(bb.TARGETS)) == tuple(sorted(bp.TARGET_PLATFORMS))


def test_both_third_party_locks_pin_the_same_packages_at_the_same_versions_and_only_wheels_of_their_platform():
    x, a = third_party(X86), third_party(ARM)
    assert x["target"] == bb.TARGETS[X86] and a["target"] == bb.TARGETS[ARM] and x["direct"] == a["direct"]
    assert sorted((w["name"], w["version"], w["license"]) for w in x["wheels"]) == sorted((w["name"], w["version"], w["license"]) for w in a["wheels"])
    for lock, mine, other in ((x, "x86_64", "aarch64"), (a, "aarch64", "x86_64")):
        for w in lock["wheels"]:
            assert other not in w["filename"], w["filename"]
            assert mine in w["filename"] or w["filename"].endswith("-none-any.whl"), w["filename"]
    pure = lambda lock: {w["filename"]: w["sha256"] for w in lock["wheels"] if w["filename"].endswith("-none-any.whl")}
    assert pure(x) == pure(a), "a pure-Python wheel is the same file on both platforms"
    binary = lambda lock: {w["name"] for w in lock["wheels"] if not w["filename"].endswith("-none-any.whl")}
    assert binary(x) == binary(a) and {"greenlet", "playwright"} <= binary(a)


def test_pip_is_asked_for_the_wheels_of_the_target_platform_only():
    args = bb.pip_platform_args(bb.TARGETS[ARM])
    tags = [args[i + 1] for i, v in enumerate(args) if v == "--platform"]
    assert tags and all(t.endswith("aarch64") for t in tags) and "manylinux_2_17_aarch64" in tags
    assert all(t.endswith("x86_64") for t in bb.PIP_PLATFORMS_BY_TARGET[X86])
    with pytest.raises(bb.BuildError):
        bb.pip_platform_args({"python": "3.12", "python_tag": "cp312", "platform": "macos-arm64"})


def test_both_browser_locks_pin_the_same_chromium_for_the_same_playwright_from_different_archives():
    x, a = bp.parse_lock(browser(X86)), bp.parse_lock(browser(ARM))
    assert (x.platform, a.platform) == (X86, ARM)
    assert (x.playwright_version, x.browsers_json_sha256, x.revision, x.browser_version) == (a.playwright_version, a.browsers_json_sha256, a.revision, a.browser_version)
    assert [arch.name for arch in x.archives] == [arch.name for arch in a.archives] and x.dirs() == a.dirs()
    assert not {arch.sha256 for arch in x.archives} & {arch.sha256 for arch in a.archives} and x.tree_sha256 != a.tree_sha256
    assert all("arm64" in arch.file for arch in a.archives) and not any("arm64" in arch.file for arch in x.archives)
    assert all(u.startswith("https://") for arch in a.archives for u in arch.urls)


def test_a_lock_names_one_of_the_release_platforms_and_nothing_else():
    doc = json.loads(browser(ARM).decode("utf-8"))
    for target in ({"platform": "macos-arm64"}, {"platform": ARM, "python": "3.12"}, {}, ARM, None):
        bad = dict(doc, target=target)
        with pytest.raises(bp.LockError):
            bp.parse_lock(bp.render_lock(bad).encode("utf-8"))


@pytest.mark.parametrize("system, machine, want", [("Linux", "x86_64", X86), ("Linux", "AMD64", X86), ("Linux", "aarch64", ARM), ("Linux", "arm64", ARM), ("Darwin", "arm64", "darwin-arm64"),
                                                    ("Linux", "riscv64", "linux-riscv64")])
def test_the_host_is_named_in_the_locks_terms(system, machine, want):
    assert bp.host_platform(system, machine) == want


def test_the_checker_refuses_a_bundle_whose_browser_lock_is_for_the_other_platform(tmp_path):
    root = tmp_path / "b"
    root.mkdir()
    (root / "browser.lock.json").write_bytes(browser(ARM))
    lock = json.loads(browser(ARM).decode("utf-8"))
    import hashlib
    record = {"lock": "browser.lock.json", "lock_sha256": hashlib.sha256(browser(ARM)).hexdigest(), "archives": [{"file": a["file"], "sha256": a["sha256"], "size": a["size"]} for a in lock["archives"]],
              "tree_sha256": lock["tree_sha256"], "playwright": lock["playwright"]["version"], "revision": lock["browser"]["revision"], "browser_version": lock["browser"]["browser_version"]}
    mismatch = lambda findings: [f for f in findings if f.code == "BROWSER_LOCK" and "but the bundle is for" in f.message]
    same = cb._check_browser_lock(root, {"target": bb.TARGETS[ARM], "wheels": []}, record, True)
    other = cb._check_browser_lock(root, {"target": bb.TARGETS[X86], "wheels": []}, record, True)
    assert not mismatch(same), same
    assert len(mismatch(other)) == 1 and "linux-arm64" in mismatch(other)[0].message and "linux-x86_64" in mismatch(other)[0].message, other
