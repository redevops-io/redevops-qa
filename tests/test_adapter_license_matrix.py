# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The adapter licence matrix blocks unknown or incompatible redistributables (technical triage, not legal advice)."""
import copy
import hashlib
import re
import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_adapter_licenses", ROOT / "tools" / "check_adapter_licenses.py")
chk = importlib.util.module_from_spec(SPEC)
sys.modules["check_adapter_licenses"] = chk       # a dataclass needs its module registered
SPEC.loader.exec_module(chk)

MATRIX_PATH = ROOT / "third_party" / "adapter-license-matrix.yaml"
REAL = yaml.safe_load(MATRIX_PATH.read_text(encoding="utf-8"))
POLICY = REAL["policy"]


def fresh():
    return copy.deepcopy(REAL)


def comp(matrix, cid):
    return next(c for c in matrix["components"] if c["id"] == cid)


def codes(findings):
    return sorted({f.code for f in findings})


# ------------------------------------------------------------------------------------------ the real file
def test_the_matrix_in_the_repository_passes():
    assert chk.run(MATRIX_PATH, ROOT) == []


def test_every_adapter_framework_is_listed_with_an_exact_pin_and_a_licence_hash():
    frameworks = {c["id"]: c for c in REAL["components"] if c["kind"] in chk.PINNED_KINDS}
    for needed in ("selenium-python", "robotframework", "appium-server", "appium-python-client", "appium-uiautomator2-driver",
                   "appium-xcuitest-driver", "playwright-python"):
        assert needed in frameworks
    for c in frameworks.values():
        assert chk._EXACT.match(c["pinned_release"]) and len(c["license_file_sha256"]) == 64
        assert c["pinned_ref"] and f"/blob/" in c["license_url"]


def test_commercial_sdks_and_apple_toolchains_are_excluded_by_default():
    toolchains = [c for c in REAL["components"] if c["kind"] == "commercial_toolchain"]
    assert {c["id"] for c in toolchains} >= {"android-sdk-and-emulator", "apple-toolchain", "google-chrome"}
    for c in toolchains:
        assert c["redistribution"] == {**c["redistribution"], "status": "excluded_by_default", "default_enabled": False}
    xcui = comp(REAL, "appium-xcuitest-driver")
    assert xcui["redistribution"]["status"] == "excluded_by_default" and "apple-toolchain" in xcui["requires"]


def test_nothing_is_marked_redistributable_while_a_bundle_is_uninspected_or_a_licence_unreviewed():
    for c in REAL["components"]:
        if c["redistribution"]["status"] == "redistributable":
            assert c.get("bundled_deps_check", "inspected") == "inspected"
            assert chk.effective_rank(c, POLICY)[0] == chk.ALLOWED


def test_selenium_manager_crates_with_mpl_keep_selenium_out_of_the_redistributable_set():
    rank, why = chk.effective_rank(comp(REAL, "selenium-python"), POLICY)
    assert rank == chk.REVIEW and any("MPL-2.0" in w for w in why)


def test_robot_framework_report_assets_without_a_stated_licence_are_recorded_as_unverified():
    rank, why = chk.effective_rank(comp(REAL, "robotframework"), POLICY)
    assert rank == chk.UNVERIFIED and sum("unverified" in w for w in why) == 2


def test_the_playwright_pin_in_the_package_is_the_pin_in_the_matrix():
    art = comp(REAL, "playwright-python")["artifacts"][0]
    installs = [i for i in chk.gather_installs(ROOT) if i[1] == "playwright"]
    assert installs and all(i[2] == "==" + art["version"] for i in installs)


# ------------------------------------------------------------------------------------------ expressions
@pytest.mark.parametrize("expr,rank", [
    ("Apache-2.0", chk.ALLOWED), ("MIT OR Apache-2.0", chk.ALLOWED), ("(MIT OR Apache-2.0) AND Unicode-3.0", chk.REVIEW),
    ("MPL-2.0 OR MIT", chk.ALLOWED), ("MPL-2.0 AND MIT", chk.REVIEW), ("MIT AND PSF-2.0", chk.ALLOWED),
    ("Apache-2.0 WITH LLVM-exception", chk.ALLOWED), ("Apache-2.0 WITH Classpath-exception-2.0", chk.BLOCKED),
    ("GPL-2.0-only", chk.BLOCKED), ("MIT OR GPL-2.0-only", chk.ALLOWED), ("MIT AND GPL-2.0-only", chk.BLOCKED),
    ("LicenseRef-Proprietary-Whatever", chk.BLOCKED), ("LicenseRef-Commons-Clause-Thing", chk.BLOCKED),
    ("Something-Unknown-1.0", chk.BLOCKED), ("unverified", chk.UNVERIFIED), ("MIT OR unverified", chk.ALLOWED),
    ("MIT AND unverified", chk.UNVERIFIED), ("", chk.BLOCKED), ("MIT OR", chk.BLOCKED), ("(MIT", chk.BLOCKED),
    ("MIT or Apache-2.0", chk.BLOCKED), ("MIT; DROP", chk.BLOCKED),
])
def test_expression_ranking(expr, rank):
    assert chk.rank_of(expr, POLICY)[0] == rank


def test_a_non_string_licence_is_blocked():
    assert chk.rank_of(None, POLICY)[0] == chk.BLOCKED and chk.rank_of(["MIT"], POLICY)[0] == chk.BLOCKED


# ------------------------------------------------------------------------------------------ negative fixtures on the matrix
def test_an_unknown_licence_cannot_be_redistributable():
    m = fresh()
    c = comp(m, "appium-python-client")
    c["spdx"] = "Totally-Unknown-1.0"
    c["redistribution"]["status"] = "redistributable"
    assert "BLOCKED_LICENSE" in codes(chk.check_matrix(m))


def test_a_blocked_licence_may_only_be_excluded():
    m = fresh()
    c = comp(m, "appium-python-client")
    c["spdx"] = "SSPL-1.0"
    assert "BLOCKED_LICENSE" in codes(chk.check_matrix(m))
    c["redistribution"].update(status="excluded_by_default")
    assert "BLOCKED_LICENSE" not in codes(chk.check_matrix(m))


def test_a_commons_clause_licence_is_blocked_for_a_third_party_entry():
    m = fresh()
    c = comp(m, "appium-python-client")
    c["spdx"] = "LicenseRef-Commons-Clause-Apache-2.0"
    assert "BLOCKED_LICENSE" in codes(chk.check_matrix(m))


def test_a_review_licence_cannot_be_redistributable():
    m = fresh()
    c = comp(m, "appium-python-client")
    c["spdx"] = "MPL-2.0"
    c["redistribution"]["status"] = "redistributable"
    c["notices"] = [{"file": "NOTICE", "content": "x"}]
    assert "REDISTRIBUTING_UNAPPROVED_LICENSE" in codes(chk.check_matrix(m))


def test_redistributable_needs_verified_inspected_and_notices():
    m = fresh()
    c = comp(m, "appium-python-client")        # allowed licence, bundle inspected, but no notices recorded
    c["redistribution"]["status"] = "redistributable"
    assert codes(chk.check_matrix(m)) == ["MISSING_NOTICES"]
    c["notices"] = [{"file": "LICENSE", "content": "licence text"}]
    assert chk.check_matrix(m) == []
    c["bundled_deps_check"] = "not_inspected"
    assert codes(chk.check_matrix(m)) == ["UNVERIFIED_REDISTRIBUTION"]
    c["bundled_deps_check"] = "inspected"
    c["verification"]["status"] = "registry-metadata"
    assert {"UNVERIFIED_REDISTRIBUTION", "UNVERIFIED_LICENSE"} <= set(codes(chk.check_matrix(m)))


def test_an_unverified_entry_cannot_claim_optional_extra_or_redistributable():
    m = fresh()
    c = comp(m, "ci-pytest")
    c["verification"]["status"] = "unverified"
    c["redistribution"]["status"] = "optional_extra"
    assert "UNVERIFIED_REDISTRIBUTION" in codes(chk.check_matrix(m))


@pytest.mark.parametrize("cid", ["android-sdk-and-emulator", "apple-toolchain", "google-chrome"])
def test_a_commercial_toolchain_cannot_be_enabled_or_redistributed(cid):
    m = fresh()
    comp(m, cid)["redistribution"]["default_enabled"] = True
    assert "COMMERCIAL_ENABLED" in codes(chk.check_matrix(m))
    m = fresh()
    comp(m, cid)["redistribution"]["status"] = "redistributable"
    assert "COMMERCIAL_ENABLED" in codes(chk.check_matrix(m))


def test_a_commercial_toolchain_cannot_be_relabelled_with_a_permissive_licence():
    m = fresh()
    comp(m, "apple-toolchain")["spdx"] = "Apache-2.0"
    assert "COMMERCIAL_LICENSE_CLASS" in codes(chk.check_matrix(m))


def test_enabling_a_driver_by_default_is_refused_while_it_requires_an_excluded_toolchain():
    m = fresh()
    c = comp(m, "appium-xcuitest-driver")
    c["redistribution"].update(status="optional_extra", default_enabled=True)
    assert "ENABLED_BY_DEFAULT_NOT_APPROVED" in codes(chk.check_matrix(m))


def test_enabling_by_default_is_refused_for_an_unverified_bundle():
    m = fresh()
    comp(m, "robotframework")["redistribution"]["default_enabled"] = True
    assert "ENABLED_BY_DEFAULT_NOT_APPROVED" in codes(chk.check_matrix(m))


@pytest.mark.parametrize("version", ["4.52", ">=4.52.0", "4.52.*", "latest", "", "4.52.0 "])
def test_a_pin_must_be_an_exact_version(version):
    m = fresh()
    comp(m, "selenium-python")["pinned_release"] = version
    assert "UNPINNED" in codes(chk.check_matrix(m)) or version == "4.52"      # '4.52' is a valid exact version string


def test_an_artifact_version_must_equal_the_pinned_release():
    m = fresh()
    comp(m, "selenium-python")["artifacts"][0]["version"] = "4.51.0"
    assert "UNPINNED" in codes(chk.check_matrix(m))


def test_the_licence_url_must_point_at_the_pinned_tag_not_a_branch():
    m = fresh()
    comp(m, "robotframework")["license_url"] = "https://github.com/robotframework/robotframework/blob/master/LICENSE.txt"
    assert "MATRIX_SCHEMA" in codes(chk.check_matrix(m))


def test_a_framework_entry_needs_a_verified_licence_text():
    m = fresh()
    comp(m, "selenium-python")["verification"]["status"] = "registry-metadata"
    assert "UNVERIFIED_LICENSE" in codes(chk.check_matrix(m))


@pytest.mark.parametrize("key", ["project", "pinned_release", "pinned_ref", "spdx", "license_url", "license_file_sha256", "artifacts",
                                 "bundled_deps_check", "trademark", "redistribution", "verification", "notices", "adapter", "name"])
def test_a_missing_required_fact_is_reported(key):
    m = fresh()
    del comp(m, "robotframework")[key]
    assert chk.check_matrix(m)


def test_a_bad_licence_hash_is_reported():
    m = fresh()
    comp(m, "robotframework")["license_file_sha256"] = "abc"
    assert "MATRIX_SCHEMA" in codes(chk.check_matrix(m))


def test_bundled_deps_cannot_be_listed_for_an_uninspected_bundle():
    m = fresh()
    comp(m, "appium-server")["bundled_deps"] = [{"name": "x", "spdx": "MIT"}]
    assert "MATRIX_SCHEMA" in codes(chk.check_matrix(m))


def test_a_blocked_bundled_dependency_blocks_the_entry():
    m = fresh()
    comp(m, "robotframework")["bundled_deps"].append({"name": "x", "spdx": "GPL-2.0-only"})
    assert "BLOCKED_LICENSE" in codes(chk.check_matrix(m))


def test_a_dependency_group_member_with_a_blocked_licence_blocks_the_group():
    m = fresh()
    comp(m, "selenium-python-direct-deps")["members"][0]["spdx"] = "BUSL-1.1"
    assert "BLOCKED_LICENSE" in codes(chk.check_matrix(m))


def test_a_group_needs_members_with_a_constraint():
    m = fresh()
    comp(m, "selenium-python-direct-deps")["members"] = []
    assert "MISSING_FIELD" in codes(chk.check_matrix(m))
    m = fresh()
    del comp(m, "selenium-python-direct-deps")["members"][0]["version_constraint"]
    assert "MISSING_FIELD" in codes(chk.check_matrix(m))


def test_a_requires_must_name_a_known_component():
    m = fresh()
    comp(m, "appium-python-client")["requires"] = ["nope"]
    assert "MATRIX_SCHEMA" in codes(chk.check_matrix(m))


def test_duplicate_ids_and_unknown_kinds_are_rejected():
    m = fresh()
    m["components"].append(copy.deepcopy(m["components"][0]))
    assert "MATRIX_SCHEMA" in codes(chk.check_matrix(m))
    m = fresh()
    m["components"][0]["kind"] = "plugin"
    assert "MATRIX_SCHEMA" in codes(chk.check_matrix(m))


def test_wrong_schema_or_empty_matrix_is_rejected():
    assert codes(chk.check_matrix({"schema": "x", "version": 1})) == ["MATRIX_SCHEMA"]
    m = fresh()
    m["components"] = []
    assert "MATRIX_SCHEMA" in codes(chk.check_matrix(m))


def test_a_policy_identifier_in_two_lists_is_rejected():
    m = fresh()
    m["policy"]["review_spdx"].append("MIT")
    assert "MATRIX_SCHEMA" in codes(chk.check_matrix(m))


def test_enum_values_are_checked():
    for path, bad in [(("redistribution", "status"), "shipped"), (("verification", "status"), "probably"), (("trademark", "status"), "n/a")]:
        m = fresh()
        comp(m, "robotframework")[path[0]][path[1]] = bad
        assert "MATRIX_SCHEMA" in codes(chk.check_matrix(m)), path


# ------------------------------------------------------------------------------------------ what the repository installs
def _tree(tmp_path, pyproject_deps=(), extras=None, workflow_lines=(), package_json=None):
    pkg = tmp_path / "packages" / "qa-x"
    pkg.mkdir(parents=True)
    extra_text = "".join(f'{k} = {v!r}\n'.replace("'", '"') for k, v in (extras or {}).items())
    deps = "[" + ", ".join(f'"{d}"' for d in pyproject_deps) + "]"
    (pkg / "pyproject.toml").write_text(f'[project]\nname = "redevops-qa-x"\nversion = "0"\ndependencies = {deps}\n'
                                        f'[project.optional-dependencies]\n{extra_text}')
    if package_json is not None:
        import json
        (pkg / "package.json").write_text(json.dumps(package_json))
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "t.yml").write_text("jobs:\n  j:\n    steps:\n" + "".join(f"      - run: {line}\n" for line in workflow_lines))
    return tmp_path


def test_an_unknown_package_installed_by_an_adapter_package_is_reported(tmp_path):
    root = _tree(tmp_path, extras={"browser": ["somenewlib==1.0"]})
    found = chk.check_installs(REAL, chk.gather_installs(root))
    assert [(f.code, f.component) for f in found] == [("UNKNOWN_DEPENDENCY", "somenewlib")]


def test_an_unknown_package_installed_by_a_workflow_is_reported(tmp_path):
    root = _tree(tmp_path, workflow_lines=['python -m pip install "pytest>=8,<10" "evil-lib==1"'])
    found = chk.check_installs(REAL, chk.gather_installs(root))
    assert [(f.code, f.component) for f in found] == [("UNKNOWN_DEPENDENCY", "evil-lib")]


@pytest.mark.parametrize("line", ["pip install -r reqs.txt", "pip install --requirement=x.txt", "pip install -rreqs.txt", "pip install --constraint c.txt pytest", "pip install -e .", "pip install ./local",
                                  "pip install git+https://example.invalid/x.git", "pip install --index-url https://example.invalid/simple pytest",
                                  "pip install https://example.invalid/x.whl", "pip install $PKG"])
def test_an_install_the_scan_cannot_read_is_a_finding_not_a_pass(tmp_path, line):
    root = _tree(tmp_path, workflow_lines=[line])
    found = chk.check_installs(REAL, chk.gather_installs(root))
    assert codes(found) == ["UNSCANNABLE_INSTALL"], found


def test_a_continued_pip_install_line_is_scanned_as_one_command(tmp_path):
    root = _tree(tmp_path, workflow_lines=["|\n          pip install pytest \\\n            evil-lib==1"])
    found = chk.check_installs(REAL, chk.gather_installs(root))
    assert [(f.code, f.component) for f in found] == [("UNKNOWN_DEPENDENCY", "evil-lib")]


def test_names_are_normalised_before_they_are_matched(tmp_path):
    root = _tree(tmp_path, extras={"mobile": ["Appium_Python.Client==6.1.1", "SELENIUM==4.52.0"]})
    assert chk.check_installs(REAL, chk.gather_installs(root)) == []


def test_an_adapter_framework_without_an_exact_pin_is_reported(tmp_path):
    for spec in ("selenium>=4", "selenium", "selenium~=4.52.0", "selenium<5"):
        root = _tree(tmp_path / spec.replace("<", "lt").replace(">", "gt").replace("~", "t").replace("=", "e"), extras={"web": [spec]})
        assert codes(chk.check_installs(REAL, chk.gather_installs(root))) == ["UNPINNED"], spec


def test_a_pin_that_differs_from_the_matrix_is_reported(tmp_path):
    root = _tree(tmp_path, extras={"web": ["selenium==4.51.0"]})
    assert codes(chk.check_installs(REAL, chk.gather_installs(root))) == ["PIN_MISMATCH"]


def test_a_workflow_pin_that_differs_from_the_matrix_is_reported(tmp_path):
    root = _tree(tmp_path, workflow_lines=['pip install "robotframework==7.4"'])
    assert codes(chk.check_installs(REAL, chk.gather_installs(root))) == ["PIN_MISMATCH"]


def test_ranges_are_fine_for_dependencies_that_are_not_adapter_frameworks(tmp_path):
    root = _tree(tmp_path, extras={"web": ["urllib3>=2,<3", "certifi"]})
    assert chk.check_installs(REAL, chk.gather_installs(root)) == []


def test_the_repositorys_own_packages_are_not_third_party(tmp_path):
    root = _tree(tmp_path, pyproject_deps=["redevops-qa-bridge"])
    assert chk.check_installs(REAL, chk.gather_installs(root)) == []


def test_npm_dependencies_are_matched_and_must_be_exact(tmp_path):
    root = _tree(tmp_path, package_json={"dependencies": {"appium": "3.9.0", "left-pad": "1.0.0"}})
    found = chk.check_installs(REAL, chk.gather_installs(root))
    assert [(f.code, f.component) for f in found] == [("UNKNOWN_DEPENDENCY", "left-pad")]
    root = _tree(tmp_path / "b", package_json={"dependencies": {"appium": "^3.9.0"}})
    assert codes(chk.check_installs(REAL, chk.gather_installs(root))) == ["UNPINNED"]


def test_run_combines_the_matrix_and_the_install_scan(tmp_path):
    root = _tree(tmp_path, extras={"browser": ["somenewlib==1.0"]})
    found = chk.run(MATRIX_PATH, root)
    assert codes(found) == ["UNKNOWN_DEPENDENCY"]


def test_an_unreadable_matrix_is_a_failure(tmp_path):
    assert codes(chk.run(tmp_path / "missing.yaml", tmp_path)) == ["MATRIX_UNREADABLE"]
    bad = tmp_path / "bad.yaml"
    bad.write_text("- a\n- b\n")
    assert codes(chk.run(bad, tmp_path)) == ["MATRIX_UNREADABLE"]
    bad.write_text("a: [unclosed\n")
    assert codes(chk.run(bad, tmp_path)) == ["MATRIX_UNREADABLE"]


# ------------------------------------------------------------------------------------------ upstream verification (fake fetcher only)
def test_upstream_hashes_match_when_the_fetcher_returns_the_recorded_text():
    texts = {}

    def fetch(url):
        return texts[url]

    m = fresh()
    for c in m["components"]:
        if c["kind"] in chk.PINNED_KINDS:
            body = f"licence of {c['id']}".encode()
            texts[chk.raw_url(c["license_url"])] = body
            c["license_file_sha256"] = hashlib.sha256(body).hexdigest()
            for n in c["notices"]:
                if n.get("url"):
                    nb = f"notice of {c['id']}".encode()
                    texts[chk.raw_url(n["url"])] = nb
                    n["sha256"] = hashlib.sha256(nb).hexdigest()
    assert chk.verify_upstream(m, fetch) == []


def test_an_upstream_change_or_an_unreachable_upstream_fails():
    m = fresh()
    assert "UPSTREAM_HASH_MISMATCH" in codes(chk.verify_upstream(m, lambda url: b"changed"))

    def down(url):
        raise OSError("offline")

    assert set(codes(chk.verify_upstream(m, down))) == {"UPSTREAM_UNREACHABLE"}


def test_raw_url_is_derived_from_the_blob_url_and_refuses_other_hosts():
    assert chk.raw_url("https://github.com/o/r/blob/v1/LICENSE") == "https://raw.githubusercontent.com/o/r/v1/LICENSE"
    with pytest.raises(ValueError):
        chk.raw_url("https://example.com/o/r/blob/v1/LICENSE")


# ------------------------------------------------------------------------------------------ command line
def test_the_command_line_exits_zero_on_the_real_matrix_and_one_on_a_bad_one(tmp_path, capsys):
    assert chk.main(["x"]) == 0
    assert "OK" in capsys.readouterr().out
    m = fresh()
    comp(m, "apple-toolchain")["redistribution"]["default_enabled"] = True
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump(m))
    assert chk.main(["x", "--matrix", str(bad)]) == 1
    assert "COMMERCIAL_ENABLED" in capsys.readouterr().out


# ------------------------------------------------------------------------------------------ what the pinned bundle ships (bundle/third-party.lock.json)
import json  # noqa: E402

LOCK = json.loads((ROOT / "bundle" / "third-party.lock.json").read_text(encoding="utf-8"))


def lock_findings(matrix=None, lock=None):
    return chk.check_bundle_lock(matrix or fresh(), lock or copy.deepcopy(LOCK))


def shipped_owner(matrix, name):
    return next(c for c in matrix["components"] for w in c.get("shipped_wheels") or [] if w["name"] == name)


def test_every_wheel_of_the_bundle_lock_is_recorded_in_the_matrix_with_its_digest_and_a_shipping_status():
    assert lock_findings() == []
    names = {w["name"] for w in LOCK["wheels"]}
    assert names == {"playwright", "robotframework", "pyyaml", "greenlet", "pyee", "typing-extensions"}
    for name in names:
        owner = shipped_owner(REAL, name)
        assert owner["redistribution"]["status"] in chk.SHIPPING


def test_every_shipped_entry_is_private_staging_only_and_clears_nothing_for_public_distribution():
    for name in {w["name"] for w in LOCK["wheels"]}:
        red = shipped_owner(REAL, name)["redistribution"]
        assert red["status"] == "staged_unmodified" and red["public_distribution"] == "owner_decision_required"
        assert "PRIVATE STAGING ONLY" in red["reason"] and "owner decision" in red["reason"] and red["default_enabled"] is False
    assert not [c for c in REAL["components"] if c["redistribution"]["status"] == "redistributable"]      # nothing here claims clearance


def test_the_playwright_entry_describes_the_node_runtime_the_inlined_npm_packages_and_libwebp_it_ships():
    pw = comp(REAL, "playwright-python")
    assert pw["bundled_deps_check"] == "inspected"
    text = json.dumps(pw)
    for needle in ("playwright/driver/node", "playwright/driver/LICENSE", "79 npm packages", "utilsBundle.js.LICENSE", "serverRegistry.js.LICENSE", "libwebp", "webp_codec.LICENSE", "NOTICE", "ThirdPartyNotices.txt"):
        assert needle in text, needle
    paths = {lf["path"] for lf in pw["shipped_wheels"][0]["license_files"]}
    assert {"playwright/driver/LICENSE", "playwright/driver/package/NOTICE", "playwright/driver/package/lib/utilsBundle.js.LICENSE", "playwright/driver/package/lib/webp_codec.LICENSE"} <= paths
    assert any(d["spdx"] == "unverified" for d in pw["bundled_deps"])          # the components nobody classified one by one are not claimed


def test_the_two_robot_assets_of_unestablished_licence_are_recorded_unverified_with_their_exact_paths():
    rb = comp(REAL, "robotframework")
    unverified = [d for d in rb["bundled_deps"] if d["spdx"] == "unverified"]
    assert len(unverified) == 2
    joined = json.dumps(unverified)
    assert "robot/htmldata/lib/jquery.min.js" in joined and "robot/htmldata/lib/jquery.tablesorter.min.js" in joined and "UNVERIFIED" in joined
    assert all(re.search(r"sha256 [0-9a-f]{64}", d["name"]) for d in rb["bundled_deps"])
    assert "PRIVATE STAGING ONLY" in rb["redistribution"]["reason"] and "UNVERIFIED" in rb["redistribution"]["reason"]


def test_pyyaml_is_no_longer_described_as_never_shipped_and_typing_extensions_is_listed():
    assert "never shipped" not in json.dumps(comp(REAL, "ci-pyyaml"))
    assert "ALSO shipped in the bundle" in json.dumps(comp(REAL, "ci-pyyaml"))
    assert comp(REAL, "pyyaml-shipped")["redistribution"]["status"] == "staged_unmodified"
    assert comp(REAL, "typing-extensions-shipped")["shipped_wheels"][0]["name"] == "typing-extensions"


def test_a_locked_wheel_that_the_matrix_does_not_record_is_found_and_so_is_a_recorded_one_the_lock_does_not_hold():
    m = fresh()
    owner = shipped_owner(m, "typing-extensions")
    owner["shipped_wheels"] = [w for w in owner["shipped_wheels"] if w["name"] != "typing-extensions"] or None
    if owner["shipped_wheels"] is None:
        del owner["shipped_wheels"]
    assert "UNLISTED_SHIPPED_WHEEL" in codes(lock_findings(m))
    lock = copy.deepcopy(LOCK)
    lock["wheels"] = [w for w in lock["wheels"] if w["name"] != "pyee"]
    assert "STALE_SHIPPED_WHEEL" in codes(lock_findings(lock=lock))


@pytest.mark.parametrize("mutation,expected", [
    (lambda w: w.__setitem__("sha256", "0" * 64), "SHIPPED_WHEEL_MISMATCH"),
    (lambda w: w.__setitem__("file", "other.whl"), "SHIPPED_WHEEL_MISMATCH"),
    (lambda w: w.__setitem__("license_declared", "GPL-3.0-only"), "SHIPPED_LICENSE_DRIFT"),
])
def test_a_recorded_wheel_that_differs_from_the_lock_is_found(mutation, expected):
    m = fresh()
    mutation(shipped_owner(m, "greenlet")["shipped_wheels"][0])
    assert expected in codes(lock_findings(m))


def test_a_new_version_in_the_lock_without_a_matrix_update_is_found():
    lock = copy.deepcopy(LOCK)
    next(w for w in lock["wheels"] if w["name"] == "pyyaml")["version"] = "6.0.4"
    assert {"UNLISTED_SHIPPED_WHEEL", "STALE_SHIPPED_WHEEL"} <= set(codes(lock_findings(lock=lock)))


@pytest.mark.parametrize("status", ["optional_extra", "excluded_by_default", "unverified"])
def test_a_shipped_wheel_under_any_other_status_is_found_by_both_checks(status):
    m = fresh()
    c = shipped_owner(m, "robotframework")
    c["redistribution"]["status"] = status
    if status == "unverified":
        c["verification"]["status"] = "unverified"
    assert "SHIPPED_NOT_STAGED" in codes(lock_findings(m)) and "SHIPPED_NOT_STAGED" in codes(chk.check_matrix(m))


def test_a_staged_entry_that_claims_clearance_or_drops_its_caveat_is_found():
    for mutate, code in ((lambda r: r.__setitem__("public_distribution", "cleared"), "STAGED_PUBLIC_CLAIM"),
                         (lambda r: r.pop("public_distribution"), "STAGED_PUBLIC_CLAIM"),
                         (lambda r: r.__setitem__("reason", "shipped unmodified"), "STAGED_PUBLIC_CLAIM"),
                         (lambda r: r.__setitem__("default_enabled", True), "ENABLED_BY_DEFAULT_NOT_APPROVED")):
        m = fresh()
        mutate(comp(m, "playwright-python")["redistribution"])
        assert code in codes(chk.check_matrix(m)), code


def test_a_staged_entry_needs_the_wheel_read_notices_recorded_and_the_bundle_inspected():
    m = fresh()
    comp(m, "playwright-python")["bundled_deps_check"] = "not_inspected"
    comp(m, "playwright-python")["bundled_deps"] = []
    assert "UNVERIFIED_STAGING" in codes(chk.check_matrix(m))
    m = fresh()
    comp(m, "pyyaml-shipped")["verification"]["status"] = "registry-metadata"
    assert "UNVERIFIED_STAGING" in codes(chk.check_matrix(m)) or "UNVERIFIED_REDISTRIBUTION" in codes(chk.check_matrix(m))
    m = fresh()
    comp(m, "pyyaml-shipped")["notices"] = []
    assert "MISSING_NOTICES" in codes(chk.check_matrix(m))
    m = fresh()
    del comp(m, "pyyaml-shipped")["shipped_wheels"]
    assert "MISSING_FIELD" in codes(chk.check_matrix(m))


def test_a_shipped_wheel_record_without_its_licence_files_or_digest_is_found():
    for key in ("license_files", "sha256", "file", "version"):
        m = fresh()
        del comp(m, "pyyaml-shipped")["shipped_wheels"][0][key]
        assert "MISSING_FIELD" in codes(chk.check_matrix(m)), key
    m = fresh()
    comp(m, "pyyaml-shipped")["shipped_wheels"][0]["license_files"] = [{"path": "x"}]
    assert "MATRIX_SCHEMA" in codes(chk.check_matrix(m))


def test_a_staged_entry_whose_licence_is_blocked_is_still_refused():
    m = fresh()
    comp(m, "pyyaml-shipped")["members"][0]["spdx"] = "SSPL-1.0"
    assert "BLOCKED_LICENSE" in codes(chk.check_matrix(m))


def test_run_checks_the_lock_of_the_repository_and_reports_a_finding_for_an_unreadable_one(tmp_path):
    assert chk.run(MATRIX_PATH, ROOT) == []
    (tmp_path / "bundle").mkdir()
    (tmp_path / "bundle" / "third-party.lock.json").write_text("{")
    (tmp_path / "packages").mkdir()
    assert "BUNDLE_LOCK_UNREADABLE" in codes(chk.run(MATRIX_PATH, tmp_path))
