# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import shutil
from pathlib import Path

import pytest

from redevops_qa_bridge import deps, pins as pins_mod
from redevops_qa_bridge.errors import DependencyUnavailable, PinMismatch, PinsInvalid

@pytest.fixture(autouse=True)
def _no_pin_set_in_the_environment(monkeypatch):
    monkeypatch.delenv(pins_mod.PIN_SET_ENV, raising=False)


HEX40 = "a" * 40
HEX64 = "b" * 64


def _dep_block(prefix, repo, extra="", commit=HEX40, tag="", temp_pin="true", base_pin=False):
    head = f'''
[sets.{prefix}.{repo[0]}]
repo = "r/{repo[0]}"
version = "1"
tag = "{tag}"
temp_pin = {temp_pin}
commit = "{commit}"
package = "pkg_{repo[1]}"
source_path = "{repo[1]}"
distribution_paths = ["pkg_{repo[1]}"]
distribution_sha256 = "{HEX64}"
'''
    if base_pin:
        head += f'base_pin = "{HEX40}"\n'
    return head + extra + f'''
[sets.{prefix}.{repo[0]}.vector_files]
"golden/v.json" = "{HEX64}"
'''


def _write_pins(tmp_path, *, contracts_extra="", harness_extra="", contracts_commit=HEX40, temp_pin="true", tag="",
                default_set="a", extra_sets=()):
    text = f'''
schema = "redevops-qa/pins"
version = 2
default_set = "{default_set}"
'''
    for name in ("a", *extra_sets):
        text += _dep_block(name, ("contracts", "c"), contracts_extra, contracts_commit, tag, temp_pin)
        text += _dep_block(name, ("harness_qa", "h"), harness_extra, HEX40, "", "true", base_pin=True)
    path = tmp_path / "pins.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_the_repository_pins_file_has_both_sets_and_c4_is_the_default():
    c3 = pins_mod.load_pins(pin_set="c3")
    c4 = pins_mod.load_pins(pin_set="c4")
    assert c3.available_sets == c4.available_sets == ("c3", "c4")
    assert c3.contracts.commit == "13e00f23da74782af091aec607c47358e9814fc6"
    assert c4.contracts.commit == "15a6f6cf79f22d27a920f59969dfeb2732a2d1cb"
    assert c3.harness_qa.commit == c4.harness_qa.commit
    assert "golden/qa_canon_vectors_addendum.json" in c4.contracts.vector_files
    assert "golden/qa_canon_vectors_addendum.json" not in c3.contracts.vector_files
    assert c3.pin_set == "c3" and c4.pin_set == "c4"
    assert c3.contracts.vector_files["golden/qa.json"] == c4.contracts.vector_files["golden/qa.json"]


def test_the_default_set_is_c4(monkeypatch):
    monkeypatch.delenv(pins_mod.PIN_SET_ENV, raising=False)
    assert pins_mod.load_pins().pin_set == "c4"


def test_the_pin_set_environment_variable_selects_a_set(monkeypatch):
    monkeypatch.setenv(pins_mod.PIN_SET_ENV, "c3")
    assert pins_mod.load_pins().pin_set == "c3"
    assert pins_mod.load_pins(pin_set="c4").pin_set == "c4"       # an explicit argument wins


def test_an_unknown_pin_set_is_refused():
    with pytest.raises(PinsInvalid):
        pins_mod.load_pins(pin_set="nope")


def test_the_repository_pins_file_loads(pins):
    assert pins.contracts.commit in {"13e00f23da74782af091aec607c47358e9814fc6", "15a6f6cf79f22d27a920f59969dfeb2732a2d1cb"}
    assert pins.harness_qa.base_pin == "6b8ba3a596a5e2caf0fdf009f2af013517591662"
    assert pins.contracts.temp_pin and pins.harness_qa.temp_pin
    assert "golden/qa.json" in pins.contracts.vector_files


def test_a_minimal_valid_file_loads(tmp_path, monkeypatch):
    for name in pins_mod.PATH_ENV.values():
        monkeypatch.delenv(name, raising=False)
    loaded = pins_mod.load_pins(_write_pins(tmp_path))
    assert loaded.contracts.resolved_path in {(tmp_path / "c").resolve(), tmp_path / "c"}
    assert loaded.pin_set == "a"


@pytest.mark.parametrize("kwargs", [
    {"contracts_commit": "abc123"}, {"contracts_commit": "A" * 40}, {"tag": "v1.2.3"},        # TEMP-PIN with a tag
    {"temp_pin": "false"},                                                                  # release pin without a tag
])
def test_invalid_pins_are_refused(tmp_path, kwargs):
    with pytest.raises(PinsInvalid) as info:
        pins_mod.load_pins(_write_pins(tmp_path, **kwargs))
    assert info.value.code == "PINS_INVALID"


def test_missing_and_malformed_files_are_refused(tmp_path):
    with pytest.raises(PinsInvalid):
        pins_mod.load_pins(tmp_path / "nope.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("this is = = not toml", encoding="utf-8")
    with pytest.raises(PinsInvalid):
        pins_mod.load_pins(bad)
    wrong = tmp_path / "wrong.toml"
    wrong.write_text('schema = "other"\nversion = 1\n', encoding="utf-8")
    with pytest.raises(PinsInvalid):
        pins_mod.load_pins(wrong)


def test_the_path_environment_override_applies(tmp_path, monkeypatch):
    monkeypatch.delenv("QA_PIN_HARNESS_QA_PATH", raising=False)
    monkeypatch.setenv("QA_PIN_CONTRACTS_PATH", str(tmp_path / "elsewhere"))
    loaded = pins_mod.load_pins(_write_pins(tmp_path))
    assert loaded.contracts.resolved_path == tmp_path / "elsewhere"
    assert loaded.harness_qa.resolved_path.name == "h"


def test_a_temp_pin_is_forbidden_on_main(tmp_path):
    loaded = pins_mod.load_pins(_write_pins(tmp_path))
    with pytest.raises(PinMismatch):
        pins_mod.check_forbid_temp_pin(loaded)
    released = pins_mod.load_pins(_write_pins(tmp_path, temp_pin="false", tag="v0.3.15"))
    with pytest.raises(PinMismatch):       # the harness is still a TEMP-PIN
        pins_mod.check_forbid_temp_pin(released)


def test_a_second_set_in_one_file_is_selectable(tmp_path, monkeypatch):
    monkeypatch.delenv(pins_mod.PIN_SET_ENV, raising=False)
    path = _write_pins(tmp_path, extra_sets=("b",), default_set="a")
    assert pins_mod.load_pins(path, "b").pin_set == "b"
    assert pins_mod.load_pins(path).pin_set == "a"
    with pytest.raises(PinsInvalid):
        pins_mod.load_pins(_write_pins(tmp_path, default_set="zz"))


def test_the_github_output_mode_prints_the_commits(tmp_path, capsys):
    path = _write_pins(tmp_path)
    assert pins_mod.main(["--file", str(path), "--github-output"]) == 0
    out = capsys.readouterr().out
    assert f"contracts_commit={HEX40}" in out and "pin_set=a" in out and "harness_qa_path=h" in out


def test_the_pins_cli_reports_ok_and_failure(tmp_path, capsys):
    good = _write_pins(tmp_path)
    assert pins_mod.main(["--file", str(good)]) == 0
    assert pins_mod.main(["--file", str(good), "--forbid-temp-pin"]) == 1
    assert pins_mod.main(["--file", str(tmp_path / "missing.toml")]) == 1


# -- tree digests and pin problems -----------------------------------------------------------------------------------------

def _tree(root: Path, body="x = 1\n", vector="{}"):
    (root / "pkg_c").mkdir(parents=True, exist_ok=True)
    (root / "pkg_c" / "__init__.py").write_text(body, encoding="utf-8")
    (root / "golden").mkdir(exist_ok=True)
    (root / "golden" / "v.json").write_text(vector, encoding="utf-8")


def test_tree_digest_is_stable_ignores_bytecode_and_changes_with_content(tmp_path):
    _tree(tmp_path)
    first = pins_mod.tree_digest(tmp_path, ("pkg_c",))
    (tmp_path / "pkg_c" / "__pycache__").mkdir()
    (tmp_path / "pkg_c" / "__pycache__" / "x.cpython-313.pyc").write_bytes(b"junk")
    assert pins_mod.tree_digest(tmp_path, ("pkg_c",)) == first
    (tmp_path / "pkg_c" / "__init__.py").write_text("x = 2\n", encoding="utf-8")
    assert pins_mod.tree_digest(tmp_path, ("pkg_c",)) != first
    with pytest.raises(PinMismatch):
        pins_mod.tree_digest(tmp_path, ("absent",))


def test_pin_problems_name_every_difference(tmp_path):
    _tree(tmp_path)
    digest = pins_mod.tree_digest(tmp_path, ("pkg_c",))
    vec = pins_mod.sha256_file(tmp_path / "golden" / "v.json")
    base = pins_mod.load_pins(_write_pins(tmp_path, contracts_extra='addendum_globs = ["golden/*addendum*.json"]'))
    import dataclasses
    dep = dataclasses.replace(base.contracts, resolved_path=tmp_path, distribution_sha256=digest,
                              vector_files={"golden/v.json": vec})
    assert deps.pin_problems(dep) == []
    (tmp_path / "golden" / "v_addendum.json").write_text("{}", encoding="utf-8")
    assert [c for c, _ in deps.pin_problems(dep)] == ["PIN_VECTOR_UNLISTED"]
    (tmp_path / "golden" / "v.json").write_text('{"changed": 1}', encoding="utf-8")
    codes = {c for c, _ in deps.pin_problems(dep)}
    assert {"PIN_VECTOR_MISMATCH", "PIN_VECTOR_UNLISTED"} <= codes
    (tmp_path / "pkg_c" / "__init__.py").write_text("changed = 1\n", encoding="utf-8")
    assert "PIN_DIGEST_MISMATCH" in {c for c, _ in deps.pin_problems(dep)}
    missing = dataclasses.replace(dep, resolved_path=tmp_path / "gone")
    assert [c for c, _ in deps.pin_problems(missing)] == ["PIN_SOURCE_MISSING"]


def test_the_repository_pins_match_the_trees_on_disk(pins):
    for dep in (pins.contracts, pins.harness_qa):
        assert deps.pin_problems(dep) == [], dep.name
    deps.verify_pins(pins)


def test_verify_pins_fails_when_the_package_comes_from_somewhere_else(pins, tmp_path):
    import dataclasses
    elsewhere = dataclasses.replace(pins.contracts, resolved_path=tmp_path)
    assert [c for c, _ in deps.imported_from_pin(elsewhere)] == ["PIN_PATH_MISMATCH"]


# -- dependency availability ------------------------------------------------------------------------------------------------

def test_an_unimportable_dependency_is_a_failure_not_a_skip(monkeypatch):
    monkeypatch.setattr(deps, "_MODULES", {"contracts": "no_such_contracts_module", "harness_qa": "agent_harness.qa"})
    with pytest.raises(DependencyUnavailable) as info:
        deps.contracts_qa()
    assert info.value.code == "DEPENDENCY_UNAVAILABLE" and info.value.details["dependency"] == "contracts"
    assert deps.availability() == {"contracts": False, "harness_qa": True}


def test_the_harness_python_floor_guard_counts_as_unavailable(monkeypatch):
    monkeypatch.setattr(deps, "_MODULES", {"contracts": "runtime_contracts.qa", "harness_qa": "no_such_harness"})
    assert deps.availability() == {"contracts": True, "harness_qa": False}


# -- verify_trees: what CI runs after fetching the pinned upstreams by commit --------------------------------------------------

def _checkout(root, package, vector):
    from receipt_helpers import git, make_repo
    make_repo(root)
    (root / package).mkdir()
    (root / package / "__init__.py").write_text("x = 1\n")
    (root / vector).parent.mkdir(parents=True, exist_ok=True)
    (root / vector).write_text("{}\n")
    (root / ".gitignore").write_text("__pycache__/\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "tree")
    return git(root, "rev-parse", "HEAD")


def _pins_for(tmp_path):
    c, h = tmp_path / "c", tmp_path / "h"
    c_commit, h_commit = _checkout(c, "pkg_c", "golden/v.json"), _checkout(h, "pkg_h", "golden/v.json")
    text = _write_pins(tmp_path).read_text()
    text = text.replace("a" * 40, c_commit, 1)
    text = text.replace('commit = "' + "a" * 40 + '"', 'commit = "' + h_commit + '"', 1)
    vec = pins_mod.sha256_file(c / "golden" / "v.json")
    text = text.replace("b" * 64, vec)
    path = tmp_path / "pins.toml"
    path.write_text(text)
    loaded = pins_mod.load_pins(path, "a")
    import dataclasses
    return dataclasses.replace(
        loaded,
        contracts=dataclasses.replace(loaded.contracts, commit=c_commit, resolved_path=c, distribution_sha256=pins_mod.tree_digest(c, ("pkg_c",))),
        harness_qa=dataclasses.replace(loaded.harness_qa, commit=h_commit, resolved_path=h, distribution_sha256=pins_mod.tree_digest(h, ("pkg_h",)))), c, h


def test_verify_trees_accepts_clean_checkouts_at_the_pinned_commits(tmp_path):
    loaded, c, h = _pins_for(tmp_path)
    pins_mod.verify_trees(loaded, require_git=True)


def test_verify_trees_requires_a_git_checkout_when_asked(tmp_path):
    loaded, c, h = _pins_for(tmp_path)
    import shutil
    shutil.rmtree(c / ".git")
    with pytest.raises(PinMismatch, match="PIN_NOT_A_CHECKOUT"):
        pins_mod.verify_trees(loaded, require_git=True)
    pins_mod.verify_trees(loaded)           # without the requirement the digests alone decide


def test_verify_trees_fails_on_a_different_head(tmp_path):
    from receipt_helpers import git
    loaded, c, h = _pins_for(tmp_path)
    (c / "other.txt").write_text("x")
    git(c, "add", "other.txt")
    git(c, "commit", "-q", "-m", "moved")
    with pytest.raises(PinMismatch, match="PIN_COMMIT_MISMATCH"):
        pins_mod.verify_trees(loaded, require_git=True)


def test_verify_trees_fails_on_a_dirty_checkout(tmp_path):
    loaded, c, h = _pins_for(tmp_path)
    (h / "stray.txt").write_text("x")
    with pytest.raises(PinMismatch, match="PIN_TREE_DIRTY"):
        pins_mod.verify_trees(loaded, require_git=True)


def test_verify_trees_fails_on_a_changed_tree_even_when_the_head_is_right(tmp_path):
    loaded, c, h = _pins_for(tmp_path)
    (c / "pkg_c" / "__init__.py").write_text("x = 2\n")
    with pytest.raises(PinMismatch) as info:
        pins_mod.verify_trees(loaded, require_git=True)
    assert "PIN_DIGEST_MISMATCH" in str(info.value)


def test_verify_trees_fails_on_a_missing_tree(tmp_path):
    import dataclasses
    loaded, c, h = _pins_for(tmp_path)
    gone = dataclasses.replace(loaded, contracts=dataclasses.replace(loaded.contracts, resolved_path=tmp_path / "absent"))
    with pytest.raises(PinMismatch, match="PIN_SOURCE_MISSING"):
        pins_mod.verify_trees(gone, require_git=True)


def test_the_repository_pins_match_the_trees_on_disk_through_verify_trees(pins):
    pins_mod.verify_trees(pins)
    with pytest.raises(PinMismatch, match="PIN_NOT_A_CHECKOUT"):
        pins_mod.verify_trees(pins, require_git=True)       # the read-only snapshots used here are not checkouts


def test_the_cli_verify_trees_flag(tmp_path, capsys, monkeypatch):
    _pins_for(tmp_path)
    for name in pins_mod.PATH_ENV.values():
        monkeypatch.delenv(name, raising=False)
    # without source overrides the default paths (tmp/c, tmp/h) are the checkouts, but the digests in the file are placeholders
    assert pins_mod.main(["--file", str(tmp_path / "pins.toml"), "--verify-trees", "--require-git"]) == 1
    assert "FAIL PIN_MISMATCH" in capsys.readouterr().out
