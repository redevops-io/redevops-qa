# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The manifest loader: safe parsing, refusals, determinism, read-only behaviour."""
import json
import os
from pathlib import Path

import pytest

from qc_fixtures import deployment, dump, good_set, reference, write_tree
from redevops_qa_checks import manifests as M
from redevops_qa_checks.errors import LimitExceeded, PathRefused


def codes(ms):
    return sorted(e.code for e in ms.errors)


def test_a_tree_loads_in_sorted_path_order(case_root):
    ms = M.load_tree(case_root)
    assert [m.source for m in ms.manifests] == sorted(m.source for m in ms.manifests)
    assert ms.errors == () and len(ms.manifests) == 9


def test_multi_document_files_and_list_kinds_expand():
    text = "apiVersion: v1\nkind: List\nitems:\n- {apiVersion: v1, kind: Namespace, metadata: {name: a}}\n- {apiVersion: v1, kind: Namespace, metadata: {name: b}}\n---\napiVersion: v1\nkind: Namespace\nmetadata: {name: c}\n"
    ms = M.load_text(text, "x.yaml")
    assert [m.name for m in ms.manifests] == ["a", "b", "c"]


def test_json_manifests_load():
    ms = M.load_text(json.dumps({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "n"}}), "x.json")
    assert ms.manifests[0].kind == "Namespace"


@pytest.mark.parametrize("text,code", [
    ("a: &x 1\nb: *x\n", "YAML_REFUSED"),                                  # alias
    ("a: 1\na: 2\n", "YAML_REFUSED"),                                      # duplicate key
    ("a: !!python/object/apply:os.system [echo]\n", "YAML_REFUSED"),       # unsafe tag
    ("a: [1, 2\n", "YAML_REFUSED"),                                        # syntax error
    ("- 1\n- 2\n", "NOT_A_MAPPING"),
    ("x: .nan\n", "NON_FINITE_NUMBER"),
])
def test_unsafe_or_malformed_yaml_is_an_error_entry_not_a_crash_and_not_silent(text, code):
    ms = M.load_text(text, "x.yaml")
    assert ms.manifests == () and codes(ms) == [code]


def test_json_duplicate_keys_and_constants_are_refused():
    assert codes(M.load_text('{"a":1,"a":2}', "x.json")) == ["DUPLICATE_KEY"]
    assert codes(M.load_text('{"a": NaN}', "x.json")) == ["NON_FINITE_NUMBER"]


def test_floats_become_decimal_strings_and_dates_become_text():
    ms = M.load_text("apiVersion: v1\nkind: X\nmetadata: {name: n}\nspec: {cpu: 0.5, when: 2024-01-02}\n", "x.yaml")
    spec = ms.manifests[0].doc["spec"]
    assert spec["cpu"] == "0.5" and spec["when"] == "2024-01-02"


def test_parsed_documents_are_frozen():
    doc = M.load_text("apiVersion: v1\nkind: X\nmetadata: {name: n, labels: {a: b}}\nspec: {l: [1, 2]}\n", "x.yaml").manifests[0].doc
    with pytest.raises(TypeError):
        doc["kind"] = "Y"
    with pytest.raises(AttributeError):
        doc._d = {}
    assert isinstance(doc["spec"]["l"], tuple)


def test_empty_and_comment_only_documents_are_dropped():
    assert M.load_text("---\n# nothing\n---\n", "x.yaml").manifests == ()


def test_byte_order_mark_and_invalid_utf8():
    assert len(M.load_tree.__doc__) > 0
    assert M.load_text("\ufeffapiVersion: v1\nkind: X\nmetadata: {name: n}\n", "x.yaml").manifests[0].name == "n"
    assert codes(M._from_bytes(b"\xff\xfe\x00bad", "x.yaml")) == ["NOT_UTF8"]


def test_oversized_file_and_oversized_document_are_refused():
    assert codes(M._from_bytes(b"a: 1\n" * (M.MAX_FILE_BYTES // 4), "x.yaml")) == ["TOO_LARGE"]
    deep = "a: " + "[" * 60 + "]" * 60 + "\n"
    assert codes(M.load_text(deep, "x.yaml")) in (["TOO_DEEP"], ["YAML_REFUSED"], ["PARSE_REFUSED"])


def test_reference_documents_are_separated_from_manifests():
    ms = M.load_text(dump([reference("ImageMap", {"images": []}), deployment()]), "x.yaml")
    assert [r.kind for r in ms.references] == ["ImageMap"] and [m.kind for m in ms.manifests] == ["Deployment"]


@pytest.mark.parametrize("key", ["expected", "Expected_Value", "predicate", "verdict", "expect"])
def test_a_reference_document_cannot_carry_an_expected_value(key):
    ms = M.load_text(dump([reference("ImageMap", {"images": [{"name": "a", key: "x"}]})]), "x.yaml")
    assert ms.references == () and codes(ms) == ["REFERENCE_CARRIES_EXPECTED"]


def test_malformed_reference_is_an_error():
    assert codes(M.load_text("apiVersion: qa-checks/reference-1\nkind: ImageMap\n", "x.yaml")) == ["REFERENCE_MALFORMED"]


def test_symbolic_links_are_refused(tmp_path):
    root = write_tree(tmp_path / "c", good_set())
    os.symlink(root / "10-app.yaml", root / "link.yaml")
    with pytest.raises(PathRefused):
        M.load_tree(root)
    with pytest.raises(PathRefused):
        M.tree_digest(root)


def test_a_symlinked_directory_component_is_refused(tmp_path):
    real = write_tree(tmp_path / "real", {"a.yaml": [deployment()]})
    root = tmp_path / "case"
    root.mkdir()
    os.symlink(real, root / "d")
    with pytest.raises(PathRefused):
        M.load_tree(root, "d")


@pytest.mark.parametrize("bad", ["", "/etc/passwd", "../x", "a/../../x", "a\\b", "a/\x00b", "C:/x", "a//b", "./../x"])
def test_unsafe_relative_paths_are_refused(bad, tmp_path):
    with pytest.raises(PathRefused):
        M.safe_relative(bad)


def test_missing_path_is_file_not_found_so_the_caller_can_report_unresolved(tmp_path):
    with pytest.raises(FileNotFoundError):
        M.load_tree(tmp_path, "nope")


def test_git_directory_is_not_read_and_other_files_are_counted(tmp_path):
    root = write_tree(tmp_path / "c", {"a.yaml": [deployment()]})
    (root / ".git").mkdir()
    (root / ".git" / "x.yaml").write_text("not: [valid", encoding="utf-8")
    (root / "notes.txt").write_text("hello", encoding="utf-8")
    ms = M.load_tree(root)
    assert ms.errors == () and ms.ignored_files == 1 and len(ms.manifests) == 1


def test_a_file_count_over_the_cap_is_refused(tmp_path, monkeypatch):
    root = write_tree(tmp_path / "c", {f"{i}.yaml": [deployment(f"d{i}")] for i in range(5)})
    monkeypatch.setattr(M, "MAX_FILES", 3)
    with pytest.raises(LimitExceeded):
        M.load_tree(root)


def test_tree_digest_changes_with_content_and_path_and_ignores_git(tmp_path):
    root = write_tree(tmp_path / "c", {"a.yaml": [deployment()]})
    d0 = M.tree_digest(root)
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("x", encoding="utf-8")
    assert M.tree_digest(root) == d0
    (root / "a.yaml").write_text(dump([deployment(replicas=3)]), encoding="utf-8")
    assert M.tree_digest(root) != d0
    (root / "a.yaml").rename(root / "b.yaml")
    assert M.tree_digest(root) not in (d0,)


def test_loading_writes_nothing(tmp_path):
    root = write_tree(tmp_path / "c", good_set())
    before = sorted((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in root.rglob("*"))
    M.load_tree(root)
    M.tree_digest(root)
    assert before == sorted((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in root.rglob("*"))


def test_manifest_properties_tolerate_odd_shapes():
    m = M.load_text("apiVersion: 3\nkind: [x]\nmetadata: oops\n", "x.yaml").manifests[0]
    assert (m.api_version, m.kind, m.name, m.namespace) == ("", "", "", "") and len(m.labels) == 0
