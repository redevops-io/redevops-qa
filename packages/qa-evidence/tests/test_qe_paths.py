# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Path rules: relative, POSIX separators, NFC, plain characters, no traversal, and the keys under which two names collide."""
import pytest

from qa_evidence.constants import Limits
from qa_evidence import paths as paths_module
from qa_evidence.paths import fold_key, path_problems


@pytest.mark.parametrize("path", ["report.json", "lanes/browser/blobs/" + "a" * 64, "a/b-c_d.e+f=g@h,i", "x"])
def test_ordinary_paths_are_accepted(path):
    assert path_problems(path) == []


@pytest.mark.parametrize("path,code", [
    ("", "PATH_UNSAFE"), ("..", "PATH_TRAVERSAL"), ("../x", "PATH_TRAVERSAL"), ("a/..", "PATH_TRAVERSAL"), ("a/../b", "PATH_TRAVERSAL"),
    ("/x", "PATH_ABSOLUTE"), ("//x", "PATH_ABSOLUTE"), ("C:\\x", "PATH_UNSAFE"), ("C:/x", "PATH_UNSAFE"), ("c:x", "PATH_UNSAFE"), ("a:b", "PATH_UNSAFE"),
    ("a\\b", "PATH_UNSAFE"), ("a//b", "PATH_UNSAFE"), ("a/", "PATH_UNSAFE"), (".", "PATH_UNSAFE"), ("a/./b", "PATH_UNSAFE"), (".hidden", "PATH_UNSAFE"),
    ("a.", "PATH_UNSAFE"), ("a\x00b", "PATH_UNSAFE"), ("a\nb", "PATH_UNSAFE"), ("a b", "PATH_UNSAFE"), ("a*b", "PATH_UNSAFE"), ("a?b", "PATH_UNSAFE"),
    ("CON", "PATH_UNSAFE"), ("con.txt", "PATH_UNSAFE"), ("a/NUL", "PATH_UNSAFE"), ("lpt1", "PATH_UNSAFE"), ("a\u202eb", "PATH_NOT_ASCII"), ("a\u200bb", "PATH_NOT_ASCII"),
    ("a\u00a0b", "PATH_NOT_ASCII"), ("a\ud800b", "PATH_NOT_ASCII"), ("e\u0301", "PATH_NOT_ASCII"), ("caf\u00e9", "PATH_NOT_ASCII"), ("\u65e5\u672c", "PATH_NOT_ASCII"), ("x" * 65, "PATH_TOO_LONG"),
    ("a/" * 51 + "b", "PATH_TOO_LONG"), ("\U0001f600", "PATH_NOT_ASCII"),
])
def test_unsafe_paths_name_the_rule_they_break(path, code):
    assert code in {c for c, _ in path_problems(path)}


def test_a_non_string_is_refused():
    assert path_problems(None) and path_problems(5)


def test_the_caps_are_parameters():
    assert path_problems("abcdefghij", Limits(max_path_bytes=5))[0][0] == "PATH_TOO_LONG"
    assert path_problems("abcdefghij", Limits(max_component_bytes=5))[0][0] == "PATH_TOO_LONG"


def test_fold_key_makes_case_variants_collide_and_never_depends_on_the_unicode_database():
    assert fold_key("A/B.txt") == fold_key("a/b.TXT")
    assert fold_key("a") != fold_key("b")
    assert fold_key("caf\u00c9") == "caf\u00c9"            # only ASCII letters fold


def test_acceptance_never_depends_on_the_interpreters_unicode_database():
    """A character that is unassigned in one Python release and assigned in the next is refused everywhere: the rule is a fixed ASCII set."""
    for ch in ("\U00016d40", "\u0378", "\ue000", "\U000e0001", "\u00e9", "\u0301"):
        assert [c for c, _ in path_problems("lanes/a" + ch + "b.txt")] == ["PATH_NOT_ASCII"]
    with open(paths_module.__file__, encoding="utf-8") as fh:
        assert "import unicodedata" not in fh.read()
