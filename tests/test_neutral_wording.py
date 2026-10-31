# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The neutral-wording guard: no tracked file carries a deny-listed term (held as digests in tools/check_neutral_wording.py).

The plain terms are not in this repository. The test-only list below is ROT13 text decoded when a test runs, so a text search of
the repository finds none of them; the encoding is a convenience, not a secret. The tests prove that the list and the digests in
the tool agree exactly, that each term is found however it is spelled, that a hit names file and line, that the allow-list works
and cannot go stale, and that introducing a term into a tree makes the check fail."""
import codecs
import hashlib
import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_neutral_wording", ROOT / "tools" / "check_neutral_wording.py")
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)

_PHRASES_ROT13 = (
    "uryqbhg",
    "uryq bhg",
    "onfryvar serrmr",
    "cvybg onfryvar",
    "cvaarq urnq",
    "unearff2",
    "unearff 2",
    "genpx c",
    "genpx v",
    "zhgngvba nez",
    "nez o",
    "sebmra urnq",
    "sebmra urnqf",
    "sebmra ce",
    "sebmra cef",
    "frnyrq zhgngvba",
    "frnyrq zhgngvbaf",
    "tebhaq gehgu",
    "orapuznex cebtenzzr",
    "orapuznex cebtenzzrf",
    "rkcybengbel vasen",
    "rkcybengbel vasenfgehpgher",
    "ntragvp bf ragrecevfr",
    "erqribcf ncc jro",
    "erqribcf orapuznexf",
    "erqribcf vb jro",
    "ehagvzr cyhtvaf ragrecevfr",
    "vagryyvtrapr tngrjnl",
    "dn cvybg onfryvar serrmr",
    "erqribcf dn cunfr",
    "erqribcf dn gvre",
    "erqribcf dn frnyrq",
    "nqe dn",
    "dn pbzcbarag vairagbel",
)
PHRASES = tuple(codecs.decode(p, "rot13").lower() for p in _PHRASES_ROT13)


def digest(phrase):
    return hashlib.sha256(phrase.encode()).hexdigest()


def test_the_digests_in_the_tool_are_exactly_the_digests_of_the_test_only_list():
    assert {digest(p) for p in PHRASES} == set(G.DENY_DIGESTS)


@pytest.mark.parametrize("phrase", PHRASES)
def test_each_term_is_found_however_it_is_spelled(phrase):
    words = phrase.split()
    spellings = [phrase, phrase.upper(), phrase.title(), "-".join(words), "_".join(words), "  ".join(words), "".join(w.capitalize() for w in words) if len(words) == 1 else phrase,
                 f"# {phrase}", f'"{phrase}"', f"x/{'-'.join(words)}.md"]
    for s in spellings:
        assert digest(phrase) in {d for _l, d in G.find_terms(f"a line\n{s}\nend")}, s
    if len(words) > 1:                                                     # a line break inside the phrase does not hide it
        assert [d for _l, d in G.find_terms(f"intro\n{words[0]}\n# {' '.join(words[1:])}")].count(digest(phrase)) == 1


def test_a_hit_reports_the_line_the_term_starts_on_and_never_the_term():
    term = PHRASES[0]
    hits = G.find_terms(f"one\ntwo\n  three {term} four\n")
    assert hits == [(3, digest(term))]
    h = G.Hit("docs/a.md", 3, digest(term))
    assert str(h) == f"docs/a.md:3: deny-list entry {digest(term)[:12]}" and term not in str(h)


@pytest.mark.parametrize("text", [
    "@dataclass(frozen=True)", "FROZEN = frozenset({1})", "a sealed run starts nothing that downloads", "held", "in", "held up", "out", "track", "tracking it",
    "baseline", "pinned files", "freeze(doc)", "head of the list", "arm", "arm b64", "harness", "the harness verifier", "ground", "gateway", "truth",
    "enterprise", "intelligence", "redevops-qa", "redevops-io/runtime-contracts", "redevops-io/agent-harness", "ADR A.2.5", "tier K",
])
def test_ordinary_wording_is_not_flagged(text):
    assert G.find_terms(text) == [], text


def _tree(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return sorted(files)


def test_a_term_in_a_file_makes_the_scan_fail_with_file_and_line(tmp_path):
    names = _tree(tmp_path, {"README.md": "fine\n", "docs/notes.md": "one\ntwo\n" + PHRASES[0] + "\n"})
    hits, stale = G.scan(tmp_path, names)
    assert [(h.path, h.line) for h in hits] == [("docs/notes.md", 3)] and stale == []


def test_a_term_in_a_file_name_is_found(tmp_path):
    name = "docs/" + PHRASES[1].replace(" ", "-") + ".md"
    names = _tree(tmp_path, {name: "fine\n"})
    hits, _ = G.scan(tmp_path, names)
    assert [(h.path, h.line) for h in hits] == [(name, 0)]


def test_binary_and_oversized_files_are_skipped_and_text_with_odd_bytes_is_still_scanned(tmp_path):
    (tmp_path / "b.bin").write_bytes(b"\0" + PHRASES[0].encode())
    (tmp_path / "odd.txt").write_bytes(b"\xff\xfe " + PHRASES[0].encode() + b"\n")
    hits, _ = G.scan(tmp_path, ["b.bin", "odd.txt"])
    assert [(h.path, h.line) for h in hits] == [("odd.txt", 1)]


def test_the_allow_list_silences_exactly_one_entry_in_matching_files_and_must_be_used(tmp_path):
    a, b = PHRASES[0], PHRASES[2]
    names = _tree(tmp_path, {"keep/a.md": f"{a}\n{b}\n", "other/b.md": f"{a}\n"})
    allow = [G.AllowEntry("keep/*", digest(a)[:12], "documents the legacy name on purpose", 1)]
    hits, stale = G.scan(tmp_path, names, allow)
    assert sorted((h.path, h.line) for h in hits) == [("keep/a.md", 2), ("other/b.md", 1)] and stale == []
    unused = G.AllowEntry("nowhere/*", digest(a)[:12], "no longer needed", 2)
    _hits, stale = G.scan(tmp_path, names, [*allow, unused])
    assert stale == [unused]


def test_allow_list_entries_need_a_reason_and_a_digest_prefix(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text("# comment\n\nsrc/* 0123456789ab because the file documents the rule\n", encoding="utf-8")
    assert G.load_allowlist(f) == [G.AllowEntry("src/*", "0123456789ab", "because the file documents the rule", 3)]
    for bad in ("src/* 0123456789ab\n", "src/* nothex012345 reason\n", "src/* 0123 reason\n", "src/*\n"):
        f.write_text(bad, encoding="utf-8")
        with pytest.raises(ValueError):
            G.load_allowlist(f)
    assert G.load_allowlist(tmp_path / "missing.txt") == []


def test_main_exits_one_on_a_hit_or_a_stale_entry_and_zero_when_clean(tmp_path, capsys):
    _tree(tmp_path, {"a.md": "fine\n"})
    assert G.main(["x", str(tmp_path)]) == 0 and "OK neutral wording" in capsys.readouterr().out
    _tree(tmp_path, {"b.md": f"fine\n{PHRASES[0]}\n"})
    assert G.main(["x", str(tmp_path)]) == 1 and "b.md:2: deny-list entry" in capsys.readouterr().out


def test_no_tracked_file_carries_a_deny_listed_term():
    hits, stale = G.scan(ROOT, allow=G.load_allowlist())
    assert [str(h) for h in hits] == [] and [(e.glob, e.prefix) for e in stale] == []


def test_the_guard_looks_at_the_tracked_files_of_this_repository():
    names = set(G.tracked_files(ROOT))
    assert {"pins.toml", "tools/check_neutral_wording.py", "tests/test_neutral_wording.py"} <= names
    assert any(n.startswith("packages/qa-checks/src/") for n in names) and not any(".git/" in n for n in names)


def test_introducing_a_term_into_a_copy_of_the_tracked_tree_makes_the_check_fail(tmp_path):
    """Mutation check: the real tree passes; the same tree with one term added to one file, or one file name, fails with file and line."""
    names = [n for n in G.tracked_files(ROOT) if n.endswith((".md", ".py", ".toml", ".yml"))][:60]
    for n in names:
        (tmp_path / n).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / n, tmp_path / n)
    clean_hits, _ = G.scan(tmp_path, names)
    assert clean_hits == []
    victim = "README.md"
    original = (tmp_path / victim).read_text(encoding="utf-8")
    (tmp_path / victim).write_text(original + "\n" + PHRASES[0] + "\n", encoding="utf-8")
    hits, _ = G.scan(tmp_path, names)
    assert [(h.path, h.line) for h in hits] == [(victim, original.count("\n") + 2)]
    (tmp_path / victim).write_text(original, encoding="utf-8")
    extra = PHRASES[1].replace(" ", "_") + ".txt"
    (tmp_path / extra).write_text("fine\n", encoding="utf-8")
    hits, _ = G.scan(tmp_path, [*names, extra])
    assert [(h.path, h.line) for h in hits] == [(extra, 0)]
