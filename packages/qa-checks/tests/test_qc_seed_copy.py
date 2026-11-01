# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""seed-copy: a copy in a work root, one named deterministic transformation, a recorded diff, and a list of refusals."""
import hashlib
import itertools
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import qc_protected as QP
from redevops_qa_checks import cli
from redevops_qa_checks import seed_copy as SC
from redevops_qa_checks.manifests import tree_digest

PKG = Path(__file__).resolve().parents[1]
D1, D2 = "sha256:" + "a" * 64, "sha256:" + "b" * 64

DEPLOY = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: demo
spec:
  replicas: 2
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: registry.example.test/team/web@{D1}  # pinned
          ports:
            - containerPort: 8080
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
          livenessProbe:
            httpGet:
              path: /live
              port: 8080
          resources:
            requests:
              cpu: 100m
            limits:
              cpu: 500m
        - name: side
          image: "registry.example.test/team/side@{D2}"
          securityContext:
            runAsNonRoot: true
"""
SERVICE = """apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: demo
spec:
  ports:
    - port: 80
      targetPort: 8080
"""


@pytest.fixture
def base(tmp_path_factory):
    return tmp_path_factory.mktemp("seed")


@pytest.fixture
def source(base):
    d = base / "corpus"
    (d / "app").mkdir(parents=True)
    (d / "app" / "deploy.yaml").write_text(DEPLOY, encoding="utf-8")
    (d / "app" / "svc.yaml").write_text(SERVICE, encoding="utf-8")
    (d / "notes.txt").write_text("keep me\n", encoding="utf-8")
    (d / "data.json").write_text('{"image": "x@' + D1 + '"}\n', encoding="utf-8")
    return d


@pytest.fixture
def work(base):
    return SC.create_work_root(base / "work")


def run(source, work, name="v1", t="replace-digest-with-tag", **params):
    return SC.seed_copy(source, work, name, t, params)


def read(work, name, rel="app/deploy.yaml"):
    return (work / name / rel).read_text(encoding="utf-8")


def reason(exc):
    return exc.value.reason


# -- the transformations ------------------------------------------------------------------------------------------------------------------------------

def test_replace_digest_with_tag_changes_the_first_site_only_by_default(source, work):
    rec = run(source, work, tag="1.0.0")
    out = read(work, "v1")
    assert "image: registry.example.test/team/web:1.0.0  # pinned" in out and f"@{D2}" in out and f"@{D1}" not in out
    assert [c["path"] for c in rec["files_changed"]] == ["app/deploy.yaml"]


def test_replace_digest_with_tag_all_handles_quotes_and_comments(source, work):
    run(source, work, tag="latest", occurrence="all")
    out = read(work, "v1")
    assert 'image: "registry.example.test/team/side:latest"' in out and "web:latest  # pinned" in out and "@sha256" not in out


def test_the_second_site_can_be_chosen(source, work):
    run(source, work, tag="9", occurrence=2)
    out = read(work, "v1")
    assert f"web@{D1}" in out and 'side:9"' in out


def test_json_and_text_files_are_never_touched(source, work):
    run(source, work, tag="1", occurrence="all")
    assert (work / "v1" / "data.json").read_text(encoding="utf-8") == (source / "data.json").read_text(encoding="utf-8")
    assert (work / "v1" / "notes.txt").read_bytes() == b"keep me\n"


@pytest.mark.parametrize("field,absent,kept", [
    ("allowPrivilegeEscalation", ["allowPrivilegeEscalation"], ["runAsUser: 10001", "capabilities:"]),
    ("runAsUser", ["runAsUser"], ["allowPrivilegeEscalation: false"]),
    ("capabilities", ["capabilities:", "drop:", "- ALL"], ["allowPrivilegeEscalation: false"]),
    ("seccompProfile", ["seccompProfile", "RuntimeDefault"], ["runAsNonRoot: true"]),
])
def test_remove_security_context_field_removes_the_field_and_its_children(source, work, field, absent, kept):
    before = (source / "app/deploy.yaml").read_text(encoding="utf-8")
    run(source, work, t="remove-security-context-field", field=field, occurrence="all")
    out = read(work, "v1")
    for text in absent:
        assert text not in out
    for text in kept:
        assert text in out
    assert out.count("\n") < before.count("\n")


def test_remove_security_context_field_occurrence_picks_one_block(source, work):
    run(source, work, t="remove-security-context-field", field="runAsNonRoot", occurrence=1)
    out = read(work, "v1")
    assert out.count("runAsNonRoot") == 2                       # one of three removed: the pod-level one


def test_remove_security_context_field_second_block(source, work):
    run(source, work, t="remove-security-context-field", field="runAsNonRoot", occurrence=2)
    out = read(work, "v1")
    assert out.count("runAsNonRoot") == 2 and out.index("runAsNonRoot") < out.index("runAsUser")      # the first container's is gone


def test_change_port_changes_container_port_and_probe_ports_but_not_other_numbers(source, work):
    run(source, work, t="change-port", from_port=8080, to_port=9090, occurrence="all")
    out = read(work, "v1")
    assert out.count("9090") == 3 and "8080" not in out and "replicas: 2" in out
    run(source, work, name="v2", t="change-port", from_port=8080, to_port=9091, occurrence=1)
    assert read(work, "v2").count("9091") == 1 and read(work, "v2").count("8080") == 2
    assert "targetPort: 8080" in read(work, "v2", "app/svc.yaml")                        # sites are counted in sorted path order: deploy.yaml first


def test_change_port_across_files_in_sorted_path_order(source, work):
    run(source, work, t="change-port", from_port=8080, to_port=7000, occurrence=4)
    assert "targetPort: 7000" in read(work, "v1", "app/svc.yaml") and read(work, "v1").count("8080") == 3


@pytest.mark.parametrize("probe", ["readinessProbe", "livenessProbe"])
def test_remove_probe_removes_the_declaration_with_its_children(source, work, probe):
    run(source, work, t="remove-probe", probe=probe)
    out = read(work, "v1")
    assert probe not in out and (out.count("httpGet") == 1) and "resources:" in out


def test_remove_resource_limits_keeps_requests(source, work):
    run(source, work, t="remove-resource-limits")
    out = read(work, "v1")
    assert "limits" not in out and "requests:" in out and "cpu: 100m" in out and "cpu: 500m" not in out


def test_a_transformation_that_matches_nothing_fails_instead_of_changing_nothing(source, work):
    with pytest.raises(SC.SeedRefused) as e:
        run(source, work, t="change-port", from_port=1234, to_port=2345)
    assert reason(e) == "NO_MATCH" and not (work / "v1").exists() and not (work / "v1.diff").exists()
    with pytest.raises(SC.SeedRefused) as e:
        run(source, work, t="replace-digest-with-tag", tag="1", occurrence=9)
    assert reason(e) == "NO_MATCH"


def test_the_library_is_small_documented_and_generic():
    assert sorted(SC.LIBRARY) == ["change-port", "remove-probe", "remove-resource-limits", "remove-security-context-field", "replace-digest-with-tag"]
    for t in SC.LIBRARY.values():
        assert t.description and t.version == "1.0.0" and t.params and "occurrence" in t.params


@pytest.mark.parametrize("t,params", [
    ("replace-digest-with-tag", {}), ("replace-digest-with-tag", {"tag": ""}), ("replace-digest-with-tag", {"tag": "a b"}), ("replace-digest-with-tag", {"tag": 5}),
    ("replace-digest-with-tag", {"tag": "1", "occurrence": 0}), ("replace-digest-with-tag", {"tag": "1", "occurrence": "some"}),
    ("replace-digest-with-tag", {"tag": "1", "occurrence": True}), ("replace-digest-with-tag", {"tag": "1", "extra": 1}),
    ("replace-digest-with-tag", {"tag": "1", "path_prefix": "../x"}), ("replace-digest-with-tag", {"tag": "1", "path_prefix": "/abs"}),
    ("remove-security-context-field", {}), ("remove-security-context-field", {"field": "image"}),
    ("change-port", {"from_port": 80}), ("change-port", {"from_port": 80, "to_port": 80}), ("change-port", {"from_port": 0, "to_port": 80}),
    ("change-port", {"from_port": 80, "to_port": 65536}), ("change-port", {"from_port": "80", "to_port": 81}), ("change-port", {"from_port": True, "to_port": 81}),
    ("remove-probe", {}), ("remove-probe", {"probe": "env"}),
])
def test_bad_parameters_are_refused(source, work, t, params):
    with pytest.raises(SC.SeedRefused) as e:
        SC.seed_copy(source, work, "v1", t, params)
    assert reason(e) == "PARAMS_INVALID" and not (work / "v1").exists()


def test_an_unknown_transformation_is_refused(source, work):
    with pytest.raises(SC.SeedRefused) as e:
        SC.seed_copy(source, work, "v1", "rewrite-everything", {})
    assert reason(e) == "TRANSFORMATION_UNKNOWN"


def test_path_prefix_limits_the_files(source, work):
    run(source, work, t="change-port", from_port=8080, to_port=9000, occurrence="all", path_prefix="app/svc")
    assert read(work, "v1", "app/svc.yaml").count("9000") == 1 and read(work, "v1").count("8080") == 3


# -- the copy, the diff and the record -----------------------------------------------------------------------------------------------------------------------

def test_the_record_the_diff_and_the_marker_describe_exactly_what_changed(source, work):
    rec = run(source, work, tag="1.0.0")
    assert rec["dev"] is True and rec["transformation"]["id"] == "replace-digest-with-tag" and rec["params"] == {"occurrence": 1, "path_prefix": "", "tag": "1.0.0"}
    assert rec["source_tree_sha256"] == tree_digest(source) and rec["output_tree_sha256"] == tree_digest(work / "v1")
    assert rec["files_total"] == 4 and rec["files_changed"][0]["before_sha256"] != rec["files_changed"][0]["after_sha256"]
    diff = (work / "v1.diff").read_text(encoding="utf-8")
    assert diff.startswith("--- a/app/deploy.yaml\n+++ b/app/deploy.yaml\n") and f"-          image: registry.example.test/team/web@{D1}  # pinned" in diff
    assert "+          image: registry.example.test/team/web:1.0.0  # pinned" in diff
    on_disk = json.loads((work / "v1.record.json").read_text(encoding="utf-8"))
    assert on_disk == rec and rec["diff_sha256"] == json.loads((work / "v1" / ".qa-dev-variant").read_text(encoding="utf-8"))["diff_sha256"]
    marker = json.loads((work / "v1" / SC.DEV_MARKER_FILE).read_text(encoding="utf-8"))
    assert marker["dev"] is True and "not part of any protected or reference set" in marker["note"]


def test_applying_the_diff_to_the_source_gives_the_copy(source, work, base):
    import difflib
    run(source, work, t="remove-resource-limits")
    a = (source / "app/deploy.yaml").read_text(encoding="utf-8").splitlines(keepends=True)
    b = read(work, "v1").splitlines(keepends=True)
    assert "".join(difflib.unified_diff(a, b, fromfile="a/app/deploy.yaml", tofile="b/app/deploy.yaml")) == (work / "v1.diff").read_text(encoding="utf-8")


def test_the_copy_is_deterministic_in_bytes_modes_and_times(source, work, base):
    r1 = run(source, work, name="one", tag="2")
    r2 = run(source, work, name="two", tag="2")
    assert r1["output_tree_sha256"] == r2["output_tree_sha256"] and (work / "one.diff").read_bytes() == (work / "two.diff").read_bytes()
    for p in (work / "one").rglob("*"):
        if p.is_file():
            assert os.stat(p).st_mtime == 0 and stat.S_IMODE(os.stat(p).st_mode) in (0o644, 0o755)


def test_the_output_is_identical_across_hash_seeds(source, work, base):
    code = ("import sys; from pathlib import Path; from redevops_qa_checks import seed_copy as S; "
            "w = S.create_work_root(Path(sys.argv[2])); r = S.seed_copy(Path(sys.argv[1]), w, 'v', 'remove-security-context-field', {'field': 'runAsNonRoot', 'occurrence': 'all'}); "
            "print(r['output_tree_sha256'])")
    outs = set()
    for i, seed in enumerate(("0", "1", "random")):
        r = subprocess.run([sys.executable, "-B", "-c", code, str(source), str(base / f"w{i}")], capture_output=True, text=True, timeout=60,
                           env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": seed, "PYTHONPATH": str(PKG / "src"), "HOME": str(base)})
        assert r.returncode == 0, r.stderr
        outs.add(r.stdout.strip())
    assert len(outs) == 1


def test_the_executable_bit_is_kept_and_line_endings_are_preserved(base, work):
    d = base / "crlf"
    d.mkdir()
    (d / "a.yaml").write_bytes(b"spec:\r\n  ports:\r\n    - containerPort: 80\r\n")
    (d / "run.sh").write_bytes(b"#!/bin/sh\n")
    os.chmod(d / "run.sh", 0o755)
    SC.seed_copy(d, work, "v1", "change-port", {"from_port": 80, "to_port": 81})
    assert (work / "v1" / "a.yaml").read_bytes() == b"spec:\r\n  ports:\r\n    - containerPort: 81\r\n"
    assert os.stat(work / "v1" / "run.sh").st_mode & 0o111


# -- the input is never edited --------------------------------------------------------------------------------------------------------------------------------

def test_the_source_tree_is_identical_before_and_after_and_a_read_only_source_works(source, work):
    before = tree_digest(source)
    snap = sorted((str(p.relative_to(source)), p.stat().st_mtime_ns, p.stat().st_size) for p in source.rglob("*"))
    for p in sorted(source.rglob("*"), reverse=True):
        os.chmod(p, 0o555 if p.is_dir() else 0o444)
    os.chmod(source, 0o555)
    try:
        run(source, work, tag="3", occurrence="all")
        assert tree_digest(source) == before
        assert snap == sorted((str(p.relative_to(source)), p.stat().st_mtime_ns, p.stat().st_size) for p in source.rglob("*"))
    finally:
        for p in sorted(source.rglob("*")):
            os.chmod(p, 0o755 if p.is_dir() else 0o644)
        os.chmod(source, 0o755)


def test_only_the_copy_the_diff_and_the_record_are_written(source, work, base):
    before = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in base.rglob("*") if work not in p.parents or p.parent == work}
    run(source, work, tag="3")
    new = {str(p.relative_to(base)) for p in base.rglob("*")} - {str(p.relative_to(base)) for p in before}
    assert {n.split("/")[1] for n in new if n.startswith("work/")} == {"v1", "v1.diff", "v1.record.json"}
    assert not any(n.startswith("corpus") for n in new)
    for p, st in before.items():
        assert (p.stat().st_mtime_ns, p.stat().st_size) == st or p == work


def test_the_digest_of_the_bytes_read_equals_the_digest_of_the_tree_on_disk(source):
    assert SC.files_digest(SC.read_source(source)) == tree_digest(source)


def test_a_work_root_that_lies_inside_the_source_is_refused_by_seed_copy(base):
    src = base / "src2"
    src.mkdir()
    (src / "a.yaml").write_text(SERVICE, encoding="utf-8")
    wr = SC.create_work_root(src / "work")                         # created by the tool, but inside the source tree
    (src / "a.yaml").write_text(SERVICE, encoding="utf-8")
    with pytest.raises(SC.SeedRefused) as e:
        SC.seed_copy(src, wr, "v1", "change-port", {"from_port": 8080, "to_port": 9})
    assert reason(e) == "WORK_ROOT_INSIDE_SOURCE" and not (wr / "v1").exists()
    assert sorted(p.name for p in src.iterdir() if p.name != "work") == ["a.yaml"]


def test_a_source_that_lies_inside_the_work_root_is_refused(work):
    inner = work / "tree"
    inner.mkdir()
    (inner / "a.yaml").write_text(SERVICE, encoding="utf-8")
    with pytest.raises(SC.SeedRefused) as e:
        SC.seed_copy(inner, work, "v1", "change-port", {"from_port": 8080, "to_port": 9})
    assert reason(e) == "SOURCE_INSIDE_WORK_ROOT"


def test_the_source_changing_during_the_copy_removes_the_copy_and_fails(source, work, monkeypatch):
    real = SC.read_source

    def read_then_edit(s):
        files = real(s)
        (Path(s) / "notes.txt").write_text("edited while copying\n", encoding="utf-8")
        return files
    monkeypatch.setattr(SC, "read_source", read_then_edit)
    with pytest.raises(SC.SeedRefused) as e:
        run(source, work, tag="3")
    assert reason(e) == "SOURCE_CHANGED_DURING_COPY"
    assert not (work / "v1").exists() and not (work / "v1.diff").exists() and not (work / "v1.record.json").exists()


# -- refusals ---------------------------------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("vcs", [".git", ".hg", ".svn", ".bzr", ".gitmodules"])
def test_a_source_with_version_control_metadata_is_refused_wherever_it_is(source, work, vcs):
    where = source / "app" / vcs
    if vcs == ".gitmodules":
        where.write_text("x", encoding="utf-8")
    else:
        where.mkdir()
    with pytest.raises(SC.SeedRefused) as e:
        run(source, work, tag="1")
    assert reason(e) == "SOURCE_HAS_VCS_METADATA" and not (work / "v1").exists()


def test_a_source_with_a_symbolic_link_or_a_special_file_is_refused(source, work):
    os.symlink(source / "notes.txt", source / "link")
    with pytest.raises(SC.SeedRefused) as e:
        run(source, work, tag="1")
    assert reason(e) == "SOURCE_HAS_SYMLINK"
    os.unlink(source / "link")
    os.mkfifo(source / "pipe")
    with pytest.raises(SC.SeedRefused) as e:
        run(source, work, tag="1")
    assert reason(e) == "SOURCE_SPECIAL_FILE"


def test_a_source_that_is_a_link_or_a_file_or_missing_is_refused(source, work, base):
    os.symlink(source, base / "srclink")
    for bad, why in ((base / "srclink", "SOURCE_NOT_DIRECTORY"), (source / "notes.txt", "SOURCE_NOT_DIRECTORY"), (base / "missing", "SOURCE_MISSING")):
        with pytest.raises(SC.SeedRefused) as e:
            SC.seed_copy(bad, work, "v1", "change-port", {"from_port": 1, "to_port": 2})
        assert reason(e) == why


@pytest.mark.parametrize("word", QP.TOKENS)
def test_a_path_that_names_a_protected_corpus_is_refused_as_source_and_as_work_root(base, word):
    for i, variant in enumerate((word, word.upper(), word.title(), f"x_{word}_y", f"{word}-corpus", f"corpus.{word}")):
        bad_source = base / f"s{i}" / variant                                      # one directory per variant (case-insensitive file systems)
        bad_source.mkdir(parents=True)
        (bad_source / "a.yaml").write_text(SERVICE, encoding="utf-8")
        good_work = SC.create_work_root(base / f"ok-work-{i}")
        with pytest.raises(SC.SeedRefused) as e:
            SC.seed_copy(bad_source, good_work, "v1", "change-port", {"from_port": 8080, "to_port": 9})
        assert reason(e) == "SOURCE_PROTECTED_MARKER" and not (good_work / "v1").exists(), variant
        with pytest.raises(SC.SeedRefused) as e:
            SC.create_work_root(base / f"{variant}-work")
        assert reason(e) == "OUTPUT_PROTECTED_MARKER", variant


@pytest.mark.parametrize("word", QP.TOKENS)
def test_a_path_segment_anywhere_in_the_source_path_is_enough(base, word):
    deep = base / word / "inner" / "tree"
    deep.mkdir(parents=True)
    (deep / "a.yaml").write_text(SERVICE, encoding="utf-8")
    w = SC.create_work_root(base / "w-deep")
    with pytest.raises(SC.SeedRefused) as e:
        SC.seed_copy(deep, w, "v1", "change-port", {"from_port": 8080, "to_port": 9})
    assert reason(e) == "SOURCE_PROTECTED_MARKER"


@pytest.mark.parametrize("word", QP.TOKENS)
def test_an_output_name_that_names_a_protected_corpus_is_refused(source, work, word):
    for name in (word, f"{word}-copy", f"{word}-1", f"x.{word}.y"):
        if not SC._NAME.fullmatch(name):
            continue
        with pytest.raises(SC.SeedRefused) as e:
            SC.seed_copy(source, work, name, "change-port", {"from_port": 8080, "to_port": 9})
        assert reason(e) == "OUTPUT_PROTECTED_MARKER" and not (work / name).exists(), name


@pytest.mark.parametrize("word", QP.TOKENS)
def test_names_that_only_contain_the_letters_are_not_refused(base, word):
    for i, name in enumerate(QP.near_misses(word)):
        assert SC.has_marker(base / name) is None, name
    d = base / QP.near_misses(word)[0]
    d.mkdir()
    (d / "a.yaml").write_text(SERVICE, encoding="utf-8")
    w = SC.create_work_root(base / "w-ok")
    SC.seed_copy(d, w, "ok-1", "change-port", {"from_port": 8080, "to_port": 9})
    assert SC.has_marker(base / "reselling-sealing") is None and SC.has_marker(base / "unfrozenish") is None


@pytest.mark.parametrize("marker", QP.MARKER_FILES)
def test_a_source_that_contains_an_earlier_marker_file_is_refused(source, work, marker):
    for name in (marker, marker.upper(), marker.lower()):
        (source / name).write_text("x", encoding="utf-8")
        with pytest.raises(SC.SeedRefused) as e:
            run(source, work, tag="1")
        assert reason(e) == "SOURCE_PROTECTED_MARKER", name
        (source / name).unlink()
    (source / "sub").mkdir()
    (source / "sub" / marker).write_text("x", encoding="utf-8")                  # in a sub-directory too
    with pytest.raises(SC.SeedRefused) as e:
        run(source, work, tag="1")
    assert reason(e) == "SOURCE_PROTECTED_MARKER"


@pytest.mark.parametrize("marker", sorted(SC.MARKER_FILES))
def test_a_source_that_contains_the_protected_marker_file_is_refused(source, work, marker):
    assert marker == ".qa-protected"
    for name in (marker, marker.upper()):
        (source / name).write_text("", encoding="utf-8")
        with pytest.raises(SC.SeedRefused) as e:
            run(source, work, tag="1")
        assert reason(e) == "SOURCE_PROTECTED_MARKER" and not (work / "v1").exists(), name
        (source / name).unlink()
    (source / "app" / marker).mkdir()                                               # a directory of that name marks the tree as well
    with pytest.raises(SC.SeedRefused) as e:
        run(source, work, tag="1")
    assert reason(e) == "SOURCE_PROTECTED_MARKER"


def test_file_names_that_only_resemble_a_marker_file_do_not_refuse_the_source(source, work):
    for marker in (*QP.MARKER_FILES, ".qa-protected"):
        for name in (marker + "x", "x" + marker, marker + ".txt"):
            (source / name).write_text("x", encoding="utf-8")
    for name in ("qa-protected", ".qa_protected"):
        (source / name).write_text("x", encoding="utf-8")
    run(source, work, tag="1")                                                      # none of them is a marker file


def test_the_digest_lists_are_exactly_the_digests_of_the_test_only_lists():
    assert set(SC.PROTECTED_TOKEN_DIGESTS) == {hashlib.sha256(t.encode()).hexdigest() for t in QP.TOKENS}
    assert set(SC.LEGACY_MARKER_FILE_DIGESTS) == {hashlib.sha256(t.lower().encode()).hexdigest() for t in QP.MARKER_FILES}
    assert tuple(SC.PROTECTED_MARKERS) == tuple(SC.PROTECTED_TOKEN_DIGESTS) and len(SC.PROTECTED_TOKEN_DIGESTS) == len(set(SC.PROTECTED_TOKEN_DIGESTS))
    assert all(re.fullmatch(r"[0-9a-f]{64}", d) for d in (*SC.PROTECTED_TOKEN_DIGESTS, *SC.LEGACY_MARKER_FILE_DIGESTS))


def _generated_components():
    pieces = [*QP.TOKENS, "x", "un", "s", "ed", "freeze", "held", "head", "out", "pinned", "baseline", "1"]
    seps = ["", "-", "_", ".", " ", "--", "\u00e9"]
    for a, sep1, b, sep2, c in itertools.product(pieces, seps, pieces, seps, pieces):
        yield a + sep1 + b + sep2 + c
    swaps = {"s": "\u017f", "k": "\u212a", "i": "\u0130"}
    for t in QP.TOKENS:
        yield "".join(swaps.get(ch, ch) for ch in t)                                # letters that match an ASCII letter when case is ignored
        yield "".join(swaps.get(ch, ch) for ch in t).upper()
        yield "\u0131".join(t.split("i"))
        yield t.upper()
        yield t.title()


def test_the_digest_matcher_refuses_exactly_what_the_original_word_matcher_refused():
    n = 0
    for part in _generated_components():
        n += 1
        assert (SC.part_marker(part) is not None) == (QP.reference_part_marker(part) is not None), repr(part)
    assert n > 100000


@pytest.mark.parametrize("word", QP.TOKENS)
def test_the_refusal_does_not_print_the_token(base, word):
    with pytest.raises(SC.SeedRefused) as e:
        SC.create_work_root(base / f"{word}-w")
    shown = json.dumps(e.value.details, default=str) + str(e.value)
    assert word not in shown.lower() and e.value.details["marker"] == hashlib.sha256(word.encode()).hexdigest()[:16]


def test_an_existing_output_or_diff_or_record_is_refused_and_left_alone(source, work):
    run(source, work, tag="1")
    snap = (work / "v1.record.json").read_bytes()
    with pytest.raises(SC.SeedRefused) as e:
        run(source, work, tag="2")
    assert reason(e) == "OUTPUT_EXISTS" and (work / "v1.record.json").read_bytes() == snap
    (work / "v2.diff").write_text("x", encoding="utf-8")
    with pytest.raises(SC.SeedRefused) as e:
        run(source, work, name="v2", tag="2")
    assert reason(e) == "OUTPUT_EXISTS" and not (work / "v2").exists()


@pytest.mark.parametrize("name", ["", "V1", "a/b", "../x", ".hidden", "-x", "a b", "x" * 65, "a\n", 5, None])
def test_an_output_name_is_a_short_lower_case_name(source, work, name):
    with pytest.raises(SC.SeedRefused) as e:
        SC.seed_copy(source, work, name, "change-port", {"from_port": 8080, "to_port": 9})
    assert reason(e) == "NAME_INVALID"


def test_a_directory_the_tool_did_not_create_is_not_a_work_root(source, base):
    plain = base / "plain-dir"
    plain.mkdir(mode=0o700)
    with pytest.raises(SC.SeedRefused) as e:
        SC.seed_copy(source, plain, "v1", "change-port", {"from_port": 8080, "to_port": 9})
    assert reason(e) == "WORK_ROOT_NOT_CREATED_BY_TOOL" and sorted(p.name for p in plain.iterdir()) == []
    with pytest.raises(SC.SeedRefused) as e:
        SC.seed_copy(source, base / "missing-dir", "v1", "change-port", {"from_port": 8080, "to_port": 9})
    assert reason(e) == "WORK_ROOT_NOT_CREATED_BY_TOOL"


@pytest.mark.parametrize("sentinel", ['{"schema": "other", "uid": 0}', "not json", '{"schema": "qa-checks/seed-work-root/1", "uid": 0}'])
def test_a_forged_or_foreign_sentinel_is_refused(source, base, sentinel):
    fake = base / "fake-root"
    fake.mkdir(mode=0o700)
    (fake / SC.WORK_ROOT_SENTINEL).write_text(sentinel if os.getuid() != 0 else '{"schema": "x"}', encoding="utf-8")
    with pytest.raises(SC.SeedRefused) as e:
        SC.seed_copy(source, fake, "v1", "change-port", {"from_port": 8080, "to_port": 9})
    assert reason(e) == "WORK_ROOT_NOT_CREATED_BY_TOOL"


def test_a_work_root_writable_by_others_or_a_link_is_refused(source, work, base):
    os.chmod(work, 0o770)
    with pytest.raises(SC.SeedRefused) as e:
        run(source, work, tag="1")
    assert reason(e) == "WORK_ROOT_NOT_CREATED_BY_TOOL"
    os.chmod(work, 0o700)
    os.symlink(work, base / "worklink")
    with pytest.raises(SC.SeedRefused) as e:
        SC.seed_copy(source, base / "worklink", "v1", "change-port", {"from_port": 8080, "to_port": 9})
    assert reason(e) == "WORK_ROOT_NOT_CREATED_BY_TOOL"


def test_a_work_root_is_never_created_inside_a_version_control_checkout(base):
    repo = base / "repo"
    (repo / ".git").mkdir(parents=True)
    with pytest.raises(SC.SeedRefused) as e:
        SC.create_work_root(repo / "work")
    assert reason(e) == "WORK_ROOT_IN_VCS"
    deeper = repo / "a" / "b"
    deeper.mkdir(parents=True)
    with pytest.raises(SC.SeedRefused) as e:
        SC.create_work_root(deeper / "work")
    assert reason(e) == "WORK_ROOT_IN_VCS"


def test_a_work_root_that_became_a_checkout_is_refused(source, work):
    (work / ".git").mkdir()
    with pytest.raises(SC.SeedRefused) as e:
        run(source, work, tag="1")
    assert reason(e) == "WORK_ROOT_IN_VCS"


def test_creating_a_work_root_needs_a_new_path_and_a_real_parent(base):
    (base / "exists").mkdir()
    with pytest.raises(SC.SeedRefused) as e:
        SC.create_work_root(base / "exists")
    assert reason(e) == "OUTPUT_EXISTS"
    with pytest.raises(SC.SeedRefused) as e:
        SC.create_work_root(base / "no" / "parent")
    assert reason(e) == "WORK_ROOT_PARENT_INVALID"
    w = SC.create_work_root(base / "fresh")
    assert stat.S_IMODE(os.stat(w).st_mode) == 0o700 and json.loads((w / SC.WORK_ROOT_SENTINEL).read_text(encoding="utf-8"))["schema"] == SC.WORK_ROOT_SCHEMA


def test_a_failure_part_way_removes_the_copy_it_made(source, work, monkeypatch):
    real = os.chmod
    calls = {"n": 0}

    def flaky(path, mode, **kw):
        calls["n"] += 1
        if calls["n"] == 3:
            raise OSError("disk trouble")
        return real(path, mode, **kw)
    monkeypatch.setattr(SC.os, "chmod", flaky)
    with pytest.raises(OSError):
        run(source, work, tag="1")
    monkeypatch.undo()
    assert not (work / "v1").exists() and not (work / "v1.diff").exists() and not (work / "v1.record.json").exists()


def test_oversized_trees_and_files_are_refused(source, work, monkeypatch):
    monkeypatch.setattr(SC, "MAX_SEED_FILE_BYTES", 10)
    with pytest.raises(SC.SeedRefused) as e:
        run(source, work, tag="1")
    assert reason(e) == "SOURCE_TOO_LARGE"


# -- the command line ---------------------------------------------------------------------------------------------------------------------------------------------

def test_the_command_line_creates_a_work_root_lists_the_library_and_applies(source, base, capsys):
    root = base / "cli-work"
    assert cli.main(["seed-copy", "create-work-root", str(root)]) == 0 and capsys.readouterr().out.strip() == str(root)
    assert cli.main(["seed-copy", "list"]) == 0 and len(capsys.readouterr().out.strip().splitlines()) == 5
    assert cli.main(["seed-copy", "apply", "--source", str(source), "--work-root", str(root), "--name", "v1", "--transform", "change-port",
                     "--params", json.dumps({"from_port": 8080, "to_port": 9000, "occurrence": "all"})]) == 0
    assert json.loads(capsys.readouterr().out)["transformation"]["id"] == "change-port" and (root / "v1.diff").exists()


def test_the_command_line_refuses_with_a_reason_and_exit_code_2(source, base, capsys):
    root = base / "cli-work2"
    cli.main(["seed-copy", "create-work-root", str(root)])
    capsys.readouterr()
    assert cli.main(["seed-copy", "apply", "--source", str(source), "--work-root", str(root), "--name", "v1", "--transform", "nope"]) == 2
    assert json.loads(capsys.readouterr().err)["reason"] == "TRANSFORMATION_UNKNOWN"
    assert cli.main(["seed-copy", "apply", "--source", str(source), "--work-root", str(root), "--name", "v1", "--transform", "change-port", "--params", "{bad"]) == 2
    assert cli.main(["seed-copy", "create-work-root", str(root)]) == 2


def test_the_command_line_has_no_in_place_or_output_path_option():
    for flag in ("--in-place", "--output", "--inplace", "--force", "--overwrite"):
        with pytest.raises(SystemExit):
            cli.main(["seed-copy", "apply", "--source", "x", "--work-root", "y", "--name", "n", "--transform", "t", flag, "z"])
