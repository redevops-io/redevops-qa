# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Building bundles: both forms, determinism (byte-identical rebuilds, golden digests that must be the same on every host), and the builder's
own refusals."""
import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from qa_evidence.build import BuildError, FileSpec, anchor_document, build_bundle, describe_environment, read_files, write_archive, write_directory
from qa_evidence.canon import dumps_canonical, sha256_bytes
from qa_evidence.constants import ANCHOR_NAME, ASSERTION_LOCK_NAME, FORMAT_DOC, FORMAT_DOC_NAME, INTEGRITY_STATEMENT, MANIFEST_NAME, REPORT_NAME
from qa_evidence.tarfmt import write_tar
from qa_evidence.verify import verify_bundle, verify_files

from qe_helpers import BROWSER_NATIVE, ENV, build_base, codes, inputs, load

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"

# Golden vectors: recomputed here from first principles (hashlib over the bytes), and fixed as constants. They are the same on a Mac and
# on the Linux CI runner, and they change only when the format changes.
GOLDEN_MANIFEST_DIGEST = "sha256:b1797156f3a9601219d0b1ae4eeaf068dd7f7fc5214474db9e471fed36c92113"
GOLDEN_ARCHIVE_DIGEST = "sha256:79756bc1ae52cafe00f4b6ccb954f773efc62cc1791b32eeec5e4380692b45fa"
GOLDEN_FILES = {
    "BUNDLE-FORMAT.txt": "sha256:d99b82c24d8793900791a0bfb59723cd2bcc8d86dc35d775fd8e908f72213eae",
    "assertion-lock.json": "sha256:64dc238a95e54c7de6889b39b76a141c3f996f979d1748a767fcf17f2e20cd3c",
    "lanes/browser/native/native.txt": "sha256:c58b67997070d1e8cdcc446a0e8733b815b9053995f05a401b42eec882b26742",
    "lanes/browser/observations.json": "sha256:2b0c9aa46b536748f98e9b80ecee3627c50bc22eeb0713b06a0fb32aa3785846",
    "lanes/robot/native/output.xml": "sha256:91d8240dd501537d2bf00fcd43b3b8dcbbc5745d7a2c35aa466d98d2d2b01cc0",
    "lanes/robot/observations.json": "sha256:f9a2020648ae5d4bff5ded1c9c30514d95be870d24df1a299f22645b25a11abe",
    "logs/orchestrator.log": "sha256:f81a97ea85a6db544337fe579efc84550798e7cbace37d9cbeaff26a0781bde2",
    "report.json": "sha256:4019d8f46cecac77049d6b487fc28904211248f66f3565dd9a16d8d5411ba5ce",
}


def test_the_bundle_has_the_documented_layout():
    b = build_base()
    assert sorted(b.files) == sorted([MANIFEST_NAME, REPORT_NAME, FORMAT_DOC_NAME, ASSERTION_LOCK_NAME, "lanes/browser/native/native.txt", "lanes/browser/observations.json",
                                      "lanes/robot/native/output.xml", "lanes/robot/observations.json", "logs/orchestrator.log"])
    man = load(b.files, MANIFEST_NAME)
    assert [f["path"] for f in man["files"]] == sorted(f["path"] for f in man["files"]) and MANIFEST_NAME not in [f["path"] for f in man["files"]]
    assert {f["path"]: (f["digest"], f["size"]) for f in man["files"]} == {p: (sha256_bytes(d), len(d)) for p, d in b.files.items() if p != MANIFEST_NAME}
    assert man["run_id"] == "r0-test" and [x["lane_id"] for x in man["lanes"]] == ["browser", "robot"]
    assert man["lanes"][1]["engine"] == {"name": "robotframework", "version": "7.5"} and man["tools"] == {"orchestrator": "0.1.0", "qa-verify": "0.1.0"}
    assert {k: man["environment"][k] for k in ("os", "arch", "python")} == ENV
    assert man["assertion_set_digests"] == [load(b.files, REPORT_NAME)["assertion_set"]["digest"]]
    assert man["integrity"] == {"mechanism": "sha256-file-digests", "keyed": False, "statement": INTEGRITY_STATEMENT}
    assert man["anchor"]["slot"] == "anchor.json" and man["anchor"]["binds"] == "manifest-digest" and "anchor.json" not in b.files
    assert b.files[FORMAT_DOC_NAME].decode() == FORMAT_DOC and "UNKEYED" in FORMAT_DOC and "NOT" in FORMAT_DOC


def test_the_manifest_and_the_documentation_state_the_limit_of_unkeyed_hashes():
    man = load(build_base().files, MANIFEST_NAME)
    assert "do NOT detect deliberate re-forging" in man["integrity"]["statement"] and man["integrity"]["keyed"] is False
    assert "does not establish anything" in man["anchor"]["statement"]
    assert "not stored in it" in man["anchor"]["statement"]


def test_the_manifest_digest_is_the_sha256_of_the_exact_manifest_bytes():
    b = build_base()
    assert b.manifest_digest == "sha256:" + hashlib.sha256(b.files[MANIFEST_NAME]).hexdigest()


def test_golden_vectors():
    b = build_base()
    assert b.manifest_digest == GOLDEN_MANIFEST_DIGEST
    assert {p: "sha256:" + hashlib.sha256(d).hexdigest() for p, d in b.files.items() if p != MANIFEST_NAME} == GOLDEN_FILES
    assert "sha256:" + hashlib.sha256(b.archive_bytes()).hexdigest() == GOLDEN_ARCHIVE_DIGEST


def test_the_directory_form_and_the_archive_form_both_verify_and_hold_the_same_files(tmp_path):
    b = build_base()
    b.write_directory(str(tmp_path / "dir"))
    b.write_archive(str(tmp_path / "b.tar"))
    for loc in (tmp_path / "dir", tmp_path / "b.tar"):
        r = verify_bundle(str(loc))
        assert r.ok and r.file_count == len(b.files) and r.manifest_digest == b.manifest_digest
    assert read_files(str(tmp_path / "dir")) == read_files(str(tmp_path / "b.tar")) == b.files
    assert verify_bundle(str(tmp_path / "dir")).form == "directory" and verify_bundle(str(tmp_path / "b.tar")).form == "archive"


def test_rebuilding_twice_gives_byte_identical_archives_and_directories(tmp_path):
    one, two = build_base(), build_base()
    assert one.files == two.files and one.archive_bytes() == two.archive_bytes()
    one.write_archive(str(tmp_path / "1.tar"))
    two.write_archive(str(tmp_path / "2.tar"))
    assert (tmp_path / "1.tar").read_bytes() == (tmp_path / "2.tar").read_bytes()
    one.write_directory(str(tmp_path / "d1"))
    old = os.umask(0o077)
    try:
        two.write_directory(str(tmp_path / "d2"))
    finally:
        os.umask(old)
    for rel in one.files:
        assert (tmp_path / "d1" / rel).read_bytes() == (tmp_path / "d2" / rel).read_bytes()
    assert sorted(str(p.relative_to(tmp_path / "d1")) for p in (tmp_path / "d1").rglob("*") if p.is_file()) == \
        sorted(str(p.relative_to(tmp_path / "d2")) for p in (tmp_path / "d2").rglob("*") if p.is_file())


def test_input_order_does_not_change_the_bytes():
    report, files, tools = inputs()
    reversed_files = dict(reversed(list(files.items())))
    a = build_bundle(report=report, files=files, tools=tools, producer={"name": "qa-runner", "version": "0.1.0"})
    b = build_bundle(report=report, files=reversed_files, tools=dict(reversed(list(tools.items()))), producer={"name": "qa-runner", "version": "0.1.0"})
    assert a.files == b.files and a.archive_bytes() == b.archive_bytes()


SCRIPT = """
import sys
sys.path.insert(0, {src!r}); sys.path.insert(0, {tests!r})
from qe_helpers import build_base
b = build_base()
open(sys.argv[1], "wb").write(b.archive_bytes())
print(b.manifest_digest)
"""


@pytest.mark.parametrize("env", [{"TZ": "Pacific/Auckland", "LANG": "C", "PYTHONHASHSEED": "1"}, {"TZ": "America/Los_Angeles", "LC_ALL": "C.UTF-8", "PYTHONHASHSEED": "random"},
                                 {"TZ": "UTC", "PYTHONHASHSEED": "4242", "USER": "someone", "LOGNAME": "someone", "HOSTNAME": "build-host-17"}])
def test_a_fresh_interpreter_with_another_time_zone_locale_hash_seed_user_and_cwd_builds_the_same_bytes(tmp_path, env):
    out = tmp_path / "other.tar"
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()
    full = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1", **env}
    done = subprocess.run([sys.executable, "-I", "-c", SCRIPT.format(src=str(SRC), tests=str(HERE)), str(out)], cwd=cwd, env=full,
                          capture_output=True, text=True, check=True)
    assert done.stdout.strip() == GOLDEN_MANIFEST_DIGEST
    assert out.read_bytes() == build_base().archive_bytes()


def test_the_archive_holds_no_user_host_or_time_information(tmp_path):
    data = build_base().archive_bytes()
    for needle in (os.environ.get("USER", "\x01nouser").encode(), os.uname().nodename.encode(), str(tmp_path).encode(), b"/Users/", b"/home/"):
        assert needle not in data
    assert b"ustar\x00" in data


def test_the_builder_never_reads_a_clock_or_the_environment():
    text = "\n".join(p.read_text(encoding="utf-8") for p in (SRC / "qa_evidence").glob("*.py"))
    for word in ("time.time", "datetime", "getpass", "os.environ", "getuid", "gethostname", "uname(", "os.getlogin", "import random", "uuid"):
        assert word not in text, word


def test_describe_environment_is_only_a_helper_for_callers():
    env = describe_environment()
    assert set(env) == {"os", "arch", "python"} and all(isinstance(v, str) and v for v in env.values())


# ---- builder refusals ---------------------------------------------------------------------------------------------------------------------
def test_the_builder_refuses_an_invalid_report():
    report, files, tools = inputs()
    report["accounting"]["verified"] = 9
    with pytest.raises(BuildError) as exc:
        build_bundle(report=report, files=files, tools=tools)
    assert "ACCOUNTING_COUNT_MISMATCH" in {c for c, _, _ in exc.value.problems}


def test_the_builder_refuses_a_report_that_does_not_match_the_files():
    report, files, tools = inputs()
    files["lanes/robot/native/output.xml"] = (b"other", "native-artifact")
    with pytest.raises(BuildError) as exc:
        build_bundle(report=report, files=files, tools=tools)
    assert "NATIVE_ARTIFACT_MISMATCH" in {c for c, _, _ in exc.value.problems}
    report, files, tools = inputs()
    del files["lanes/robot/observations.json"]
    with pytest.raises(BuildError) as exc:
        build_bundle(report=report, files=files, tools=tools)
    assert "EVIDENCE_NOT_IN_MANIFEST" in {c for c, _, _ in exc.value.problems}


@pytest.mark.parametrize("path,spec,code", [
    ("../x", (b"x", "log"), "PATH_TRAVERSAL"), ("report.json", (b"x", "log"), "RESERVED_PATH"), ("bundle-manifest.json", (b"x", "log"), "RESERVED_PATH"),
    ("anchor.json", (b"x", "log"), "RESERVED_PATH"), ("BUNDLE-FORMAT.txt", (b"x", "log"), "RESERVED_PATH"), ("logs/a.log", (b"x", "report"), "BAD_ROLE"),
    ("logs/a.log", (b"x", "documentation"), "BAD_ROLE"), ("logs/a.log", (b"x", "secret"), "BAD_ROLE"), ("logs/a.log", ("text", "log"), "BAD_DATA")])
def test_the_builder_refuses_unsafe_or_reserved_inputs(path, spec, code):
    report, files, tools = inputs()
    files[path] = spec
    with pytest.raises(BuildError) as exc:
        build_bundle(report=report, files=files, tools=tools)
    assert code in {c for c, _, _ in exc.value.problems}


def test_the_builder_refuses_a_floating_point_value_in_the_report():
    report, files, tools = inputs()
    report["extensions"] = {"ratio": 0.5}
    with pytest.raises(BuildError):
        build_bundle(report=report, files=files, tools=tools)


def test_the_builder_enforces_the_caps():
    from qa_evidence.constants import Limits
    report, files, tools = inputs()
    with pytest.raises(BuildError) as exc:
        build_bundle(report=report, files=files, tools=tools, limits=Limits(max_file_bytes=10))
    assert "OVERSIZE_ENTRY" in {c for c, _, _ in exc.value.problems}


def test_writers_do_not_overwrite_or_follow(tmp_path):
    b = build_base()
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "x").write_text("x")
    with pytest.raises(FileExistsError):
        b.write_directory(str(tmp_path / "d"))
    b.write_archive(str(tmp_path / "a.tar"))
    with pytest.raises(FileExistsError):
        b.write_archive(str(tmp_path / "a.tar"))
    os.symlink(tmp_path / "d", tmp_path / "alias")
    with pytest.raises(FileExistsError):
        b.write_directory(str(tmp_path / "alias"))
    with pytest.raises(BuildError):
        write_directory({"../x": b"x"}, str(tmp_path / "new"))


def test_a_file_name_the_platform_allows_but_the_format_does_not_is_found_in_a_directory(tmp_path):
    b = build_base()
    b.write_directory(str(tmp_path / "d"))
    (tmp_path / "d" / "a\\b.txt").write_bytes(b"x")
    (tmp_path / "d" / "bad name.txt").write_bytes(b"x")
    r = verify_bundle(str(tmp_path / "d"))
    assert "PATH_UNSAFE" in codes(r)
    assert any(f.code == "PATH_UNSAFE" and "a\\b.txt" in f.path for f in r.findings)


def test_read_files_refuses_a_bundle_with_structural_problems(tmp_path):
    b = build_base()
    b.write_directory(str(tmp_path / "d"))
    os.symlink("/etc/hostname", tmp_path / "d" / "l")
    with pytest.raises(BuildError):
        read_files(str(tmp_path / "d"))


# ---- the CI flow: build, publish the manifest digest outside, verify against it later ---------------------------------------------------------
def test_a_ci_style_flow_builds_records_the_digest_and_verifies_against_it_later(tmp_path):
    b = build_base()
    b.write_archive(str(tmp_path / "evidence.tar"))
    published = b.manifest_digest                       # what a CI job would hand to its attestation step; not done here
    anchored = b.with_anchor("ci-artifact-attestation", "run-17/evidence.tar")
    anchored.write_archive(str(tmp_path / "evidence-anchored.tar"))
    assert anchored.manifest_digest == b.manifest_digest
    r = verify_bundle(str(tmp_path / "evidence-anchored.tar"), anchor=published)
    assert r.ok and r.anchor.state == "verified" and r.anchor.reference == "run-17/evidence.tar"
    assert verify_bundle(str(tmp_path / "evidence.tar")).anchor.state == "absent"


def test_the_anchor_document_is_data_only_and_validated():
    doc = anchor_document("ci-artifact-attestation", "ref", "sha256:" + "a" * 64)
    assert set(doc) == {"schema", "schema_version", "anchor_type", "anchor_reference", "manifest_digest"}
    for args in (("trust-me", "ref", "sha256:" + "a" * 64), ("signed-bundle", "ref", "sha256:" + "a" * 64), ("ci-artifact-attestation", "", "sha256:" + "a" * 64), ("ci-artifact-attestation", "ref", "abc")):
        with pytest.raises(BuildError):
            anchor_document(*args)
    assert dumps_canonical(doc).endswith(b"\n")


def test_a_run_with_no_assertions_is_not_a_bundle_and_never_a_verified_outcome():
    """Every lane needs a frozen assertion, so a run that froze nothing cannot be built; and the outcome function never says VERIFIED for it."""
    from qa_evidence.report import assemble_report, assertion_set_digest, compute_outcome
    report, files, tools = inputs()
    empty = assemble_report(run_id="r0-test", started_at=report["started_at"], finished_at=report["finished_at"], plan_digest=assertion_set_digest([]), environment=ENV,
                            lanes=report["lanes"], frozen=[], results=[], verifier={"id": "qa-verify", "version": "0.1.0"})
    assert empty["verdict"]["outcome"] == "INCONCLUSIVE" and compute_outcome([], 0, ["NATIVE_PASS"]) == "INCONCLUSIVE"
    with pytest.raises(BuildError) as exc:
        build_bundle(report=empty, files={"lanes/browser/native/native.txt": (BROWSER_NATIVE, "native-artifact"),
                                          "lanes/robot/native/output.xml": files["lanes/robot/native/output.xml"]}, tools=tools)
    assert "LANE_WITHOUT_ASSERTIONS" in {c for c, _, _ in exc.value.problems}
