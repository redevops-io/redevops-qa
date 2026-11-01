# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The command line: ``python -m qa_evidence``. Exit codes, JSON output, and the integrity notice on every path."""
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from qa_evidence.build import write_archive
from qa_evidence.cli import main
from qa_evidence.constants import ANCHOR_ABSENT_NOTICE

from qe_helpers import build_base, build_forged, rechain

SRC = Path(__file__).resolve().parents[1] / "src"


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture()
def good(tmp_path):
    b = build_base()
    b.write_archive(str(tmp_path / "good.tar"))
    b.write_directory(str(tmp_path / "gooddir"))
    return b, str(tmp_path / "good.tar"), str(tmp_path / "gooddir")


@pytest.fixture()
def bad(tmp_path):
    files = dict(build_base().files)
    files["logs/orchestrator.log"] = b"orchestrator log LINE\n"
    write_archive(files, str(tmp_path / "bad.tar"))
    return str(tmp_path / "bad.tar")


def test_inspect_prints_the_summary_and_the_unanchored_notice_for_both_forms(good):
    _, archive, directory = good
    for loc in (archive, directory):
        code, out, _ = run("inspect", loc)
        assert code == 0 and ANCHOR_ABSENT_NOTICE in out and "NATIVE ENGINE RESULTS" in out and "INDEPENDENT VERDICT" in out


def test_verify_exit_codes(good, bad):
    b, archive, directory = good
    assert run("verify", archive)[0] == 0 and run("verify", directory)[0] == 0
    code, out, _ = run("verify", bad)
    assert code == 1 and "DIGEST_MISMATCH" in out
    code, out, _ = run("verify", archive, "--anchor", "sha256:" + "0" * 64)
    assert code == 1 and "ANCHOR_MISMATCH" in out
    assert run("verify", archive, "--anchor", b.manifest_digest)[0] == 0
    assert run("inspect", bad)[0] == 1


def test_require_anchor_makes_an_unanchored_bundle_exit_3(good):
    b, archive, _ = good
    code, out, err = run("verify", archive, "--require-anchor")
    assert code == 3 and ANCHOR_ABSENT_NOTICE in err
    assert run("verify", archive, "--require-anchor", "--anchor", b.manifest_digest)[0] == 0
    assert run("inspect", archive, "--require-anchor")[0] == 3
    assert run("html", archive, "--require-anchor")[0] == 3


def test_a_rechained_forgery_passes_verify_and_says_so(tmp_path):
    forged = build_forged()
    forged.write_archive(str(tmp_path / "f.tar"))
    code, out, _ = run("verify", str(tmp_path / "f.tar"))
    assert code == 0 and "OK: internally consistent" in out and ANCHOR_ABSENT_NOTICE in out
    code, out, _ = run("inspect", str(tmp_path / "f.tar"))
    assert code == 0 and ANCHOR_ABSENT_NOTICE in out
    assert run("verify", str(tmp_path / "f.tar"), "--require-anchor")[0] == 3
    original = build_base().manifest_digest
    assert run("verify", str(tmp_path / "f.tar"), "--anchor", original)[0] == 1


def test_json_output_is_valid_and_carries_the_anchor_state(good):
    b, archive, _ = good
    code, out, _ = run("verify", archive, "--json")
    doc = json.loads(out)
    assert code == 0 and doc["ok"] is True and doc["anchor"]["state"] == "absent" and doc["assurance"] == "internal-consistency-only"
    assert doc["manifest_digest"] == b.manifest_digest and doc["findings"] == []
    code, out, _ = run("inspect", archive, "--json", "--anchor", b.manifest_digest)
    doc = json.loads(out)
    assert code == 0 and doc["verification"]["anchor"]["state"] == "verified" and doc["verification"]["assurance"] == "matches-supplied-anchor"
    assert doc["summary"]["independent_verdict"]["outcome"] == "FAILED" and doc["summary"]["lanes"][0]["native"]["status"] == "NATIVE_PASS"


def test_html_writes_a_new_file_and_refuses_to_overwrite(good, tmp_path):
    _, archive, _ = good
    target = tmp_path / "report.html"
    assert run("html", archive, "-o", str(target))[0] == 0
    page = target.read_text(encoding="utf-8")
    assert ANCHOR_ABSENT_NOTICE in page and page.startswith("<!DOCTYPE html>")
    code, _, err = run("html", archive, "-o", str(target))
    assert code == 2 and "cannot write" in err
    code, out, _ = run("html", archive)
    assert code == 0 and out == page


def test_digest_prints_the_value_an_anchor_should_hold(good, bad):
    b, archive, directory = good
    assert run("digest", archive)[1].strip() == run("digest", directory)[1].strip() == b.manifest_digest
    code, out, err = run("digest", bad)
    assert code == 1 and out == "" and "refusing" in err      # a digest is only named for a bundle that verifies


def test_anchor_prints_data_only_and_refuses_a_bundle_that_does_not_verify(good, bad):
    b, archive, _ = good
    code, out, _ = run("anchor", archive, "--type", "ci-artifact-attestation", "--reference", "run-17")
    doc = json.loads(out)
    assert code == 0 and doc["manifest_digest"] == b.manifest_digest and doc["anchor_type"] == "ci-artifact-attestation" and "attestation" not in doc
    assert set(doc) == {"schema", "schema_version", "anchor_type", "anchor_reference", "manifest_digest"}
    code, _, err = run("anchor", bad, "--type", "ci-artifact-attestation", "--reference", "r")
    assert code == 1 and "refusing" in err
    assert run("anchor", archive, "--type", "bogus", "--reference", "r")[0] == 2


def test_usage_and_io_errors_exit_2(tmp_path):
    assert run()[0] == 2
    assert run("frobnicate", "x")[0] == 2
    code, _, err = run("verify", str(tmp_path / "missing"))
    assert code == 2 and "cannot open" in err
    code, _, err = run("verify", str(tmp_path))
    assert code == 1


def test_a_symlink_given_as_the_bundle_is_refused(good, tmp_path):
    _, archive, _ = good
    os.symlink(archive, tmp_path / "alias.tar")
    code, _, err = run("verify", str(tmp_path / "alias.tar"))
    assert code == 2 and "symbolic link" in err


def test_the_module_entry_point_runs_in_a_clean_interpreter(good):
    b, archive, _ = good
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(SRC), "PYTHONDONTWRITEBYTECODE": "1"}
    done = subprocess.run([sys.executable, "-m", "qa_evidence", "inspect", archive], capture_output=True, text=True, env=env)
    assert done.returncode == 0 and ANCHOR_ABSENT_NOTICE in done.stdout and "QA EVIDENCE BUNDLE" in done.stdout
    done = subprocess.run([sys.executable, "-m", "qa_evidence", "inspect", "--json", archive], capture_output=True, text=True, env=env)
    assert json.loads(done.stdout)["verification"]["anchor"]["state"] == "absent"
    done = subprocess.run([sys.executable, "-m", "qa_evidence", "--version"], capture_output=True, text=True, env=env)
    assert done.stdout.startswith("qa-evidence ")
