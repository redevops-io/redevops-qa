# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""`pack` is the one writer of the canonical archive form a bundle takes as a single file (qa_evidence.tarfmt). The service serves
`/v1/runs/<id>/bundle.tar` as exactly what `pack` writes, so this is the cross-layer check that was missing when the service re-tarred bundles with
Python's tarfile: an archive made by a generic writer carries extended (PAX) headers and directory members, and `verify` refuses such bytes as
findings. Here a real bundle goes directory -> pack -> archive -> verify, through the real command, offline."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from qa_evidence.build import build_bundle
from qa_evidence.canon import sha256_bytes
from qa_evidence.report import assemble_report, assertion_set_digest
from qa_evidence.verify import verify_bundle

ROOT = Path(__file__).resolve().parents[1]
PKG_SRC = [str(p) for p in sorted((ROOT / "packages").glob("*/src"))]

BROWSER_NATIVE = b"browser native report\n"
BROWSER_OBS = b'{"final_url": "/settings?saved=1", "save_status": "Settings saved"}\n'
LOG = b"orchestrator log line\n"
A1, A2 = ("sha256:" + c * 64 for c in "12")


def one_lane_bundle():
    """The smallest bundle the real builder accepts: one browser lane, two assertions the fixture reference restates."""
    lanes = [{"lane_id": "browser", "run_id": "r0-pack.browser", "engine": {"name": "playwright", "version": "1.64.1"},
              "native": {"status": "NATIVE_PASS", "raw_status": "passed", "exit_code": 0, "counts": {"passed": 2, "failed": 0, "errored": 0, "skipped": 0},
                         "artifacts": [{"path": "lanes/browser/native/native.txt", "digest": sha256_bytes(BROWSER_NATIVE), "size": len(BROWSER_NATIVE)}]}}]
    frozen = [{"assertion_id": "A-STATUS", "lane_id": "browser", "digest": A1}, {"assertion_id": "A-URL", "lane_id": "browser", "digest": A2}]
    results = [{"assertion_id": "A-STATUS", "native_status": "NATIVE_PASS", "state": "VERIFIED", "reason_code": "EQUALS_EXPECTED",
                "evidence": {"path": "lanes/browser/observations.json", "digest": sha256_bytes(BROWSER_OBS)}},
               {"assertion_id": "A-URL", "native_status": "NATIVE_PASS", "state": "VERIFIED", "reason_code": "EQUALS_EXPECTED",
                "evidence": {"path": "lanes/browser/observations.json", "digest": sha256_bytes(BROWSER_OBS)}}]
    report = assemble_report(run_id="r0-pack", started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:09Z",
                             plan_digest=assertion_set_digest(frozen), environment={"os": "linux", "arch": "x86_64", "python": "3.12.3"},
                             lanes=lanes, frozen=frozen, results=results, verifier={"id": "qa-verify", "version": "0.1.0"},
                             redaction={"applied": True, "rules": [{"id": "env-values", "description": "environment variable values removed", "count": 1}], "notes": []},
                             ceiling="VERIFIED")
    files = {"lanes/browser/native/native.txt": (BROWSER_NATIVE, "native-artifact"), "lanes/browser/observations.json": (BROWSER_OBS, "observation"),
             "logs/orchestrator.log": (LOG, "log")}
    return build_bundle(report=report, files=files, tools={"orchestrator": "0.1.0", "qa-verify": "0.1.0"}, producer={"name": "qa-runner", "version": "0.1.0"})


def cli(*argv, binary_stdout: bool = False):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(PKG_SRC))
    done = subprocess.run([sys.executable, "-s", "-m", "qa_runner", *argv], env=env, cwd=str(ROOT),
                          capture_output=True, timeout=180, check=False)
    return done.returncode, done.stdout, done.stderr.decode("utf-8", "replace")


def test_pack_of_a_directory_writes_the_canonical_archive_bytes_of_the_bundle(tmp_path):
    bb = one_lane_bundle()
    bb.write_directory(str(tmp_path / "bundle"))
    rc, out, err = cli("pack", str(tmp_path / "bundle"), "--out", str(tmp_path / "pack.tar"))
    assert rc == 0, err
    assert (tmp_path / "pack.tar").read_bytes() == bb.archive_bytes()      # byte for byte the form this package's own writer defines


def test_a_packed_bundle_verifies_as_an_archive_offline_and_repacks_to_the_same_bytes(tmp_path):
    bb = one_lane_bundle()
    bb.write_directory(str(tmp_path / "bundle"))
    rc, out, err = cli("pack", str(tmp_path / "bundle"), "--out", str(tmp_path / "pack.tar"))
    assert rc == 0, err
    r = verify_bundle(str(tmp_path / "pack.tar"))                          # the strict reader and the integrity recomputation, over the packed bytes
    assert r.ok and r.form == "archive" and r.manifest_digest == bb.manifest_digest and r.file_count == len(bb.files)
    rc, out, err = cli("pack", str(tmp_path / "pack.tar"), "--out", str(tmp_path / "pack2.tar"))
    assert rc == 0 and (tmp_path / "pack2.tar").read_bytes() == (tmp_path / "pack.tar").read_bytes(), err


def test_pack_writes_the_same_bytes_to_stdout(tmp_path):
    bb = one_lane_bundle()
    bb.write_directory(str(tmp_path / "bundle"))
    rc, out, err = cli("pack", str(tmp_path / "bundle"))                   # stdout captured as a pipe is binary: what a CGI-style caller gets
    assert rc == 0, err
    assert out == bb.archive_bytes()


def test_pack_refuses_an_archive_re_written_by_a_generic_writer_without_writing_anything(tmp_path):
    """The bug this command closes: what `tarfile`/system tar produce is readable by tar tools but is not the canonical form, and `verify` rejects it (exit 5)."""
    bb = one_lane_bundle()
    bb.write_directory(str(tmp_path / "bundle"))
    with tarfile.open(tmp_path / "generic.tar", mode="w") as tf:           # Python's default writer: PAX headers, directory members
        tf.add(str(tmp_path / "bundle"), arcname="bundle")
    with pytest.raises(Exception):                                         # the strict reader refuses it before any output exists...
        from qa_evidence.build import read_files
        read_files(str(tmp_path / "generic.tar"))
    rc, out, err = cli("pack", str(tmp_path / "generic.tar"), "--out", str(tmp_path / "never.tar"))
    assert rc == 2 and "BUNDLE_NOT_CANONICAL" in err
    assert not (tmp_path / "never.tar").exists()                           # ...and pack writes nothing
    rc, out, err = cli("verify", str(tmp_path / "generic.tar"), "--json")  # and the plain user path says why: the archive form, not the evidence, is what fails
    assert rc == 5
    codes = {f["code"] for f in json.loads(out)["findings"]}
    assert "ARCHIVE_NONCANONICAL" in codes or "MANIFEST_MISSING" in codes