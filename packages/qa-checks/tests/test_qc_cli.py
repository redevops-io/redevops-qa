# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The hash-pinned command line runs the identical code as the library and the adapter."""
import json
import subprocess
import sys

import pytest

from redevops_qa_checks import cli
from redevops_qa_checks.canonical import canonical_bytes
from redevops_qa_checks.engine import CheckEngine

ID = "manifest.image-references"


def test_list_prints_every_program_with_its_hash(registry, capsys):
    assert cli.main(["list"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == len(registry) and f"{ID} 1.0.0 {registry.registered_program_hash(ID, '1.0.0')}" in lines


def test_run_prints_the_same_value_the_engine_returns(case_root, registry, capsys):
    h = registry.registered_program_hash(ID, "1.0.0")
    assert cli.main(["run", "--case-root", str(case_root), "--program", f"{ID}@1.0.0", "--program-hash", h, "--input", "."]) == 0
    printed = json.loads(capsys.readouterr().out)
    out = CheckEngine(case_root, registry).run_check({"check_program_ref": {"id": ID, "version": "1.0.0", "program_hash": h},
                                                      "inputs": [{"kind": "MANIFEST_PATH", "path": "."}], "tier": "OFFLINE"})
    assert printed == {"resolution": "RESOLVED", "value": json.loads(canonical_bytes(out.value))}


def test_a_wrong_hash_is_refused_with_exit_2_and_nothing_on_stdout(case_root, capsys):
    rc = cli.main(["run", "--case-root", str(case_root), "--program", f"{ID}@1.0.0", "--program-hash", "sha256:" + "0" * 64, "--input", "."])
    out = capsys.readouterr()
    assert rc == 2 and out.out == "" and json.loads(out.err)["error"] == "PROGRAM_HASH_MISMATCH"


def test_an_unknown_program_is_refused(case_root, capsys):
    assert cli.main(["run", "--case-root", str(case_root), "--program", "manifest.no@1.0.0", "--program-hash", "sha256:" + "0" * 64, "--input", "."]) == 2


def test_the_hash_is_required_and_there_is_no_expected_option(case_root):
    with pytest.raises(SystemExit):
        cli.main(["run", "--case-root", str(case_root), "--program", f"{ID}@1.0.0", "--input", "."])
    for flag in ("--expected", "--verdict", "--expect"):
        with pytest.raises(SystemExit):
            cli.main(["run", "--case-root", str(case_root), "--program", f"{ID}@1.0.0", "--program-hash", "sha256:" + "0" * 64, flag, "x"])


def test_a_missing_input_exits_3_with_a_resolution_not_a_value(case_root, registry, capsys):
    h = registry.registered_program_hash(ID, "1.0.0")
    assert cli.main(["run", "--case-root", str(case_root), "--program", f"{ID}@1.0.0", "--program-hash", h, "--input", "missing"]) == 3
    assert json.loads(capsys.readouterr().out) == {"match_count": 0, "resolution": "UNRESOLVED"}


def test_the_module_runs_as_a_script_with_a_scrubbed_environment(case_root, registry, tmp_path):
    h = registry.registered_program_hash(ID, "1.0.0")
    import os
    from pathlib import Path
    src = str(Path(cli.__file__).resolve().parents[1])
    proc = subprocess.run([sys.executable, "-B", "-m", "redevops_qa_checks.cli", "run", "--case-root", str(case_root), "--program", f"{ID}@1.0.0",
                           "--program-hash", h, "--input", "."], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "PYTHONPATH": src + os.pathsep + os.environ.get("PYTHONPATH", ""), "HOME": str(tmp_path)})
    assert proc.returncode == 0 and json.loads(proc.stdout)["resolution"] == "RESOLVED"
