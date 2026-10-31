# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Helper for mutation tests: run named tests against a copy of the package source in which one guard has been removed.

A guard is only worth having if removing it makes the suite fail. ``mutant_result`` copies ``packages/qa-checks/src`` into a
temporary directory, replaces one exact piece of source (it must occur exactly once), and runs the selected tests in a fresh
interpreter that imports the mutated copy. ``baseline_result`` runs the same tests against an unmodified copy, so a mutation
test also proves that the selected tests pass when the guard is present."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

PKG = Path(__file__).resolve().parents[1]
REPO = PKG.parents[1]
KEEP_ENV = ("PATH", "HOME", "LANG", "QA_PIN_CONTRACTS_PATH", "QA_PIN_HARNESS_QA_PATH", "REDEVOPS_QA_PIN_SET")


def _run(work: Path, tests: Sequence[str]) -> subprocess.CompletedProcess:
    ini = work / "mutant.ini"
    ini.write_text("[pytest]\npythonpath = %s %s\naddopts = -p no:cacheprovider -q\nfilterwarnings = error\n"
                   % (REPO / "packages" / "qa-bridge" / "src", work / "src"), encoding="utf-8")
    env = {k: os.environ[k] for k in KEEP_ENV if k in os.environ}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    cmd = [sys.executable, "-m", "pytest", "-c", str(ini), "--rootdir", str(work), *[str(PKG / "tests" / t) for t in tests]]
    return subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=300)


def _copy(tmp: Path) -> Path:
    work = tmp / "mutant"
    shutil.copytree(PKG / "src", work / "src", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return work


def baseline_result(tmp: Path, tests: Sequence[str]) -> subprocess.CompletedProcess:
    return _run(_copy(tmp), tests)


def mutant_result(tmp: Path, rel: str, old, new, tests: Sequence[str]) -> subprocess.CompletedProcess:
    work = _copy(tmp)
    target = work / "src" / "redevops_qa_checks" / rel
    text = target.read_text(encoding="utf-8")
    olds, news = ((old,), (new,)) if isinstance(old, str) else (tuple(old), tuple(new))
    for o, n in zip(olds, news):
        if text.count(o) != 1:
            raise AssertionError(f"mutation anchor must occur exactly once in {rel}; found {text.count(o)}: {o!r}")
        text = text.replace(o, n)
    target.write_text(text, encoding="utf-8")
    return _run(work, tests)
