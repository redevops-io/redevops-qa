# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Mutation helper for the qa-runner tests: run named tests against a copy of ``qa_runner`` in which one guard has been removed. The copy is put FIRST on the
import path; every other package comes from the checkout as usual. A guard is only worth having if removing it makes a named test fail, and the same tests must
pass on an unmodified copy."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

PKG = Path(__file__).resolve().parents[1]
ROOT = PKG.parents[1]
KEEP_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "REDEVOPS_QA_PINS", "REDEVOPS_QA_PIN_SET", "QA_PIN_CONTRACTS_PATH", "QA_PIN_HARNESS_QA_PATH")
OTHER_SRC = ("qa-bridge", "qa-playwright", "qa-egress", "qa-adapter-kit", "qa-checks", "qa-robot", "qa-evidence", "qa-fixture-app")


def _run(work: Path, tests: Sequence[str]) -> subprocess.CompletedProcess:
    paths = [str(work / "src")] + [str(ROOT / "packages" / p / "src") for p in OTHER_SRC]
    ini = work / "mutant.ini"
    ini.write_text("[pytest]\npythonpath = %s\naddopts = -p no:cacheprovider -q -x\nfilterwarnings = error\n" % " ".join(paths), encoding="utf-8")
    env = {k: os.environ[k] for k in KEEP_ENV if k in os.environ}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    cmd = [sys.executable, "-m", "pytest", "-c", str(ini), "--rootdir", str(work), *[str(PKG / "tests" / t) for t in tests]]
    return subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=600)


def _copy(tmp: Path) -> Path:
    work = tmp / "mutant"
    shutil.copytree(PKG / "src", work / "src", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return work


def baseline_result(tmp: Path, tests: Sequence[str]) -> subprocess.CompletedProcess:
    return _run(_copy(tmp), tests)


def mutant_result(tmp: Path, rel: str, old, new, tests: Sequence[str]) -> subprocess.CompletedProcess:
    work = _copy(tmp)
    target = work / "src" / "qa_runner" / rel
    text = target.read_text(encoding="utf-8")
    olds, news = ((old,), (new,)) if isinstance(old, str) else (tuple(old), tuple(new))
    for o, n in zip(olds, news):
        if text.count(o) != 1:
            raise AssertionError(f"mutation anchor must occur exactly once in {rel}; found {text.count(o)}: {o!r}")
        text = text.replace(o, n)
    target.write_text(text, encoding="utf-8")
    return _run(work, tests)
