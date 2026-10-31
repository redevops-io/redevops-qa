# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The same scenario gives the same bytes, in this process and under different hash seeds."""
import subprocess
import sys
from pathlib import Path

import pytest

from qa_pw_scenario import digest

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"


def test_the_scenario_is_repeatable_in_one_process():
    assert digest() == digest()


@pytest.mark.parametrize("seed", ["0", "1", "777"])
def test_the_scenario_digest_does_not_depend_on_the_hash_seed(seed, pins):
    bridge = HERE.parents[1] / "qa-bridge" / "src"
    env = {"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": seed, "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONPATH": ":".join(str(p) for p in (HERE, SRC, bridge, pins.harness_qa.resolved_path, pins.contracts.resolved_path)),
           "REDEVOPS_QA_PIN_SET": pins.set_name if hasattr(pins, "set_name") else "c4",
           "QA_PIN_CONTRACTS_PATH": str(pins.contracts.resolved_path), "QA_PIN_HARNESS_QA_PATH": str(pins.harness_qa.resolved_path)}
    done = subprocess.run([sys.executable, "-c", "import conftest, qa_pw_scenario, sys; sys.stdout.write(qa_pw_scenario.digest())"],
                          env=env, capture_output=True, text=True, cwd=str(HERE))
    assert done.returncode == 0, done.stderr
    assert done.stdout == digest()
