# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Fixtures for the qa-checks tests. The pinned harness tree from pins.toml is put on sys.path (the neutral module is
imported from there, never installed); a missing dependency makes the tests that need it fail, never skip."""
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from redevops_qa_bridge import deps                      # noqa: E402
from redevops_qa_bridge.pins import load_pins            # noqa: E402

deps.prepare_paths(load_pins())

from qc_fixtures import good_set, write_tree                # noqa: E402
from redevops_qa_checks.registry import builtin_registry  # noqa: E402


@pytest.fixture(scope="session")
def neutral():
    return deps.neutral_qa()


@pytest.fixture(scope="session")
def registry():
    return builtin_registry()


@pytest.fixture
def case_root(tmp_path):
    return write_tree(tmp_path / "case", good_set())
