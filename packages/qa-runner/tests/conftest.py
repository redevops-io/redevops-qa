# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Fixtures for the qa-runner tests. The pinned trees named in pins.toml are put on sys.path (the same helper the bridge uses); a missing dependency makes
the tests that need it fail, never skip. Nothing here installs anything or reaches a host other than loopback."""
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from redevops_qa_bridge import deps                      # noqa: E402
from redevops_qa_bridge.pins import load_pins            # noqa: E402

deps.prepare_paths(load_pins())


@pytest.fixture(scope="session")
def up():
    from qa_runner.deps import bootstrap
    return bootstrap()


@pytest.fixture(scope="session")
def golden_frozen(up):
    from qa_runner.golden import golden_plan
    from qa_runner.plan import freeze_plan
    return freeze_plan(up, golden_plan())
