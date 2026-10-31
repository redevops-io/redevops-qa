# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Fixtures for the bridge tests. The pinned trees named in pins.toml are put on sys.path first; a missing dependency
makes every test that needs it fail (the ``deps`` fixture raises), never skip."""
import copy
import json
from pathlib import Path

import pytest

from redevops_qa_bridge import deps
from redevops_qa_bridge.pins import load_pins

PINS = load_pins()
deps.prepare_paths(PINS)


@pytest.fixture(scope="session")
def pins():
    return PINS


@pytest.fixture(scope="session")
def contracts(pins):
    return deps.contracts_qa()


@pytest.fixture(scope="session")
def neutral(pins):
    return deps.neutral_qa()


@pytest.fixture(scope="session")
def golden(pins):
    path = pins.contracts.vector_path("golden/qa.json")
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def golden_input(golden, name):
    case = golden["cases"][name]
    data = copy.deepcopy(case["input"])
    if case.get("custody"):
        data["custody"] = case["custody"]
    return data


@pytest.fixture(scope="session")
def gi(golden):
    return lambda name: golden_input(golden, name)
