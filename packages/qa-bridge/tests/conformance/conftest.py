# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Parametrises every conformance module over the items of its check. A test module sets ``CHECK = "CHKn"``."""
import pytest

from redevops_qa_bridge.conformance.items import enumerate_items

_ITEMS = None


def _items():
    global _ITEMS
    if _ITEMS is None:
        _ITEMS = enumerate_items()
    return _ITEMS


def pytest_generate_tests(metafunc):
    if "item" not in metafunc.fixturenames:
        return
    check = metafunc.module.CHECK
    items = _items()[check]
    metafunc.parametrize("item", [pytest.param(i, id=i.item_id, marks=pytest.mark.check(check)) for i in items])
