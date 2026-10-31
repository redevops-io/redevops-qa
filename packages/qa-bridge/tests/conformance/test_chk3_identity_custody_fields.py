# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Conformance check CHK3: one test per item (see redevops_qa_bridge.conformance.items)."""
from redevops_qa_bridge.conformance.checks import run_item

CHECK = "CHK3"


def test_item(item):
    run_item(item)
