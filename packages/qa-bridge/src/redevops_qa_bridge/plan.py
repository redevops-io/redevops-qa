# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Plan validation at the boundary: only ``coverage_contract = FULL`` reaches the harness.

The harness receives no plan record (ADR A.2.4 item 7): budgets and recovery limits arrive in ``TestSpec.budget`` and
full coverage is enforced inside the harness by the coverage-list invariants. Rejecting ``SUBSET`` happens where the
plan is read, and this module is that place for ``redevops-qa``. :func:`validate_plan` returns validated plain data;
:func:`runnable_items` returns the items in run order only after the whole plan validated, so no item can be released
from a plan that is refused.

Each guard is a named function so a test can remove it and prove the refusal it provides disappears with it.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, Mapping, Tuple

from . import deps
from .convert import assert_data_only
from .errors import Codes, PlanRejected, UnsupportedCoverageContract

FULL = "FULL"


def _guard_full_coverage(coverage_contract: Any) -> None:
    if coverage_contract != FULL:
        raise UnsupportedCoverageContract(
            f"coverage_contract {coverage_contract!r} is not supported; only FULL is accepted and no partial coverage "
            "is certified anywhere", coverage_contract=str(coverage_contract))


def _guard_plan_parses(data: Mapping[str, Any]) -> Any:
    c = deps.contracts_qa()
    try:
        return c.QAPlan.from_json(copy.deepcopy(dict(data)))
    except c.QAContractError as exc:
        raise PlanRejected(str(getattr(exc, "detail", exc)), reason_code=exc.code) from exc


def validate_plan(plan: Any) -> Dict[str, Any]:
    """Validate a plan given as JSON data (or as a contracts ``QAPlan``) and return it as validated plain data.

    Refused before anything else: a ``coverage_contract`` that is not ``FULL`` (``UNSUPPORTED_COVERAGE_CONTRACT``).
    Then the contracts validator runs (unknown field, lane and gate rules, ...; the contracts reason code is kept).
    """
    c = deps.contracts_qa()
    if isinstance(plan, c.QAPlan):
        data = plan.to_json()
    else:
        assert_data_only(plan, "plan")
        data = plan
    if not isinstance(data, Mapping):
        raise PlanRejected("a plan is a JSON object", reason_code=Codes.PLAN_INVALID)
    if "coverage_contract" in data:
        _guard_full_coverage(data["coverage_contract"])
    parsed = _guard_plan_parses(data)
    _guard_full_coverage(parsed.coverage_contract.value)      # the parsed object is checked again, not just the input
    out = parsed.to_json()
    assert_data_only(out, "validated plan")
    return out


def runnable_items(plan: Any) -> Tuple[Dict[str, Any], ...]:
    """The plan's items as plain data, in lane/order sequence, released only after the whole plan validated."""
    validated = validate_plan(plan)
    items = sorted(validated["items"], key=lambda i: (validated["lanes"].index(i["lane"]), i["order"]))
    return tuple(copy.deepcopy(i) for i in items)
