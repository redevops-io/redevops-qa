# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The plain-Python reference check reports each seeded defect, and only that defect, over HTTP against a running app (in-process
and as a separate process), and its own arithmetic is independent of the app's."""
import json
import re
import sys
import subprocess

import pytest
import qfa_support as s

from qa_fixture_app import create_server, reference_check

EXPECTED = {"none": [], "discount": ["discount-rule"], "settings": ["settings-persistence"]}


@pytest.mark.parametrize("mode", s.MODES)
def test_the_reference_check_reports_exactly_the_seeded_defect(mode):
    with create_server(mode) as server:
        result = reference_check.run_checks(server.url)
    assert sorted({d["check"] for d in result["deviations"]}) == EXPECTED[mode]
    assert result["checked"] == ["discount-rule", "settings-persistence"]


def test_the_discount_deviations_name_the_orders_and_boundaries_that_are_wrong():
    with create_server("discount") as server:
        result = reference_check.run_checks(server.url)
    assert sorted(d["where"] for d in result["deviations"]) == sorted([
        "/api/orders/101", "/api/orders/103", "/api/orders/104", "/api/discount?subtotal_cents=10000",
        "/api/discount?subtotal_cents=10005", "/api/discount?subtotal_cents=10500"])


@pytest.mark.parametrize("mode", s.MODES)
def test_the_command_line_exit_status_is_0_without_a_deviation_and_1_with_one(mode, tmp_path):
    with s.spawn(tmp_path, defect=mode) as run:
        out = subprocess.run([sys.executable, "-m", "qa_fixture_app.reference_check", run.url], cwd=str(tmp_path), env=s.child_env(),
                             capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        run.proc.terminate()
        run.proc.wait(timeout=30)
    assert out.returncode == (0 if mode == "none" else 1), out.stderr
    assert sorted({d["check"] for d in json.loads(out.stdout)["deviations"]}) == EXPECTED[mode]


def test_an_unreachable_or_non_loopback_target_exits_2(tmp_path):
    with create_server() as gone:
        url = gone.url
    for target in (url, "http://example.com:80"):
        out = subprocess.run([sys.executable, "-m", "qa_fixture_app.reference_check", target], cwd=str(tmp_path), env=s.child_env(),
                             capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        assert out.returncode == 2 and out.stdout == "" and out.stderr.startswith("error:"), target


@pytest.mark.parametrize("lines,expected", [([(2, 4000), (1, 2500)], (10500, 1050, 9450)), ([(1, 9999)], (9999, 0, 9999)),
                                            ([(1, 10000)], (10000, 1000, 9000)), ([(1, 10005)], (10005, 1000, 9005))])
def test_the_reference_arithmetic_matches_the_documented_numbers(lines, expected):
    t = reference_check.expected_totals(lines)
    assert (t["subtotal_cents"], t["discount_cents"], t["total_cents"]) == expected


def test_the_reference_check_shares_no_code_with_the_app():
    text = (s.SRC / "qa_fixture_app" / "reference_check.py").read_text(encoding="utf-8")
    assert not re.search(r"^\s*(from \.|from qa_fixture_app|import qa_fixture_app)", text, re.M)
