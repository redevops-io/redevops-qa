# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Observation tags with the real Robot Framework 7.5: a runtime ``Set Tags`` appears in output.xml and is read by the importer. Runs only in the ``robot-real`` job."""
import sys
import textwrap

import pytest

from qa_adapter_kit import MalformedReport, Status, SuiteRunRequest, SuiteRunner
from qa_robot import RobotConfig, RobotSuiteAdapter, parse_observations

pytestmark = pytest.mark.robot_real

SUITE = textwrap.dedent('''\
    *** Test Cases ***
    Records Observations
        ${total}=    Set Variable    9450
        Set Tags    qa-observe:order_total_cents=${total}
        Set Tags    qa-observe:banner=Hello
        Should Be Equal    ${total}    9450
    ''')


def run(tmp_path, text, name="suite/s.robot"):
    ws, out = tmp_path / "workspace", tmp_path / "output"
    (ws / "suite").mkdir(parents=True)
    out.mkdir()
    (ws / name).write_text(text)
    adapter = RobotSuiteAdapter(sys.executable, config=RobotConfig(keep_raw_output=True))
    req = SuiteRunRequest(run_id="real-obs", adapter_id="robot-suite", workspace=str(ws), suite_path="suite", output_dir=str(out))
    return SuiteRunner(adapter).run(req), out


def test_a_runtime_tag_set_by_a_real_run_is_read_back_as_a_typed_observation(robot_installed, tmp_path):
    r, out = run(tmp_path, SUITE)
    assert r.status is Status.PASS, (r.error_code, r.error_message)
    obs = parse_observations((out / "output.xml").read_bytes())
    assert dict(obs.values) == {"banner": "Hello", "order_total_cents": 9450} and obs.engine_release == "7.5"


def test_a_failing_test_still_records_what_it_saw_before_it_failed(robot_installed, tmp_path):
    text = SUITE.replace("Should Be Equal    ${total}    9450", "Should Be Equal    ${total}    1")
    r, out = run(tmp_path, text)
    assert r.status is Status.FAIL
    assert dict(parse_observations((out / "output.xml").read_bytes()).values)["order_total_cents"] == 9450


def test_a_tag_that_looks_like_an_expected_value_is_refused_from_a_real_report(robot_installed, tmp_path):
    r, out = run(tmp_path, SUITE.replace("qa-observe:banner=Hello", "qa-observe:expected=9450"))
    assert r.status is Status.PASS
    with pytest.raises(MalformedReport):
        parse_observations((out / "output.xml").read_bytes())
