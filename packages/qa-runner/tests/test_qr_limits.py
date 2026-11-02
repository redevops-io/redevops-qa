# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The operator's limits from the environment are parsed strictly (retest L-R2): a finite positive number inside a sane range, or exit 2 with a message that names the variable. Never a traceback,
never `nan`, `inf` or a huge number that amounts to no limit, never zero."""
import sys

import pytest

from qa_runner import constants as K
from qa_runner import limits
from qa_runner.errors import PlanError
from qa_runner.procs import child_env
from qr_support import run_limited

BAD_SECONDS = ["abc", "nan", "inf", "-inf", "0", "-5", "0.5", "1e9", "1e400", "3601", "99999999", " 5", "5 ", "0x10", "1_0", "５"]
GOOD_SECONDS = {"1": 1.0, "30": 30.0, "2.5": 2.5, "3600": 3600.0}


@pytest.mark.parametrize("value", BAD_SECONDS)
def test_a_bad_timeout_is_refused_by_name(monkeypatch, value):
    monkeypatch.setenv("REDEVOPS_QA_READ_TIMEOUT", value)
    with pytest.raises(PlanError) as exc:
        limits.env_seconds("REDEVOPS_QA_READ_TIMEOUT", 30.0)
    assert exc.value.code == "BAD_ENV_LIMIT" and "REDEVOPS_QA_READ_TIMEOUT" in str(exc.value)


@pytest.mark.parametrize("value,expected", list(GOOD_SECONDS.items()))
def test_a_good_timeout_is_taken(monkeypatch, value, expected):
    monkeypatch.setenv("REDEVOPS_QA_READ_TIMEOUT", value)
    assert limits.env_seconds("REDEVOPS_QA_READ_TIMEOUT", 30.0) == expected


def test_an_unset_or_empty_variable_is_the_default(monkeypatch):
    monkeypatch.delenv("REDEVOPS_QA_READ_TIMEOUT", raising=False)
    assert limits.env_seconds("REDEVOPS_QA_READ_TIMEOUT", 30.0) == 30.0
    monkeypatch.setenv("REDEVOPS_QA_READ_TIMEOUT", "")
    assert limits.env_seconds("REDEVOPS_QA_READ_TIMEOUT", 30.0) == 30.0


@pytest.mark.parametrize("value", ["abc", "nan", "inf", "0", "-1", "1023", "8589934593", "1e9", "1.5", "99999999999999", ""[:0] + "0x400"])
def test_a_bad_byte_limit_is_refused_by_name(monkeypatch, value):
    monkeypatch.setenv("REDEVOPS_QA_MAX_EVIDENCE_BYTES", value)
    with pytest.raises(PlanError) as exc:
        limits.env_bytes("REDEVOPS_QA_MAX_EVIDENCE_BYTES", 1)
    assert exc.value.code == "BAD_ENV_LIMIT" and "REDEVOPS_QA_MAX_EVIDENCE_BYTES" in str(exc.value)


@pytest.mark.parametrize("name,value", [("REDEVOPS_QA_READ_TIMEOUT", "nan"), ("REDEVOPS_QA_READ_TIMEOUT", "abc"), ("REDEVOPS_QA_READ_TIMEOUT", "1e9"), ("REDEVOPS_QA_READ_TIMEOUT", "0"),
                                        ("REDEVOPS_QA_MAX_EVIDENCE_BYTES", "inf"), ("REDEVOPS_QA_MAX_EVIDENCE_BYTES", "-3"), ("REDEVOPS_QA_MAX_EVIDENCE_BYTES", "0")])
def test_the_command_line_refuses_a_bad_limit_with_exit_2_and_no_traceback(tmp_path, name, value):
    import json
    from qa_runner.golden import golden_plan
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(golden_plan()))
    env = child_env(str(tmp_path))
    env[name] = value
    argv = ["doctor", "--plan", str(plan)] if "READ" in name else ["run", str(plan), "--out", str(tmp_path / "o")]
    code, out, err = run_limited([sys.executable, "-s", "-m", "qa_runner", *argv], timeout=60, env=env, cwd=str(tmp_path))
    assert code == K.EXIT_USAGE and "BAD_ENV_LIMIT" in err and name in err and "Traceback" not in err, (code, err)
    assert not (tmp_path / "o").exists() or not any((tmp_path / "o").iterdir())


def test_a_bad_evidence_limit_is_refused_before_a_directory_is_made_or_anything_starts(up, golden_frozen, monkeypatch):
    import qa_runner.orchestrate as orch
    monkeypatch.setenv("REDEVOPS_QA_MAX_EVIDENCE_BYTES", "nan")
    monkeypatch.setattr(orch, "make_workdir", lambda *a, **k: (_ for _ in ()).throw(AssertionError("a directory was made")))
    with pytest.raises(PlanError) as exc:
        orch.run_plan(up, golden_frozen, orch.RunOptions(run_id="r0-test"))
    assert exc.value.code == "BAD_ENV_LIMIT"
