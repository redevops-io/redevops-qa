# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The command line and doctor: usage errors, exit codes, and a doctor that reports and never installs."""
import io
import json
import subprocess

import pytest

import qa_runner.doctor as doctor
from qa_runner import constants as K
from qa_runner.cli import main
from qa_runner.golden import golden_plan


def cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), out, err)
    return code, out.getvalue(), err.getvalue()


def plan_file(tmp_path, plan=None):
    p = tmp_path / "plan.json"
    p.write_text(json.dumps(golden_plan() if plan is None else plan))
    return str(p)


def test_a_missing_command_or_option_is_a_usage_error():
    assert cli()[0] == 2
    assert cli("run")[0] == 2
    assert cli("run", "plan.json", "--out", "x", "--defect", "everything")[0] == 2
    assert cli("frobnicate")[0] == 2


def test_version_exits_zero(capsys):
    assert cli("--version")[0] == 0
    assert "redevops-qa " in capsys.readouterr().out


def test_a_missing_plan_file_is_refused(tmp_path):
    code, out, err = cli("run", str(tmp_path / "nope.json"), "--out", str(tmp_path / "o"))
    assert code == K.EXIT_USAGE and "PLAN_UNREADABLE" in err and out == ""


def test_a_plan_with_an_unknown_field_is_refused_before_anything_runs(tmp_path):
    plan = golden_plan()
    plan["lanes"][0]["spec"]["assertions"][0]["verdict"] = "PASS"
    code, out, err = cli("run", plan_file(tmp_path, plan), "--out", str(tmp_path / "o"))
    assert code == K.EXIT_USAGE and "SPEC_REJECTED" in err and not (tmp_path / "o").exists()


def test_a_plan_that_is_not_json_is_refused(tmp_path):
    p = tmp_path / "p.json"
    p.write_text("{nope")
    assert cli("run", str(p), "--out", str(tmp_path / "o"))[0] == K.EXIT_USAGE


def test_an_existing_bundle_directory_is_never_overwritten(tmp_path):
    (tmp_path / "o" / "r0-fixed").mkdir(parents=True)
    code, out, err = cli("run", plan_file(tmp_path), "--out", str(tmp_path / "o"), "--run-id", "r0-fixed")
    assert code == K.EXIT_USAGE and "OUTPUT_EXISTS" in err


def test_hostile_text_in_an_error_is_escaped(tmp_path):
    code, out, err = cli("run", str(tmp_path / "x\x1b[2Jy.json"), "--out", str(tmp_path / "o"))
    assert code == K.EXIT_USAGE and "\x1b" not in err


# ---- doctor ----------------------------------------------------------------------------------------------------------------------------------
def test_a_crash_of_the_runner_has_its_own_exit_status_and_leaks_nothing(monkeypatch):
    import qa_runner.cli as cli_module

    def boom(args, out, err):
        raise RuntimeError("secret detail from somewhere")
    monkeypatch.setattr(cli_module, "_doctor", boom)
    code, out, err = cli("doctor")
    assert code == K.EXIT_INTERNAL == 6 and err == "internal error: RuntimeError\n" and out == ""


def test_the_python_check_names_the_floor():
    assert doctor.check_python((3, 10)).status == "FAIL" and "3.11" in doctor.check_python((3, 10)).remedy
    assert doctor.check_python((3, 11)).status == "OK" and doctor.check_python((3, 13)).status == "OK"


@pytest.mark.parametrize("system,machine,status", [("Linux", "x86_64", "OK"), ("Linux", "AMD64", "OK"), ("Linux", "aarch64", "WARN"), ("Darwin", "arm64", "WARN"),
                                                    ("Windows", "AMD64", "WARN")])
def test_only_linux_x86_64_is_the_supported_platform(system, machine, status):
    c = doctor.check_platform(system, machine)
    assert c.status == status
    if status == "WARN":
        assert "development evidence" in c.detail


def test_a_missing_playwright_fails_with_the_remedy_and_installs_nothing(monkeypatch):
    monkeypatch.setattr(doctor, "_version", lambda dist: None)
    spy = []
    c = doctor.check_playwright(run=lambda *a, **k: spy.append(a))
    assert c.status == "FAIL" and "not installed" in c.detail and "pip install playwright==1.64.1" in c.remedy and spy == []


def test_another_playwright_version_fails(monkeypatch):
    monkeypatch.setattr(doctor, "_version", lambda dist: "1.0.0")
    assert doctor.check_playwright(run=lambda *a, **k: None).status == "FAIL"


def test_a_playwright_without_a_launchable_chromium_fails_with_the_install_command(monkeypatch):
    monkeypatch.setattr(doctor, "_version", lambda dist: doctor.PLAYWRIGHT_PIN)
    seen = []

    def run(argv, **kw):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 1, "", "browserType.launch: Executable doesn't exist")
    c = doctor.check_playwright(run=run)
    assert c.status == "FAIL" and "playwright install chromium" in c.remedy and "PLAYWRIGHT_BROWSERS_PATH" in c.remedy
    assert all("pip" not in " ".join(a) for a in seen)


def test_a_launchable_chromium_passes(monkeypatch):
    monkeypatch.setattr(doctor, "_version", lambda dist: doctor.PLAYWRIGHT_PIN)
    c = doctor.check_playwright(run=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "chromium 156.0.1\n", ""))
    assert c.status == "OK" and "chromium 156.0.1" in c.detail


def test_robot_framework_presence_and_version(monkeypatch):
    monkeypatch.setattr(doctor, "_version", lambda dist: None)
    assert doctor.check_robot().status == "FAIL" and "robotframework==7.5" in doctor.check_robot().remedy
    monkeypatch.setattr(doctor, "_version", lambda dist: "7.4")
    assert doctor.check_robot().status == "FAIL"
    monkeypatch.setattr(doctor, "_version", lambda dist: "7.5")
    assert doctor.check_robot().status == "OK"


def test_pins_that_are_not_the_pinned_trees_fail_and_say_what_to_fetch(monkeypatch, tmp_path):
    monkeypatch.setenv("QA_PIN_HARNESS_QA_PATH", str(tmp_path))
    c = doctor.check_pins()
    assert c.status == "FAIL" and "pins.toml" in c.remedy and "nothing is installed" in c.remedy


def test_the_pinned_dependencies_pass_when_they_are_the_pinned_trees():
    c = doctor.check_pins()
    assert c.status == "OK" and "0.2.0" in c.detail and "tree digests" in c.detail


def test_the_fixture_app_and_the_gateway_checks_pass_here():
    assert doctor.check_fixture_app().status == "OK"
    assert doctor.check_egress_gateway().status == "OK"
    assert doctor.check_workdir().status == "OK"


def test_a_gateway_that_cannot_start_is_a_failure_not_a_fallback(monkeypatch):
    import qa_egress

    class Broken:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            raise OSError("cannot bind")

        def __exit__(self, *a):
            pass
    monkeypatch.setattr(qa_egress, "GatewayServer", Broken)
    c = doctor.check_egress_gateway()
    assert c.status == "FAIL" and "refuses to continue" in c.detail


def test_doctor_exit_status_and_output_when_a_check_fails(monkeypatch):
    monkeypatch.setattr(doctor, "_version", lambda dist: None)
    code, out, err = cli("doctor")
    assert code == K.EXIT_ENVIRONMENT
    assert "[FAIL] playwright" in out and "pip install playwright==1.64.1" in out and "Nothing was installed" in out


def test_doctor_json_lists_every_check(monkeypatch):
    monkeypatch.setattr(doctor, "_version", lambda dist: None)
    code, out, err = cli("doctor", "--json")
    rows = json.loads(out)
    assert code == K.EXIT_ENVIRONMENT and {r["check"] for r in rows} >= {"python", "platform", "pinned dependencies", "playwright", "robot framework", "fixture app", "egress gateway"}
    assert all(set(r) == {"check", "status", "detail", "remedy"} for r in rows)


def test_doctor_with_a_plan_checks_only_the_engines_the_plan_uses(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_version", lambda dist: doctor.PLAYWRIGHT_PIN if dist == "playwright" else None)
    monkeypatch.setattr(doctor, "check_playwright", lambda run=None: doctor.Check("playwright", "OK", "stub"))
    code, out, err = cli("doctor", "--plan", plan_file(tmp_path), "--json")
    names = {r["check"] for r in json.loads(out)}
    assert "robot framework" not in names and "playwright" in names and code == 0
