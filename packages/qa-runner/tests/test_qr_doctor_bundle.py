# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The two doctor checks of a bundle install: the first-party packages are imported from the installation, and the pinned trees are the files the bundle shipped. Synthetic prefixes."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import qa_runner.doctor as doctor
from qa_runner.procs import CHILD_MODULES


def make_prefix(tmp_path: Path) -> Path:
    prefix = tmp_path / "prefix"
    share = prefix / "share" / "redevops-qa"
    (share / ".pinned" / "c4" / "agent-harness" / "agent_harness").mkdir(parents=True)
    (share / ".pinned" / "c4" / "runtime-contracts").mkdir(parents=True)
    files = {".pinned/c4/agent-harness/agent_harness/__init__.py": b"x = 1\n", ".pinned/c4/agent-harness/LICENSE": b"licence\n", ".pinned/c4/runtime-contracts/pyproject.toml": b"[project]\nversion = '1'\n"}
    for rel, data in files.items():
        (share / rel).write_bytes(data)
    (share / "pins.toml").write_text("x")
    (share / "pinned-files.json").write_text(json.dumps({"schema": "redevops-qa/pinned-files", "files": {k: hashlib.sha256(v).hexdigest() for k, v in files.items()}}))
    return prefix


def locate_in(root: Path, stray: str = ""):
    def locate(name):
        base = root / "site-packages" if name != stray else Path("/elsewhere")
        return SimpleNamespace(submodule_search_locations=[str(base / name)])
    return locate


# ------------------------------------------------------------------------------------------------------------------------ first-party packages
def test_a_checkout_or_development_environment_is_not_a_bundle_install_and_says_so(tmp_path):
    c = doctor.check_first_party_modules(str(tmp_path))
    assert c.status == "OK" and "not a bundle install" in c.detail


def test_every_first_party_package_imported_from_the_installation_passes(tmp_path):
    prefix = make_prefix(tmp_path)
    c = doctor.check_first_party_modules(str(prefix), locate_in(prefix))
    assert c.status == "OK" and str(len(CHILD_MODULES)) in c.detail


@pytest.mark.parametrize("name", CHILD_MODULES)
def test_one_package_imported_from_anywhere_else_fails_and_names_it(tmp_path, name):
    prefix = make_prefix(tmp_path)
    c = doctor.check_first_party_modules(str(prefix), locate_in(prefix, stray=name))
    assert c.status == "FAIL" and name in c.detail and "/elsewhere" in c.detail and "python -E -s" in c.remedy


def test_a_package_that_cannot_be_found_fails(tmp_path):
    prefix = make_prefix(tmp_path)
    c = doctor.check_first_party_modules(str(prefix), lambda name: None)
    assert c.status == "FAIL" and "not found" in c.detail


def test_a_prefix_name_that_only_starts_like_the_installation_is_not_the_installation(tmp_path):
    prefix = make_prefix(tmp_path)
    c = doctor.check_first_party_modules(str(prefix), lambda name: SimpleNamespace(submodule_search_locations=[str(prefix) + "-evil/site-packages/" + name]))
    assert c.status == "FAIL"


def test_doctor_runs_both_checks_by_default():
    names = [f.__name__ for f in (doctor.check_first_party_modules, doctor.check_pinned_files)]
    import inspect
    src = inspect.getsource(doctor.run_doctor)
    assert all(n in src for n in names)


# ------------------------------------------------------------------------------------------------------------------------ pinned files
def test_the_files_as_shipped_pass_and_the_detail_says_what_is_not_covered(tmp_path):
    c = doctor.check_pinned_files(str(make_prefix(tmp_path)))
    assert c.status == "OK" and "LICENSE and pyproject.toml included" in c.detail and "bytecode" in c.detail and "not covered" in c.detail


def test_outside_a_bundle_install_there_is_nothing_to_compare(tmp_path):
    assert doctor.check_pinned_files(str(tmp_path)).status == "OK" and "not a bundle install" in doctor.check_pinned_files(str(tmp_path)).detail


@pytest.mark.parametrize("rel", [".pinned/c4/agent-harness/LICENSE", ".pinned/c4/runtime-contracts/pyproject.toml", ".pinned/c4/agent-harness/agent_harness/__init__.py"])
def test_a_changed_licence_pyproject_or_module_is_found(tmp_path, rel):
    prefix = make_prefix(tmp_path)
    target = prefix / "share" / "redevops-qa" / rel
    target.write_bytes(target.read_bytes() + b"# changed\n")
    c = doctor.check_pinned_files(str(prefix))
    assert c.status == "FAIL" and "changed" in c.detail and rel in c.detail


def test_an_added_or_a_removed_file_is_found(tmp_path):
    prefix = make_prefix(tmp_path)
    share = prefix / "share" / "redevops-qa"
    (share / ".pinned" / "c4" / "agent-harness" / "agent_harness" / "extra.py").write_text("x")
    assert "added" in doctor.check_pinned_files(str(prefix)).detail
    (share / ".pinned" / "c4" / "agent-harness" / "agent_harness" / "extra.py").unlink()
    (share / ".pinned" / "c4" / "agent-harness" / "LICENSE").unlink()
    c = doctor.check_pinned_files(str(prefix))
    assert c.status == "FAIL" and "missing" in c.detail


def test_bytecode_is_skipped_exactly_as_the_pin_digest_skips_it_and_that_is_stated_not_hidden(tmp_path):
    prefix = make_prefix(tmp_path)
    cache = prefix / "share" / "redevops-qa" / ".pinned" / "c4" / "agent-harness" / "agent_harness" / "__pycache__"
    cache.mkdir()
    (cache / "x.cpython-312.pyc").write_bytes(b"anything")
    c = doctor.check_pinned_files(str(prefix))
    assert c.status == "OK" and "bytecode" in c.detail


def test_an_unreadable_manifest_fails(tmp_path):
    prefix = make_prefix(tmp_path)
    (prefix / "share" / "redevops-qa" / "pinned-files.json").write_text("{")
    assert doctor.check_pinned_files(str(prefix)).status == "FAIL"


# ------------------------------------------------------------------------------------------------------------------------ the adapter path policy (F1)
def test_an_interpreter_under_root_fails_before_demo_and_names_the_cause():
    c = doctor.check_path_policy([("the interpreter", "/root/redevops-qa/venv/bin/python"), ("the temporary directory", "/tmp")])
    assert c.status == "FAIL" and "the interpreter is /root/redevops-qa/venv/bin/python" in c.detail and "PROHIBITED_PATH" in c.detail and "INCONCLUSIVE" in c.detail
    assert "/opt/redevops-qa" in c.remedy and "TMPDIR" in c.remedy


@pytest.mark.parametrize("path", ["/root/tmp", "/etc/x", "/run/x", "/var/run/x", "/proc/x", "/sys/x", "/dev/x", "/boot/x", "/home/u/.config/x", "/home/u/.ssh/x"])
def test_every_path_the_kit_refuses_fails_for_the_interpreter_the_guard_script_and_the_temporary_directory(path):
    for what in ("the interpreter", "the Robot guard script", "the temporary directory"):
        c = doctor.check_path_policy([(what, path)])
        assert c.status == "FAIL" and f"{what} is {path}" in c.detail, (what, path)


def test_ordinary_paths_pass_and_the_remedy_lists_the_kits_own_prefixes():
    assert doctor.check_path_policy([("the interpreter", "/opt/redevops-qa/venv/bin/python"), ("the temporary directory", "/tmp"), ("the Robot guard script", "/home/runner/x/robot_guard.py")]).status == "OK"
    from qa_adapter_kit.paths import DENIED_PREFIXES
    remedy = doctor.check_path_policy([("the interpreter", "/root/x")]).remedy
    assert all(prefix in remedy for prefix in DENIED_PREFIXES)                  # read from the kit, not copied by hand


def test_the_check_uses_the_kits_rule_not_a_copy_of_it():
    seen = []
    doctor.check_path_policy([("the interpreter", "/anything")], is_denied=lambda p: seen.append(p) or False)
    assert seen == ["/anything", "/anything"]                                    # asked about the path as given and about its real path
    assert doctor.check_path_policy([("the interpreter", "/anything")], is_denied=lambda p: True).status == "FAIL"
    import inspect
    assert "from qa_adapter_kit.paths import is_denied as kit_is_denied" in inspect.getsource(doctor.check_path_policy)


def test_a_symbolic_link_into_a_refused_directory_is_found_by_its_real_path(tmp_path):
    hidden = tmp_path / ".config"
    hidden.mkdir()
    link = tmp_path / "bin"
    link.symlink_to(hidden)
    c = doctor.check_path_policy([("the interpreter", str(link / "python"))])
    assert c.status == "FAIL"


def test_the_default_check_looks_at_this_interpreter_the_guard_script_and_the_temporary_directory(monkeypatch, tmp_path):
    import tempfile
    assert doctor.check_path_policy().status == "OK" or doctor.check_path_policy().status == "FAIL"           # whichever this machine gives, it ran the three
    monkeypatch.setattr(tempfile, "gettempdir", lambda: "/root/tmp")
    c = doctor.check_path_policy()
    assert c.status == "FAIL" and "the temporary working directory of a run (from TMPDIR) is /root/tmp/redevops-qa-<random>" in c.detail
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(doctor.sys, "executable", "/root/venv/bin/python")
    assert "the interpreter is /root/venv/bin/python" in doctor.check_path_policy().detail


def test_doctor_runs_the_path_policy_check_among_its_defaults():
    import inspect
    assert "check_path_policy" in inspect.getsource(doctor.run_doctor)


# ------------------------------------------------------------------------------------------------------------------------ the effective configuration, not only the prefix
import io
import os
import tempfile

import qa_runner.cli as cli


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), out, err)
    return code, out.getvalue(), err.getvalue()


def test_the_denied_prefix_list_is_unchanged_or_only_grows_and_the_root_case_is_not_special_cased():
    """The owner's rule: the root case is made to pass by configuring the run, never by relaxing the rule. Pinned: today's lists, as a floor."""
    from qa_adapter_kit.paths import DENIED_COMPONENTS, DENIED_NAMES, DENIED_PREFIXES, is_denied
    assert set(DENIED_PREFIXES) >= {"/etc", "/proc", "/sys", "/dev", "/run", "/var/run", "/root", "/boot", "/private/etc", "/private/var/run"}
    assert set(DENIED_COMPONENTS) >= {".ssh", ".aws", ".gnupg", ".docker", ".kube", ".azure", ".config", ".netrc", ".git-credentials", ".npmrc", ".pypirc"}
    assert set(DENIED_NAMES) >= {"docker.sock", "containerd.sock", "podman.sock", "id_rsa", "id_ed25519", "id_ecdsa", "credentials"}
    assert is_denied("/root/redevops-qa/venv/bin/python") and is_denied("/root") and not is_denied("/opt/redevops-qa/venv/bin/python")
    text = Path(doctor.__file__).read_text(encoding="utf-8")
    assert "DENIED_PREFIXES =" not in text and "DENIED_PREFIXES.remove" not in text                  # doctor reads the list; it does not hold or edit one


def test_the_paths_on_the_lane_command_lines_are_the_ones_the_check_looks_at_and_home_and_the_evidence_directory_are_not_among_them(monkeypatch):
    from qa_runner.procs import child_env
    monkeypatch.setenv("HOME", "/root")
    listed = dict(doctor.effective_lane_paths())
    from qa_runner.lane_robot import GUARD
    assert listed["the interpreter"] == __import__("sys").executable and listed["the Robot guard script"] == GUARD
    assert any("workspace" in k for k in listed) and any("output directory" in k for k in listed)
    assert not any(v == "/root" or v.startswith("/root/") for v in listed.values()) or str(tempfile.gettempdir()).startswith("/root")          # HOME=/root is not what is checked
    assert child_env("/some/home")["HOME"] == "/some/home" and child_env("/some/home")["TMPDIR"] == "/some/home"        # a lane child gets a HOME and a TMPDIR of its own, not the process's


def test_a_prefix_under_a_refused_directory_fails_doctor_with_exit_3_naming_the_path_and_the_rule(monkeypatch):
    monkeypatch.setattr(doctor.sys, "executable", "/root/redevops-qa/venv/bin/python")
    monkeypatch.setattr(doctor, "run_doctor", lambda engines=(): [doctor.check_path_policy()])
    code, out, _err = run_cli("doctor")
    assert code == 3 and "[FAIL] adapter path policy: the interpreter is /root/redevops-qa/venv/bin/python (the prefix /root is on the refused list)" in out


def test_a_prefix_outside_with_a_tmpdir_under_a_refused_directory_fails_doctor_with_exit_3_naming_the_path_and_the_rule(monkeypatch):
    monkeypatch.setattr(doctor.sys, "executable", "/opt/redevops-qa/venv/bin/python")
    monkeypatch.setattr(tempfile, "gettempdir", lambda: "/root/tmp")
    monkeypatch.setattr(doctor, "run_doctor", lambda engines=(): [doctor.check_path_policy()])
    code, out, _err = run_cli("doctor")
    assert code == 3 and "the temporary working directory of a run (from TMPDIR) is /root/tmp/redevops-qa-<random> (the prefix /root is on the refused list)" in out
    assert "Robot lane's workspace is /root/tmp/redevops-qa-<random>/lanes/robot/workspace/suite" in out and "TMPDIR" in out


def test_a_tmpdir_under_a_refused_component_is_named_with_that_rule(monkeypatch):
    monkeypatch.setattr(tempfile, "gettempdir", lambda: "/home/u/.config/tmp")
    monkeypatch.setattr(doctor.sys, "executable", "/opt/redevops-qa/venv/bin/python")
    c = doctor.check_path_policy()
    assert c.status == "FAIL" and "a path component named .config is on the refused list" in c.detail


def test_home_and_an_evidence_directory_under_a_refused_directory_do_not_fail_doctor_because_they_are_not_on_a_lane_command_line(monkeypatch, tmp_path):
    """Measured: an installation under /opt with HOME=/root and the evidence directory under /root ends VERIFIED (tools/bundle_root_check.sh runs it as root in CI), so doctor does not call it a
    failure; the checks above are the ones that fail."""
    monkeypatch.setenv("HOME", "/root")
    monkeypatch.setattr(doctor.sys, "executable", "/opt/redevops-qa/venv/bin/python")
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    assert doctor.check_path_policy().status == "OK"


def test_demo_and_run_do_not_start_when_the_path_policy_would_end_them_inconclusive_and_say_why(monkeypatch, tmp_path):
    started = []
    monkeypatch.setattr(doctor.sys, "executable", "/root/redevops-qa/venv/bin/python")
    import qa_runner.orchestrate as orchestrate
    monkeypatch.setattr(orchestrate, "run_plan", lambda *a, **k: started.append(1))
    from qa_runner.golden import golden_plan
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(golden_plan()))
    out_dir = tmp_path / "evidence"
    for argv in (("demo", "--out", str(out_dir)), ("run", str(plan), "--out", str(out_dir))):
        code, out, err = run_cli(*argv)
        assert code == 3 and started == [] and not out_dir.exists(), argv
        assert "the interpreter is /root/redevops-qa/venv/bin/python (the prefix /root is on the refused list)" in err and "PROHIBITED_PATH" in err and "Nothing was started" in err


def test_demo_starts_as_before_when_the_effective_paths_are_accepted(monkeypatch, tmp_path):
    reached = []
    import qa_runner.orchestrate as orchestrate

    def stop(*a, **k):
        reached.append(1)
        raise RuntimeError("stop here")
    monkeypatch.setattr(orchestrate, "run_plan", stop)
    monkeypatch.setattr(doctor, "effective_lane_paths", lambda: [("the interpreter", "/opt/redevops-qa/venv/bin/python")])
    code, _out, err = run_cli("demo", "--out", str(tmp_path / "evidence"))
    assert reached == [1] and "adapter path policy" not in err


def test_the_rule_names_agree_with_the_kits_own_decision_on_a_battery_of_paths():
    from qa_adapter_kit.paths import is_denied
    for p in ["/root", "/root/x", "/rootless/x", "/etc/x", "/etc2", "/run/x", "/runner", "/home/u/.ssh/k", "/home/u/ssh", "/srv/credentials", "/srv/credentials.json", "/srv/credentialsx", "/opt/x", "/dev/shm", "/boot"]:
        assert bool(doctor.path_rule(p)) == is_denied(p), p
