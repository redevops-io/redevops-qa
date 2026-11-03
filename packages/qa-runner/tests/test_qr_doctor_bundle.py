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
    assert seen == ["/anything"]                                                 # as the command line gives it: the kit does not follow a link there
    seen.clear()
    doctor.check_path_policy([("the working directory", "/anything", True)], is_denied=lambda p: seen.append(p) or False)
    assert seen == ["/anything", "/anything"]                                    # asked about the path as given and about its real path
    assert doctor.check_path_policy([("the interpreter", "/anything")], is_denied=lambda p: True).status == "FAIL"
    import inspect
    assert "from qa_adapter_kit.paths import is_denied as kit_is_denied" in inspect.getsource(doctor.check_path_policy)


def test_a_symbolic_link_into_a_refused_directory_is_found_by_its_real_path_for_the_working_directory_only(tmp_path):
    hidden = tmp_path / ".config"
    hidden.mkdir()
    link = tmp_path / "tmp"
    link.symlink_to(hidden)
    c = doctor.check_path_policy([("the temporary working directory of a run (from TMPDIR)", str(link / "redevops-qa-<random>"), True)])
    assert c.status == "FAIL" and "whose real path" in c.detail and "a path component named .config" in c.detail
    # the interpreter and the guard script are named on the command line as they are: a link elsewhere is not followed by the kit
    assert doctor.check_path_policy([("the interpreter", str(link / "python")), ("the Robot guard script", str(link / "robot_guard.py"))]).status == "OK"


def test_an_interpreter_that_is_a_link_to_a_python_under_a_refused_directory_is_accepted_because_the_kit_judges_the_argument_as_given(tmp_path, monkeypatch):
    """A venv's bin/python links to the interpreter it was made from (a pyenv or uv Python under /root, as root): measured, install --prefix /opt/q2 --python /root/pybase/bin/python3.12 ends
    VERIFIED. The check must not call it a failure."""
    from qa_adapter_kit.paths import is_denied
    base = tmp_path / ".config" / "pybase" / "bin"
    base.mkdir(parents=True)
    (base / "python3.12").write_text("")
    venv_bin = tmp_path / "opt" / "q2" / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").symlink_to(base / "python3.12")
    assert is_denied(os.path.realpath(venv_bin / "python")) and not is_denied(str(venv_bin / "python"))          # the premise: the real path is refused, the argument is not
    monkeypatch.setattr(doctor.sys, "executable", str(venv_bin / "python"))
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path / "tmp"))
    assert doctor.check_path_policy().status == "OK"
    # and the same interpreter given by a path that IS refused is still refused
    assert doctor.check_path_policy([("the interpreter", str(base / "python3.12"))]).status == "FAIL"


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
    listed = {what: path for what, path, _resolved in doctor.effective_lane_paths()}
    resolved = {what: flag for what, _path, flag in doctor.effective_lane_paths()}
    assert resolved["the interpreter"] is False and resolved["the Robot guard script"] is False and all(flag for what, flag in resolved.items() if "temporary" in what or "Robot lane" in what)
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
    from qa_runner.golden import demo_plan
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(demo_plan()))                    # a plan with a Robot lane: the one whose command line carries the paths
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
    monkeypatch.setattr(doctor, "effective_lane_paths", lambda: [("the interpreter", "/opt/redevops-qa/venv/bin/python", False)])
    code, _out, err = run_cli("demo", "--out", str(tmp_path / "evidence"))
    assert reached == [1] and "adapter path policy" not in err


def test_the_rule_names_agree_with_the_kits_own_decision_on_a_battery_of_paths():
    from qa_adapter_kit.paths import is_denied
    for p in ["/root", "/root/x", "/rootless/x", "/etc/x", "/etc2", "/run/x", "/runner", "/home/u/.ssh/k", "/home/u/ssh", "/srv/credentials", "/srv/credentials.json", "/srv/credentialsx", "/opt/x", "/dev/shm", "/boot"]:
        assert bool(doctor.path_rule(p)) == is_denied(p), p


# ------------------------------------------------------------------------------------------------------------------------ only the Robot lane has the command line
def plan_file(tmp_path, engines):
    """The plan of the real lanes: the browser lane alone (golden_plan), the Robot lane alone (robot_plan), or both (demo_plan)."""
    from qa_runner import constants as K
    from qa_runner.golden import demo_plan, golden_plan, robot_plan
    doc = {frozenset({K.ENGINE_PLAYWRIGHT}): golden_plan, frozenset({K.ENGINE_ROBOT}): robot_plan, frozenset({K.ENGINE_PLAYWRIGHT, K.ENGINE_ROBOT}): demo_plan}[frozenset(engines)]()
    assert {lane["engine"] for lane in doc["lanes"]} == set(engines)
    path = tmp_path / ("plan-" + "-".join(sorted(engines)) + ".json")
    path.write_text(json.dumps(doc))
    return path


def reaches_run_plan(monkeypatch, tmp_path, *argv):
    reached = []
    import qa_runner.orchestrate as orchestrate

    def stop(*a, **k):
        reached.append(1)
        raise RuntimeError("stop here")
    monkeypatch.setattr(orchestrate, "run_plan", stop)
    code, out, err = run_cli(*argv)
    return reached, code, out, err


def test_the_check_is_skipped_and_says_so_for_a_run_without_a_robot_lane_and_applies_to_one_with(monkeypatch):
    monkeypatch.setattr(doctor.sys, "executable", "/root/redevops-qa/venv/bin/python")
    skipped = doctor.check_path_policy(robot=False)
    assert skipped.status == "OK" and "not checked: no Robot lane" in skipped.detail
    assert doctor.check_path_policy(robot=True).status == "FAIL"
    assert doctor.check_path_policy().status == "FAIL"                           # the default is the check


def stub_every_other_check(monkeypatch):
    for name in ("check_python", "check_platform", "check_workdir", "check_first_party_modules", "check_pins", "check_pinned_files", "check_playwright", "check_robot", "check_fixture_app",
                 "check_egress_gateway"):
        monkeypatch.setattr(doctor, name, lambda name=name: doctor.Check(name, "OK", "stubbed"))


def test_run_doctor_takes_the_robot_lane_from_the_engines_and_checks_the_paths_only_where_there_is_one(monkeypatch):
    from qa_runner import constants as K
    stub_every_other_check(monkeypatch)
    monkeypatch.setattr(doctor.sys, "executable", "/root/redevops-qa/venv/bin/python")
    monkeypatch.setattr(tempfile, "gettempdir", lambda: "/root/tmp")

    def policy(engines):
        return next(c for c in doctor.run_doctor(engines) if c.name == "adapter path policy")
    assert policy((K.ENGINE_PLAYWRIGHT,)).status == "OK" and "not checked: no Robot lane" in policy((K.ENGINE_PLAYWRIGHT,)).detail
    assert policy((K.ENGINE_PLAYWRIGHT, K.ENGINE_ROBOT)).status == "FAIL" and policy((K.ENGINE_ROBOT,)).status == "FAIL"


def test_doctor_with_a_browser_only_plan_does_not_fail_on_paths_only_the_robot_lane_carries(monkeypatch, tmp_path):
    from qa_runner import constants as K
    monkeypatch.setattr(doctor.sys, "executable", "/root/redevops-qa/venv/bin/python")
    monkeypatch.setattr(doctor, "check_python", lambda: doctor.Check("python", "OK", "x"))
    names = []
    real = doctor.run_doctor

    def only_policy(engines=(K.ENGINE_PLAYWRIGHT,), include=None):
        names.append(tuple(engines))
        return real(engines, include=[lambda: doctor.check_path_policy(robot=K.ENGINE_ROBOT in engines)])
    monkeypatch.setattr(doctor, "run_doctor", only_policy)
    code, out, _ = run_cli("doctor", "--plan", str(plan_file(tmp_path, {K.ENGINE_PLAYWRIGHT})))
    assert names == [(K.ENGINE_PLAYWRIGHT,)] and code == 0 and "not checked: no Robot lane" in out
    code, out, _ = run_cli("doctor", "--plan", str(plan_file(tmp_path, {K.ENGINE_ROBOT})))
    assert code == 3 and "the interpreter is /root/redevops-qa/venv/bin/python" in out
    code, out, _ = run_cli("doctor")                                             # no plan: both lanes, the Robot lane included
    assert code == 3


def test_run_starts_a_browser_only_plan_whatever_the_robot_paths_are_and_refuses_a_plan_with_a_robot_lane(monkeypatch, tmp_path):
    from qa_runner import constants as K
    monkeypatch.setattr(doctor.sys, "executable", "/opt/redevops-qa/venv/bin/python")
    refused_tmp = tmp_path / ".config" / "tmp"                                   # a TMPDIR that exists and names a refused component
    refused_tmp.mkdir(parents=True)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(refused_tmp))
    out_dir = tmp_path / "evidence"
    reached, code, _out, err = reaches_run_plan(monkeypatch, tmp_path, "run", str(plan_file(tmp_path, {K.ENGINE_PLAYWRIGHT})), "--out", str(out_dir))
    assert reached == [1] and "adapter path policy" not in err.lower() and "ADAPTER_PATH_POLICY" not in err
    for engines in ({K.ENGINE_ROBOT}, {K.ENGINE_PLAYWRIGHT, K.ENGINE_ROBOT}):
        reached, code, _out, err = reaches_run_plan(monkeypatch, tmp_path, "run", str(plan_file(tmp_path, engines)), "--out", str(tmp_path / ("evidence" + "-".join(sorted(engines)))))
        assert reached == [] and code == 3 and "Nothing was started" in err and f"the temporary working directory of a run (from TMPDIR) is {refused_tmp}/redevops-qa-<random> (a path component named .config" in err, engines


# ------------------------------------------------------------------------------------------------------------------- the third-party licence and notice texts
def add_notices(prefix: Path, files=None, record_digest=True):
    """THIRD_PARTY_NOTICES under the prefix's share directory with an INDEX.json, and (like install.sh) an INSTALL.json beside the prefix that records the index digest."""
    tree = prefix / "share" / "redevops-qa" / "THIRD_PARTY_NOTICES"
    files = files or {"README.md": b"notices\n", "wheels/lib-1/lib-1.dist-info/licenses/LICENSE": b"MIT text\n"}
    for rel, data in files.items():
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree / rel).write_bytes(data)
    index = json.dumps({"schema": "redevops-qa/third-party-notices-index", "version": 1, "files": [{"path": k, "sha256": hashlib.sha256(v).hexdigest(), "size": len(v)} for k, v in sorted(files.items())]}).encode()
    (tree / "INDEX.json").write_bytes(index)
    if record_digest:
        (prefix.parent / "INSTALL.json").write_text(json.dumps({"third_party_notices_index_sha256": hashlib.sha256(index).hexdigest()}))
    return tree


def test_the_notices_check_is_part_of_doctor_and_says_a_checkout_is_not_a_bundle_install(tmp_path):
    assert doctor.check_third_party_notices in [c for c in (doctor.check_python, doctor.check_pinned_files, doctor.check_third_party_notices)]
    c = doctor.check_third_party_notices(str(tmp_path))
    assert c.status == "OK" and "not a bundle install" in c.detail
    import inspect
    assert "check_third_party_notices" in inspect.getsource(doctor.run_doctor)


def test_installed_notices_that_are_the_shipped_ones_pass_and_the_detail_says_what_is_covered(tmp_path):
    prefix = make_prefix(tmp_path)
    add_notices(prefix)
    c = doctor.check_third_party_notices(str(prefix))
    assert c.status == "OK" and "2 licence and notice files" in c.detail and "matches the digest recorded at install time" in c.detail


def test_a_bundle_install_without_the_notices_tree_fails(tmp_path):
    c = doctor.check_third_party_notices(str(make_prefix(tmp_path)))
    assert c.status == "FAIL" and "has no INDEX.json" in c.detail and "are not installed" in c.detail and "reinstall" in c.remedy


def test_an_edited_removed_or_added_notice_file_fails_by_name(tmp_path):
    prefix = make_prefix(tmp_path)
    tree = add_notices(prefix)
    (tree / "README.md").write_bytes(b"edited\n")
    c = doctor.check_third_party_notices(str(prefix))
    assert c.status == "FAIL" and "changed ['README.md']" in c.detail
    (tree / "README.md").write_bytes(b"notices\n")
    (tree / "wheels/lib-1/lib-1.dist-info/licenses/LICENSE").unlink()
    assert "missing ['wheels/lib-1/lib-1.dist-info/licenses/LICENSE']" in doctor.check_third_party_notices(str(prefix)).detail
    (tree / "wheels/lib-1/lib-1.dist-info/licenses/LICENSE").write_bytes(b"MIT text\n")
    (tree / "extra.txt").write_bytes(b"x")
    assert "added ['extra.txt']" in doctor.check_third_party_notices(str(prefix)).detail


def test_an_index_that_is_not_the_one_recorded_at_install_time_fails_and_an_unreadable_one_fails(tmp_path):
    prefix = make_prefix(tmp_path)
    tree = add_notices(prefix)
    files = {"README.md": b"notices\n"}                                       # an index rewritten together with the tree: the install-time digest no longer matches
    (tree / "INDEX.json").write_text(json.dumps({"files": [{"path": "README.md", "sha256": hashlib.sha256(b"notices\n").hexdigest(), "size": 8}]}))
    (tree / "wheels/lib-1/lib-1.dist-info/licenses/LICENSE").unlink()
    c = doctor.check_third_party_notices(str(prefix))
    assert c.status == "FAIL" and "not the one recorded when the bundle was installed" in c.detail
    (tree / "INDEX.json").write_text("{")
    assert doctor.check_third_party_notices(str(prefix)).status == "FAIL"


def test_without_a_recorded_digest_the_detail_says_a_change_made_together_with_the_index_is_not_covered(tmp_path):
    prefix = make_prefix(tmp_path)
    add_notices(prefix, record_digest=False)
    c = doctor.check_third_party_notices(str(prefix))
    assert c.status == "OK" and "not covered" in c.detail
