# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The library allowlist: the static scan before the run and the owner check after it. No Robot Framework is needed."""
import hashlib

import pytest

from qa_adapter_kit import ErrorCode, PolicyRefused
from qa_robot import DEFAULT_ALLOWED_LIBRARIES, RobotConfig, STANDARD_LIBRARIES, check_run, scan_suite


def make(tmp_path, files):
    ws = tmp_path / "ws"
    (ws / "suite").mkdir(parents=True)
    for name, text in files.items():
        p = ws / "suite" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return ws, ws / "suite"


def scan(tmp_path, files, config=None):
    ws, suite = make(tmp_path, files)
    return scan_suite(ws, suite, config or RobotConfig())


def refused(tmp_path, files, config=None, match=None):
    with pytest.raises(PolicyRefused, match=match) as info:
        scan(tmp_path, files, config)
    assert info.value.code is ErrorCode.LIBRARY_REFUSED
    return info.value


def robot(settings="", body="T1\n    Log    x\n", keywords=""):
    return f"*** Settings ***\n{settings}\n*** Keywords ***\n{keywords}\n*** Test Cases ***\n{body}"


def test_the_default_allowlist_is_standard_libraries_without_system_access():
    assert DEFAULT_ALLOWED_LIBRARIES == {"BuiltIn", "Collections", "DateTime", "String", "XML"}
    assert not DEFAULT_ALLOWED_LIBRARIES & {"OperatingSystem", "Process", "Remote", "Dialogs", "Screenshot", "Telnet"}


def test_allowed_libraries_pass_and_their_names_become_allowed_owners(tmp_path):
    r = scan(tmp_path, {"a.robot": robot("Library    Collections\nLibrary    String")})
    assert {"BuiltIn", "Collections", "String", "a"} <= r.allowed_owners and r.files == ("suite/a.robot",)


@pytest.mark.parametrize("lib", ["OperatingSystem", "Process", "Remote", "Dialogs", "Screenshot", "Telnet", "SeleniumLibrary", "AppiumLibrary", "mylib", "requests"])
def test_a_library_outside_the_allowlist_is_refused(tmp_path, lib):
    refused(tmp_path, {"a.robot": robot(f"Library    {lib}")}, match="not on the allowlist")


def test_the_allowlist_can_be_widened_with_standard_libraries_only(tmp_path):
    cfg = RobotConfig(allowed_libraries=DEFAULT_ALLOWED_LIBRARIES | {"OperatingSystem"})
    assert "OperatingSystem" in scan(tmp_path, {"a.robot": robot("Library    OperatingSystem")}, cfg).allowed_owners
    refused(tmp_path / "b", {"a.robot": robot("Library    Collections")}, RobotConfig(allowed_libraries=frozenset({"SeleniumLibrary"})), match="standard libraries")


@pytest.mark.parametrize("settings", ["Library    Collections    AS    Coll", "Library    Collections    WITH NAME    Coll", "library    collections    as    Coll"])
def test_an_alias_of_an_allowed_library_is_an_allowed_owner(tmp_path, settings):
    if settings.startswith("library"):
        refused(tmp_path, {"a.robot": robot(settings)}, match="not on the allowlist")      # names are case sensitive
        return
    assert "Coll" in scan(tmp_path, {"a.robot": robot(settings)}).allowed_owners


def test_an_alias_cannot_launder_a_library_that_is_not_allowed(tmp_path):
    refused(tmp_path, {"a.robot": robot("Library    OperatingSystem    AS    Safe")}, match="OperatingSystem")


def test_the_pipe_separated_format_is_read(tmp_path):
    text = "*** Settings ***\n| Library | OperatingSystem |\n\n*** Test Cases ***\n| T1 | Log | x |\n"
    refused(tmp_path, {"a.robot": text}, match="OperatingSystem")
    text = "*** Settings ***\n| Library | Collections |\n\n*** Test Cases ***\n| T1 | Log | x |\n"
    assert "Collections" in scan(tmp_path / "b", {"a.robot": text}).allowed_owners


@pytest.mark.parametrize("header", ["*** Settings ***", "*** Setting ***", "***Settings***", "*** SETTINGS ***"])
def test_section_headers_are_read_in_their_common_spellings(tmp_path, header):
    refused(tmp_path, {"a.robot": f"{header}\nLibrary    Process\n\n*** Test Cases ***\nT1\n    Log    x\n"}, match="Process")


def test_an_import_in_another_section_or_a_comment_is_not_an_import(tmp_path):
    text = "*** Settings ***\n# Library    Process\n\n*** Test Cases ***\nT1\n    Log    Library    Process\n"
    scan(tmp_path, {"a.robot": text})


@pytest.mark.parametrize("target", ["lib.py", "./lib.py", "pkg.module.Class", "../outside.py", "/etc/lib.py", "sub/lib.py"])
def test_a_library_by_path_needs_a_reviewed_hash(tmp_path, target):
    refused(tmp_path, {"a.robot": robot(f"Library    {target}")})


def test_a_reviewed_library_file_is_accepted_and_a_changed_one_is_not(tmp_path):
    ws, suite = make(tmp_path, {"a.robot": robot("Library    lib.py")})
    lib = suite / "lib.py"
    lib.write_text("def hello():\n    return 1\n")
    cfg = RobotConfig(allowed_library_files={"suite/lib.py": hashlib.sha256(lib.read_bytes()).hexdigest()})
    assert "lib" in scan_suite(ws, suite, cfg).allowed_owners
    lib.write_text("def hello():\n    return 2\n")
    with pytest.raises(PolicyRefused, match="reviewed hash"):
        scan_suite(ws, suite, cfg)


@pytest.mark.parametrize("target", ["https://example.invalid/r.resource", "/etc/r.resource", "../r.resource", "~/r.resource", "missing.resource", "x.py"])
def test_a_resource_must_be_a_resource_file_inside_the_workspace(tmp_path, target):
    ws, suite = make(tmp_path, {"a.robot": robot(f"Resource    {target}"), "x.py": "print(1)"})
    with pytest.raises(PolicyRefused):
        scan_suite(ws, suite, RobotConfig())


def test_a_resource_inside_the_workspace_is_accepted_and_its_name_becomes_an_owner(tmp_path):
    r = scan(tmp_path, {"a.robot": robot("Resource    common.resource"), "common.resource": "*** Keywords ***\nK\n    Log    x\n"})
    assert "common" in r.allowed_owners


def test_a_python_variable_file_is_refused_and_yaml_or_json_are_not(tmp_path):
    refused(tmp_path, {"a.robot": robot("Variables    vars.py"), "vars.py": "X = 1"}, match="YAML and JSON")
    assert scan(tmp_path / "b", {"a.robot": robot("Variables    vars.yaml"), "vars.yaml": "X: 1\n"})


@pytest.mark.parametrize("construct", ["Import Library    OperatingSystem", "import_library    os", "IMPORT LIBRARY    x", "Import Resource    r.resource",
                                        "Import Variables    v.py", "Evaluate    __import__('os').getcwd()", "${x}=    Evaluate    1+1", "${{ 1 + 1 }}",
                                        "Get Library Instance    X", "Set Library Search Order    X"])
def test_a_construct_that_loads_or_evaluates_code_is_refused(tmp_path, construct):
    refused(tmp_path, {"a.robot": robot(body=f"T1\n    {construct}\n")}, match="run time")


def test_the_dynamic_constructs_can_be_allowed_explicitly(tmp_path):
    scan(tmp_path, {"a.robot": robot(body="T1\n    ${x}=    Evaluate    1+1\n")}, RobotConfig(allow_dynamic_python=True))


def test_a_file_named_like_a_library_that_is_not_allowed_is_refused(tmp_path):
    refused(tmp_path, {"OperatingSystem.resource": "*** Keywords ***\nK\n    Log    x\n", "a.robot": robot()}, match="mistaken")


def test_a_symbolic_link_in_the_suite_is_refused(tmp_path):
    import os
    ws, suite = make(tmp_path, {"a.robot": robot()})
    outside = tmp_path / "outside.robot"
    outside.write_text(robot("Library    Process"))
    os.symlink(outside, suite / "link.robot")
    with pytest.raises(PolicyRefused, match="symbolic link"):
        scan_suite(ws, suite, RobotConfig())


def test_too_many_or_too_large_files_are_refused(tmp_path, monkeypatch):
    import qa_robot.policy as pol
    ws, suite = make(tmp_path, {"a.robot": robot(), "b.robot": robot()})
    monkeypatch.setattr(pol, "MAX_FILES", 1)
    with pytest.raises(PolicyRefused, match="more than"):
        scan_suite(ws, suite, RobotConfig())
    monkeypatch.undo()
    monkeypatch.setattr(pol, "MAX_FILE_BYTES", 5)
    with pytest.raises(PolicyRefused, match="larger"):
        scan_suite(ws, suite, RobotConfig())


def test_a_single_file_suite_is_scanned_too(tmp_path):
    ws, suite = make(tmp_path, {"a.robot": robot("Library    Process")})
    with pytest.raises(PolicyRefused):
        scan_suite(ws, suite / "a.robot", RobotConfig())


# ---------------------------------------------------------------------------------------------- after the run
def test_check_run_accepts_owners_of_allowed_libraries_and_resources(tmp_path):
    r = scan(tmp_path, {"a.robot": robot("Library    Collections")})
    check_run({"BuiltIn", "Collections", "a"}, {"Log", "Create List"}, r, RobotConfig())


def test_check_run_refuses_a_keyword_of_a_library_that_was_not_allowed(tmp_path):
    r = scan(tmp_path, {"a.robot": robot("Library    Collections")})
    with pytest.raises(PolicyRefused, match="OperatingSystem"):
        check_run({"BuiltIn", "OperatingSystem"}, {"Run"}, r, RobotConfig())


@pytest.mark.parametrize("name", ["Evaluate", "evaluate", "Import Library", "BuiltIn.Evaluate", "import_resource", "Get Library Instance"])
def test_check_run_refuses_a_call_to_a_dynamic_keyword_even_when_the_name_was_built_at_run_time(tmp_path, name):
    r = scan(tmp_path, {"a.robot": robot()})
    with pytest.raises(PolicyRefused, match="run time"):
        check_run({"BuiltIn"}, {name}, r, RobotConfig())
    check_run({"BuiltIn"}, {name}, r, RobotConfig(allow_dynamic_python=True))
