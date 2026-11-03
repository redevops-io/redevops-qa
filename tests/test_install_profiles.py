# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""qa-install-profiles.json: schema, the closed shapes of every step, pins, status rules, the CI job behind a verified status, freshness, the generated
document and the runner that executes a profile. Offline."""
import copy
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(str(ROOT / "tools"))
    return mod


chk = load("check_install_profiles", "check_install_profiles.py")
runner = load("run_install_profile", "run_install_profile.py")
gen = chk.gen
qj = chk.qa_jsonschema

PROFILES = json.loads((ROOT / "qa-install-profiles.json").read_text(encoding="utf-8"))
CAPS = json.loads((ROOT / "qa-capabilities.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((ROOT / "schemas" / "qa-install-profiles.schema.json").read_text(encoding="utf-8"))
CAP_SCHEMA = json.loads((ROOT / "schemas" / "qa-capabilities.schema.json").read_text(encoding="utf-8"))
WORKFLOW = yaml.safe_load((ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8"))


def fresh():
    return copy.deepcopy(PROFILES)


def profile(m, pid):
    return next(p for p in m["profiles"] if p["id"] == pid)


def host(p, os_arch):
    return next(h for h in p["hosts"] if h["os_arch"] == os_arch)


def joined(x):
    return "\n".join(x)


def semantic(m):
    assert [f for f in qj.validate(m, SCHEMA)] == []
    return chk.semantic_problems(m, CAPS, ROOT)


# ------------------------------------------------------------------------------------------------ the real file
def test_the_profiles_in_the_repository_pass_every_offline_check():
    assert chk.check_all(ROOT, freshness=False) == []


def test_the_schema_is_a_plain_json_schema_the_strict_validator_fully_supports_and_shares_the_host_vocabulary():
    qj.check_schema(SCHEMA)
    assert SCHEMA["$defs"]["os_arch"] == CAP_SCHEMA["$defs"]["os_arch"] and list(gen.HOSTS) == SCHEMA["$defs"]["os_arch"]["enum"]
    assert list(gen.TARGETS) == list(SCHEMA["properties"]["targets"]["required"])


def test_at_least_one_profile_is_verified_by_a_named_ci_job_and_the_rest_say_what_they_are():
    verified = [(p["id"], h["os_arch"]) for p in PROFILES["profiles"] for h in p["hosts"] if h["status"] == "verified"]
    assert verified and all(p["status"] == "verified" for p in PROFILES["profiles"] if any(h["status"] == "verified" for h in p["hosts"]))
    statuses = {p["id"]: p["status"] for p in PROFILES["profiles"]}
    assert statuses["local-python-appium-android"] == "experimental" and statuses["local-python-appium-ios"] == "planned" and statuses["local-python-playwright"] == "planned"
    for p in PROFILES["profiles"]:
        if p["status"] == "planned":
            assert p["disabled_reason"] and not p["hosts"] and not any(p["steps"].values())


def test_docker_compose_and_kubernetes_are_planned_with_a_reason_and_the_repository_has_none_of_their_files():
    for name in ("docker-compose", "kubernetes-helm"):
        t = PROFILES["targets"][name]
        assert t["status"] == "planned" and len(t["disabled_reason"]) > 40
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True).stdout.split("\n") if (ROOT / ".git").exists() else []
    names = [Path(t).name for t in tracked if t]
    assert not [n for n in names if re.match(r"(docker-compose|compose).*\.ya?ml|Dockerfile|Chart\.yaml", n)]


def test_the_install_is_a_checkout_at_a_commit_with_no_registry_package_and_no_release_tag():
    src = PROFILES["source"]
    assert src["install_method"] == "checkout-at-commit" and re.fullmatch(r"[0-9a-f]{40}", src["pinned_commit"])
    assert src["dependency_release_tags"] == {"runtime-contracts": ["v0.3.15", "v0.3.16"], "agent-harness": ["v0.2.0"]}
    text = json.dumps(PROFILES)
    assert not re.search(r"pip install (--[a-z-]+ )*redevops|pypi\.org|--index-url|--extra-index-url|--find-links|git\+https", text, re.IGNORECASE)
    for p in PROFILES["profiles"]:
        for phase in p["steps"].values():
            for s in phase:
                assert not [a for a in s["argv"] if re.fullmatch(r"redevops-qa[a-z-]*(==.*)?", a)], "a registry package that does not exist"


def test_every_verified_profile_is_pinned_exactly_and_each_pin_matches_the_capability_manifest():
    for p in PROFILES["profiles"]:
        if p["status"] == "planned":
            continue
        assert p["python"]["version"] == "3.12" and p["python"]["requires"] == ">=3.11"
        if p.get("kind") == "bundle":
            assert p["pip_pins"] == [] and p["packages"] == []                  # the pins of a bundle profile are the bundle's lock
            continue
        assert all(re.fullmatch(r"[0-9]+(\.[0-9]+)*", x["version"]) for x in p["pip_pins"])
        cap = {e["engine"]: e for e in CAPS["engines"]}
        for e in p["engines"]:
            for d in cap[e]["dependencies"]:
                if d["kind"] == "pip" and d["provided_by"] == "install":
                    assert {x["name"].lower(): x["version"] for x in p["pip_pins"]}[d["name"].lower()] == d["pin"]


def test_the_unknown_wording_never_appears():
    text = json.dumps(PROFILES) + (ROOT / "docs" / "QA_INSTALL_PROFILES.md").read_text(encoding="utf-8")
    assert not re.search(r"(?<!not )open[ -]source|private (repo|development)", text, re.IGNORECASE)


# ------------------------------------------------------------------------------------------------ schema rules
def remove(path):
    def apply(m):
        node = m
        for step in path[:-1]:
            node = node[step]
        del node[path[-1]]
    return apply


def mutate(path, value):
    def apply(m):
        node = m
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = value
    return apply


R = ("profiles", 0)
SCHEMA_CASES = [
    ("a status outside the vocabulary", mutate(R + ("status",), "ready"), "status"),
    ("a planned profile without a reason", mutate(("profiles", 3, "disabled_reason"), None), "disabled_reason"),
    ("a verified profile with a reason", mutate(R + ("disabled_reason",), "x"), "disabled_reason"),
    ("a verified host without a run", mutate(R + ("hosts", 0, "verified_by"), None), "verified_by"),
    ("an experimental host with a run", mutate(R + ("hosts", 1, "verified_by"), {"workflow": "tests.yml"}), "verified_by"),
    ("a planned target without a reason", mutate(("targets", "docker-compose", "disabled_reason"), None), "disabled_reason"),
    ("an available target with a reason", mutate(("targets", "local-python", "disabled_reason"), "x"), "disabled_reason"),
    ("a target that is not a local one", mutate(R + ("target",), "docker-compose"), "target"),
    ("a pin without an exact version", mutate(R + ("pip_pins", 0, "version"), ">=9"), "version"),
    ("a package outside packages", mutate(R + ("packages", 0), "/etc"), "packages"),
    ("a step without an argv", mutate(R + ("steps", "install", 0, "argv"), []), "argv"),
    ("an unknown step field", mutate(R + ("steps", "install", 0, "shell"), True), "shell"),
    ("an unknown phase", mutate(R + ("steps", "deploy"), []), "deploy"),
    ("a verifier flag that is not a boolean", mutate(("verifier", "supported"), "yes"), "supported"),
    ("a profile kind outside the vocabulary", mutate(R + ("kind",), "docker"), "kind"),
    ("an install method that is a registry", mutate(("source", "install_method"), "registry"), "install_method"),
    ("a bad pinned commit", mutate(("source", "pinned_commit"), "main"), "pinned_commit"),
    ("a recorded run without the commit it installed from", mutate(R + ("hosts", 0, "verified_by", "source_commit"), None), "source_commit"),
    ("a recorded run whose whole run is not green", mutate(R + ("hosts", 0, "verified_by", "run_conclusion"), "failure"), "run_conclusion"),
    ("a parameter of the wrong kind", mutate(R + ("params", "venv_dir", "kind"), "shell"), "kind"),
    ("a verified profile without a smoke step", mutate(R + ("steps", "smoke"), []), "smoke"),
    ("a host outside the vocabulary", mutate(R + ("hosts", 0, "os_arch"), "plan9-x86_64"), "os_arch"),
    ("a dependency tag that is not a version", mutate(("source", "dependency_release_tags", "agent-harness"), ["main"]), "dependency_release_tags"),
]


@pytest.mark.parametrize("label,apply,needle", SCHEMA_CASES, ids=[c[0] for c in SCHEMA_CASES])
def test_the_schema_refuses(label, apply, needle):
    m = fresh()
    if label in ("a verified host without a run", "a verified profile with a reason", "a verified profile without a smoke step"):
        # these rules apply to a verified entry; make the entry verified so the rule is exercised whatever the file says today
        p = m["profiles"][0]
        p["status"] = "verified"
        p["hosts"][0]["status"] = "verified"
        p["hosts"][0]["verified_by"] = {"workflow": "tests.yml", "job_key": "profile-local-python-robot", "job_name": "x", "run_id": 1, "job_id": 2, "head_sha": "a" * 40,
                                        "run_url": "https://github.com/a/b/actions/runs/1", "url": "https://github.com/a/b/actions/runs/1/job/2", "completed_on": "2026-11-01",
                                        "summary": "x"}
    if label == "an experimental host with a run":
        m["profiles"][0]["hosts"][1]["status"] = "experimental"
    apply(m)
    found = qj.validate(m, SCHEMA)
    assert found and needle in joined(found), (label, found)


# ------------------------------------------------------------------------------------------------ steps are closed shapes
def one_step(phase="install", index=1):
    p = profile(PROFILES, "local-python-robot")
    return p, phase, copy.deepcopy(p["steps"][phase][index])


V = "{venv_dir}/bin/python"
BAD_STEPS = [
    ("a shell", "install", ["sh", "-c", "pip install x"]),
    ("a download tool", "install", ["curl", "-sSL", "https://example.invalid/install.sh"]),
    ("a pipe to a shell", "install", ["bash", "-c", "curl https://example.invalid | sh"]),
    ("a removal", "uninstall", ["rm", "-rf", "{venv_dir}"]),
    ("a removal of anything", "uninstall", ["python3.12", "-c", "import shutil,sys; shutil.rmtree(sys.argv[1])", "{venv_dir}"]),
    ("an unpinned package", "install", [V, "-m", "pip", "install", "--disable-pip-version-check", "robotframework"]),
    ("a package that is not in the profile", "install", [V, "-m", "pip", "install", "--disable-pip-version-check", "requests==2.0.0"]),
    ("a range", "install", [V, "-m", "pip", "install", "--disable-pip-version-check", "pytest>=8", "pyyaml==6.0.3", "robotframework==7.5"]),
    ("a package name from a registry", "install", [V, "-m", "pip", "install", "--disable-pip-version-check", "--no-deps", "redevops-qa-robot"]),
    ("an editable install", "install", [V, "-m", "pip", "install", "--disable-pip-version-check", "--no-deps", "-e", "{checkout_dir}/packages/qa-robot"]),
    ("a url", "install", [V, "-m", "pip", "install", "--disable-pip-version-check", "--no-deps", "https://example.invalid/x.whl"]),
    ("another index", "install", [V, "-m", "pip", "install", "--disable-pip-version-check", "--index-url", "https://example.invalid", "pytest==9.2.0"]),
    ("a package directory outside the profile", "install", [V, "-m", "pip", "install", "--disable-pip-version-check", "--no-deps", "{checkout_dir}/packages/qa-appium"]),
    ("a package directory that climbs", "install", [V, "-m", "pip", "install", "--disable-pip-version-check", "--no-deps", "{checkout_dir}/../x"]),
    ("another interpreter", "install", ["python3", "-m", "venv", "{venv_dir}"]),
    ("another code string", "install", [V, "-I", "-c", "import os; os.system('id')", "{venv_dir}", "qa_robot"]),
    ("a module name with a separator", "install", [V, "-I", "-c", chk.CODE_ASSERT, "{venv_dir}", "os;id"]),
    ("a clone of another repository", "source", ["git", "clone", "https://example.invalid/x.git", "{checkout_dir}"]),
    ("a checkout of a branch", "source", ["git", "-C", "{checkout_dir}", "checkout", "main"]),
    ("a test run that is not scoped to the profile's packages", "smoke", [V, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-c", "{checkout_dir}/pyproject.toml", "-o", "pythonpath=",
                                                                         "--junitxml={evidence_dir}/junit-x.xml", "{checkout_dir}/packages/qa-appium/tests"]),
    ("a test run that keeps the repository's import path", "smoke", [V, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-c", "{checkout_dir}/pyproject.toml",
                                                                    "--junitxml={evidence_dir}/junit-x.xml", "{checkout_dir}/packages/qa-robot/tests"]),
    ("a marker that is not allowed", "smoke", [V, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-c", "{checkout_dir}/pyproject.toml", "-o", "pythonpath=",
                                               "--junitxml={evidence_dir}/junit-x.xml", "-m", "slow", "{checkout_dir}/packages/qa-robot/tests"]),
    ("an evidence file outside the evidence directory", "smoke", [V, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-c", "{checkout_dir}/pyproject.toml", "-o", "pythonpath=",
                                                                 "--junitxml=/tmp/x.xml", "{checkout_dir}/packages/qa-robot/tests"]),
    ("a check that is not the junit checker", "check", [V, "{checkout_dir}/tools/other.py", "{evidence_dir}/junit-x.xml"]),
    ("a placeholder that is not a parameter", "install", [V, "-m", "pip", "install", "--disable-pip-version-check", "--no-deps", "{checkout_dir}/packages/qa-robot", "{secret}"]),
]


@pytest.mark.parametrize("label,phase,argv", BAD_STEPS, ids=[c[0] for c in BAD_STEPS])
def test_a_step_that_is_not_one_of_the_allowed_shapes_is_refused(label, phase, argv):
    p = profile(PROFILES, "local-python-robot")
    assert chk.step_problems(p, phase, {"id": "x", "title": "t", "argv": argv}), label


def test_an_install_with_nothing_to_install_is_refused():
    p = copy.deepcopy(profile(PROFILES, "local-python-robot"))
    p["pip_pins"] = []
    step = {"id": "x", "title": "t", "argv": [V, "-m", "pip", "install", "--disable-pip-version-check"]}
    assert chk.step_problems(p, "install", step)


def test_every_step_of_every_profile_passes_the_closed_shapes():
    for p in PROFILES["profiles"]:
        if p.get("kind") == "bundle":
            continue                         # a bundle profile's steps are compared with the exact list (tests below)
        for phase, steps in p["steps"].items():
            for s in steps:
                assert chk.step_problems(p, phase, s) == [], (p["id"], s["id"])


def test_a_step_environment_may_name_only_three_variables_with_a_path_parameter_or_the_loopback_url():
    p = profile(PROFILES, "local-python-selenium")
    s = next(x for x in p["steps"]["smoke"] if x["id"] == "selenium-browser")
    assert chk.step_problems(p, "smoke", s) == []
    for env in ({"LD_PRELOAD": "{chrome_binary}"}, {"QA_CHROME_BINARY": "/bin/sh"}, {"QA_CHROME_BINARY": "{venv_dir}"}, {"QA_APPIUM_URL": "http://example.invalid:4723"}):
        bad = dict(s, env=env)
        assert chk.step_problems(p, "smoke", bad), env


def test_only_smoke_and_check_steps_may_be_manual():
    p = profile(PROFILES, "local-python-robot")
    s = copy.deepcopy(p["steps"]["install"][0])
    s["manual"] = True
    assert "only smoke and check steps may be manual" in joined(chk.step_problems(p, "install", s))


# ------------------------------------------------------------------------------------------------ semantic rules (each rule can be disabled)
def case_unknown_engine(m):
    profile(m, "local-python-robot")["engines"] = ["cypress"]


def case_duplicate_id(m):
    m["profiles"].append(copy.deepcopy(m["profiles"][0]))


def case_same_engines_twice(m):
    q = copy.deepcopy(profile(m, "local-python-robot"))
    q["id"] = "local-python-robot-2"
    m["profiles"].append(q)


def case_pin_differs_from_manifest(m):
    next(x for x in profile(m, "local-python-robot")["pip_pins"] if x["name"] == "robotframework")["version"] = "7.4"


def case_pytest_out_of_range(m):
    next(x for x in profile(m, "local-python-robot")["pip_pins"] if x["name"] == "pytest")["version"] = "10.0.0"


def case_packages_differ_from_manifest(m):
    profile(m, "local-python-robot")["packages"] = ["packages/qa-robot"]


def case_package_without_metadata(m):
    profile(m, "local-python-robot")["packages"] = ["packages/qa-adapter-kit", "packages/qa-robot", "packages/qa-nothing"]


def case_default_not_a_path(m):
    profile(m, "local-python-robot")["params"]["venv_dir"]["default"] = "../x"


def case_param_required_with_default(m):
    profile(m, "local-python-robot")["params"]["venv_dir"]["required"] = True


def case_missing_parameter(m):
    del profile(m, "local-python-robot")["params"]["evidence_dir"]


def case_unknown_parameter(m):
    profile(m, "local-python-robot")["params"]["shell_flags"] = {"kind": "dir-path", "default": "x", "required": False, "description": "x"}


def case_evidence_not_declared(m):
    profile(m, "local-python-robot")["evidence"]["files"] = ["junit-adapter-kit.xml"]


def case_no_check_for_a_file(m):
    p = profile(m, "local-python-robot")
    p["steps"]["check"] = p["steps"]["check"][:-1]


def case_only_manual_smoke(m):
    p = profile(m, "local-python-robot")
    for s in p["steps"]["smoke"]:
        s["manual"] = True
    p["evidence"]["manual_files"], p["evidence"]["files"] = p["evidence"]["files"], []
    for s in p["steps"]["check"]:
        s["manual"] = True


def case_no_import_location_check(m):
    p = profile(m, "local-python-robot")
    p["steps"]["install"] = [s for s in p["steps"]["install"] if s["id"] != "installed-from-venv"]


def case_no_uninstall(m):
    profile(m, "local-python-robot")["steps"]["uninstall"] = []


def case_python_executable(m):
    profile(m, "local-python-robot")["python"]["executable"] = "python3.11"


def case_remote_url(m):
    m["source"]["url"] = "https://example.invalid/x.git"


def case_tags_differ(m):
    m["source"]["dependency_release_tags"]["agent-harness"] = ["v9.9.9"]


def case_repository_differs(m):
    m["source"]["repository"] = "someone/else"


def case_open_source_wording(m):
    profile(m, "local-python-robot")["limitations"].append("This is open source.")


def case_private_wording(m):
    profile(m, "local-python-robot")["limitations"].append("The private repository needs access.")


def case_verified_engine_without_real_backing(m):
    p = profile(m, "local-python-appium-ios")
    p["status"] = "verified"
    p["disabled_reason"] = None


def case_planned_with_steps(m):
    profile(m, "local-python-appium-ios")["steps"]["install"] = copy.deepcopy(profile(m, "local-python-robot")["steps"]["install"])


def case_verified_without_a_verified_host(m):
    p = profile(m, "local-python-robot")
    p["status"] = "verified"
    for h in p["hosts"]:
        h["status"] = "experimental"
        h["verified_by"] = None


def case_experimental_with_a_verified_host(m):
    p = profile(m, "local-python-robot")
    p["status"] = "experimental"


def case_duplicate_host(m):
    p = profile(m, "local-python-robot")
    p["hosts"].append(copy.deepcopy(p["hosts"][0]))


SEMANTIC_CASES = [
    (case_unknown_engine, "is not in the capability manifest"),
    (case_duplicate_id, "duplicate id"),
    (case_same_engines_twice, "same target and engines"),
    (case_pin_differs_from_manifest, "must be 7.5"),
    (case_pytest_out_of_range, "outside the range CI uses"),
    (case_packages_differ_from_manifest, "packages must be"),
    (case_package_without_metadata, "has no pyproject.toml"),
    (case_default_not_a_path, "is not a valid dir-path"),
    (case_param_required_with_default, "required exactly when it has no default"),
    (case_missing_parameter, "missing parameter evidence_dir"),
    (case_unknown_parameter, "is not a generator field"),
    (case_evidence_not_declared, "the smoke steps write"),
    (case_no_check_for_a_file, "needs exactly one check step"),
    (case_only_manual_smoke, "needs a smoke step that is not manual"),
    (case_no_import_location_check, "imported from the virtual environment"),
    (case_no_uninstall, "needs source, install and uninstall steps"),
    (case_python_executable, "python executable must be"),
    (case_remote_url, "url must be the repository's own clone url"),
    (case_tags_differ, "differ from pins.toml"),
    (case_repository_differs, "repository differs"),
    (case_open_source_wording, "wording"),
    (case_private_wording, "wording"),
    (case_planned_with_steps, "a planned profile has no hosts and no steps"),
    (case_duplicate_host, "listed twice"),
    (case_verified_without_a_verified_host, "verified needs at least one verified host"),
    (case_experimental_with_a_verified_host, "a verified host makes the profile verified"),
]


@pytest.mark.parametrize("apply,needle", SEMANTIC_CASES, ids=[c[0].__name__ for c in SEMANTIC_CASES])
def test_the_semantic_check_refuses(apply, needle):
    m = fresh()
    apply(m)
    schema_found = qj.validate(m, SCHEMA)
    found = schema_found if schema_found and needle not in joined(schema_found) and False else chk.semantic_problems(m, CAPS, ROOT)
    assert needle in joined(found), found


def test_a_profile_cannot_be_verified_unless_every_engine_has_a_real_engine_in_the_capability_manifest():
    m = fresh()
    p = profile(m, "local-python-robot")
    caps = copy.deepcopy(CAPS)
    next(e for e in caps["engines"] if e["engine"] == "robotframework")["test_level"] = "offline-fake"
    p["status"] = "verified"
    p["hosts"][0]["status"] = "verified"
    p["hosts"][0]["verified_by"] = next((h["verified_by"] for h in profile(PROFILES, "local-python-robot")["hosts"] if h["verified_by"]), None) or {
        "workflow": "tests.yml", "job_key": "profile-local-python-robot", "job_name": "install profile local-python-robot", "run_id": 1, "job_id": 2, "head_sha": "a" * 40,
        "source_commit": PROFILES["source"]["pinned_commit"], "run_conclusion": "success", "run_url": "https://github.com/redevops-io/redevops-qa/actions/runs/1", "url": "https://github.com/redevops-io/redevops-qa/actions/runs/1/job/2",
        "completed_on": "2026-11-01", "summary": "x"}
    assert "has test level offline-fake" in joined(chk.semantic_problems(m, caps, ROOT))


def verified_copy():
    """A copy of the profiles in which the robot profile is verified through a well-formed job entry (so the job rules are exercised)."""
    m = fresh()
    p = profile(m, "local-python-robot")
    p["status"] = "verified"
    h = p["hosts"][0]
    h["status"] = "verified"
    h["verified_by"] = {"workflow": "tests.yml", "job_key": "profile-local-python-robot", "job_name": "install profile local-python-robot", "run_id": 1, "job_id": 2,
                        "head_sha": "a" * 40, "source_commit": PROFILES["source"]["pinned_commit"], "run_conclusion": "success",
                        "run_url": "https://github.com/redevops-io/redevops-qa/actions/runs/1",
                        "url": "https://github.com/redevops-io/redevops-qa/actions/runs/1/job/2", "completed_on": "2026-11-01", "summary": "x"}
    return m, p, h


def job_problems(workflow_mutation=None, profile_mutation=None):
    m, p, h = verified_copy()
    if profile_mutation:
        profile_mutation(m, p, h)
    if workflow_mutation:
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        shutil.copytree(ROOT / ".github", tmp / ".github")
        shutil.copy(ROOT / "pins.toml", tmp / "pins.toml")
        shutil.copytree(ROOT / "packages", tmp / "packages", ignore=shutil.ignore_patterns("tests", "src", "*.pyc", "__pycache__"))
        (tmp / "packages" / "qa-runner" / "src" / "qa_runner").mkdir(parents=True)             # the bundle profile's archive name comes from the runner's version
        shutil.copy(ROOT / "packages" / "qa-runner" / "src" / "qa_runner" / "__init__.py", tmp / "packages" / "qa-runner" / "src" / "qa_runner" / "__init__.py")
        wf = yaml.safe_load((tmp / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8"))
        workflow_mutation(wf["jobs"]["profile-local-python-robot"], wf)
        (tmp / ".github" / "workflows" / "tests.yml").write_text(yaml.safe_dump(wf, sort_keys=False, width=10**6), encoding="utf-8")
        return chk.semantic_problems(m, CAPS, tmp)
    return chk.semantic_problems(m, CAPS, ROOT)


def test_the_recorded_run_head_and_the_pinned_install_commit_are_stated_separately():
    src = PROFILES["source"]["pinned_commit"]
    for p in PROFILES["profiles"]:
        for h in p["hosts"]:
            vb = h["verified_by"]
            if vb:
                assert vb["source_commit"] == src and vb["run_conclusion"] == "success"
                assert vb["head_sha"] != src, "the run head supplies the workflow and tools; the pin is what was installed"
                assert "installed from the pinned commit" in vb["summary"]


def test_a_well_formed_verified_entry_passes_the_job_rules():
    found = job_problems()
    assert not [f for f in found if "host linux-x86_64" in f], found


JOB_CASES = [
    ("a run that installed from another commit", lambda m, p, h: h["verified_by"].__setitem__("source_commit", "c" * 40), "source_commit must be the pinned commit"),
    ("a job that does not exist", lambda m, p, h: h["verified_by"].__setitem__("job_key", "profile-nothing"), "has no job"),
    ("a job named differently", lambda m, p, h: h["verified_by"].__setitem__("job_name", "something else"), "is not named"),
    ("a run url that does not match", lambda m, p, h: h["verified_by"].__setitem__("run_url", "https://github.com/redevops-io/redevops-qa/actions/runs/9"), "run_url and url must be built"),
    ("a different os and arch", lambda m, p, h: h.__setitem__("os_arch", "macos-arm64"), "which is not macos-arm64"),
    ("a job that runs another profile", lambda m, p, h: h["verified_by"].__setitem__("job_key", "profile-local-python-selenium"), "does not run tools/run_install_profile.py --profile local-python-robot"),
]


@pytest.mark.parametrize("label,mutation,needle", JOB_CASES, ids=[c[0] for c in JOB_CASES])
def test_the_ci_job_behind_a_verified_status_is_checked(label, mutation, needle):
    assert needle in joined(job_problems(profile_mutation=mutation)), label


def _text(job):
    return [s for s in job["steps"] if "run" in s]


def test_a_job_with_the_experimental_channel_a_condition_or_no_required_check_warning_is_refused():
    def experimental(job, wf):
        for s in _text(job):
            s["run"] = s["run"].replace("--channel stable", "--channel experimental")
    assert "must run the stable channel" in joined(job_problems(workflow_mutation=experimental))

    def conditional(job, wf):
        job["if"] = "github.event_name == 'push'"
    assert "no condition, no continue-on-error and no matrix" in joined(job_problems(workflow_mutation=conditional))

    def step_conditional(job, wf):
        job["steps"][0]["if"] = "always()"
    assert "no condition" in joined(job_problems(workflow_mutation=step_conditional))

    def tolerant(job, wf):
        job["continue-on-error"] = True
    assert "no condition" in joined(job_problems(workflow_mutation=tolerant))

    def run_step_conditional(job, wf):
        next(s for s in job["steps"] if "tools/run_install_profile.py" in str(s.get("run", "")))["if"] = "always()"
    assert "no condition" in joined(job_problems(workflow_mutation=run_step_conditional))

    def upload_on_success_only(job, wf):
        next(s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact"))["if"] = "success()"
    assert "no condition" in joined(job_problems(workflow_mutation=upload_on_success_only))

    def tolerant_upload(job, wf):
        next(s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact"))["continue-on-error"] = True
    assert "no condition" in joined(job_problems(workflow_mutation=tolerant_upload))


@pytest.mark.parametrize("condition", ["always() && false", "failure()", "${{ always() }}", "always() || true", "success()", "ALWAYS()", "", True, None])
def test_only_the_exact_text_always_qualifies_an_evidence_upload(condition):
    step = {"uses": "actions/upload-artifact@v4", "with": {"name": "x", "path": "y"}}
    if condition is not None:
        step["if"] = condition
    assert chk.keeps_evidence(step) is False


@pytest.mark.parametrize("step", [
    {"uses": "actions/checkout@v4", "if": "always()"},
    {"uses": "evil/actions/upload-artifact@v4", "if": "always()"},
    {"run": "echo hi", "if": "always()"},
    {"uses": "actions/upload-artifact@v4", "run": "echo hi", "if": "always()"},
    {"uses": "actions/upload-artifact@v4", "shell": "bash", "if": "always()"},
    {"uses": "actions/upload-artifact@v4", "continue-on-error": True, "if": "always()"},
    {"uses": "actions/upload-artifact@v4", "continue-on-error": False, "if": "always()"},
])
def test_a_step_that_is_not_a_plain_upload_never_qualifies_even_with_always(step):
    assert chk.keeps_evidence(step) is False


def test_a_plain_upload_with_always_qualifies():
    assert chk.keeps_evidence({"uses": "actions/upload-artifact@v4", "if": "always()", "with": {"name": "x"}}) is True


def test_the_job_check_refuses_the_look_alike_conditions_on_an_evidence_upload():
    for condition in ("always() && false", "failure()", "${{ always() }}"):
        def look_alike(job, wf, condition=condition):
            next(s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact"))["if"] = condition
        assert "no condition" in joined(job_problems(workflow_mutation=look_alike)), condition

    def non_upload(job, wf):
        next(s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/setup-python"))["if"] = "always()"
    assert "no condition" in joined(job_problems(workflow_mutation=non_upload))


def test_the_selenium_profile_evidence_upload_still_fails_when_its_path_is_missing_and_expires():
    uploads = [s for s in WORKFLOW["jobs"]["profile-local-python-selenium"]["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact")]
    assert len(uploads) == 1 and uploads[0]["with"]["if-no-files-found"] == "error" and uploads[0]["with"]["retention-days"] == 14


def test_the_evidence_upload_of_a_profile_job_may_run_always_so_that_a_failed_run_keeps_its_evidence():
    def upload_always(job, wf):
        next(s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact"))["if"] = "always()"
    assert "no condition" not in joined(job_problems(workflow_mutation=upload_always))
    sel = WORKFLOW["jobs"]["profile-local-python-selenium"]["steps"]
    uploads = [s for s in sel if str(s.get("uses", "")).startswith("actions/upload-artifact")]
    assert [u["if"] for u in uploads] == ["always()"] and uploads[0]["with"]["name"] == "evidence-local-python-selenium"
    assert not [s for s in sel if "if" in s and s not in uploads]            # every other step, the profile's own included, is unconditional

    def unmarked(job, wf):
        job["name"] = "install profile local-python-robot (clean venv)"
    assert "NOT a required check until proven" in joined(job_problems(workflow_mutation=unmarked))

    def other_python(job, wf):
        for s in job["steps"]:
            if "python-version" in s.get("with", {}):
                s["with"]["python-version"] = "3.11"
    assert "does not set up Python 3.12" in joined(job_problems(workflow_mutation=other_python))

    def no_pinned_checkout(job, wf):
        for s in job["steps"]:
            if s.get("with", {}).get("path") == ".profile-src":
                s["with"]["ref"] = "main"
    assert "must check out the pinned commit" in joined(job_problems(workflow_mutation=no_pinned_checkout))

    def other_runner(job, wf):
        job["runs-on"] = "macos-14"
    assert "which is not linux-x86_64" in joined(job_problems(workflow_mutation=other_runner))


def test_the_workflow_has_one_job_per_offered_profile_and_never_makes_them_a_dependency_or_conditional():
    for p in PROFILES["profiles"]:
        if p["status"] == "planned":
            continue
        job = WORKFLOW["jobs"][f"profile-{p['id']}"]
        text = "\n".join(str(s.get("run", "")) for s in job["steps"])
        assert f"--profile {p['id']}" in text and "tools/run_install_profile.py" in text
        if p.get("kind") == "bundle":
            assert job["needs"] == "bundle" and "--phases source,install,smoke,check" in text and "--phases uninstall" in text and "required check" in job["name"]
            assert not {"if", "continue-on-error", "strategy"} & set(job) and not [s for s in job["steps"] if "if" in s or "continue-on-error" in s]
            continue
        assert not {"if", "needs", "continue-on-error", "strategy"} & set(job) and not [s for s in job["steps"] if "continue-on-error" in s or ("if" in s and not chk.keeps_evidence(s))]
        assert "required check" in job["name"] and "--phases install,smoke,check" in text and "--phases uninstall" in text
        assert job["runs-on"] == "ubuntu-24.04"
    other = WORKFLOW["jobs"]["install-profiles"]
    run = "\n".join(str(s.get("run", "")) for s in other["steps"])
    assert not {"if", "needs", "continue-on-error", "strategy"} & set(other)
    assert other["steps"][0]["with"]["fetch-depth"] == 0 and "check_install_profiles.py --cross-check" in run and "--no-freshness" not in run
    assert "tests/test_install_profiles.py" in run and "tests/test_install_config.py" in run and "tools/check_junit.py" in run


def test_the_profile_jobs_fetch_the_pinned_commit_and_add_no_credentials():
    for key, job in WORKFLOW["jobs"].items():
        if not key.startswith("profile-") or key == "profile-local-python-qa":
            continue                         # the bundle profile installs from an archive: no checkout of a pinned commit
        fetch = next(s for s in job["steps"] if s.get("with", {}).get("path") == ".profile-src")
        assert fetch["with"]["ref"] == "${{ steps.profile.outputs.commit }}" and fetch["with"]["persist-credentials"] is False
        assert set(fetch["with"]) == {"repository", "ref", "path", "persist-credentials"}
        assert "pinned_commit" in job["steps"][1]["run"]


# ------------------------------------------------------------------------------------------------ planned targets
def test_a_planned_target_whose_files_appear_in_the_repository_is_found(tmp_path):
    root = tmp_path
    for rel in (".github", "pins.toml", "packages", "third_party"):
        src = ROOT / rel
        (shutil.copytree(src, root / rel, ignore=shutil.ignore_patterns("tests", "__pycache__", "build", "*.egg-info")) if src.is_dir() else shutil.copy(src, root / rel))
    assert not [f for f in chk.semantic_problems(PROFILES, CAPS, root) if "is planned but" in f]
    (root / "deploy").mkdir()
    (root / "deploy" / "docker-compose.yml").write_text("services: {}\n")
    assert "target docker-compose is planned but the repository now has" in joined(chk.semantic_problems(PROFILES, CAPS, root))
    (root / "chart").mkdir()
    (root / "chart" / "Chart.yaml").write_text("name: x\n")
    assert "target kubernetes-helm is planned but" in joined(chk.semantic_problems(PROFILES, CAPS, root))


# ------------------------------------------------------------------------------------------------ the generated document
def test_the_checked_in_document_equals_the_generated_one_and_generation_is_deterministic():
    assert (ROOT / "docs" / "QA_INSTALL_PROFILES.md").read_text(encoding="utf-8") == chk.render_docs(PROFILES) == chk.render_docs(copy.deepcopy(PROFILES))
    shuffled = json.loads(json.dumps(PROFILES), object_pairs_hook=lambda pairs: dict(reversed(pairs)))
    assert chk.render_docs(shuffled) == chk.render_docs(PROFILES)


def test_the_document_shows_every_command_the_status_and_the_reason_for_what_is_not_offered():
    text = chk.render_docs(PROFILES)
    for p in PROFILES["profiles"]:
        assert f"## {p['id']}" in text
        if p["status"] == "planned":
            assert p["disabled_reason"] in text
        for phase in p["steps"].values():
            for s in phase:
                assert "# " + s["title"] in text
    for t in PROFILES["targets"].values():
        if t["disabled_reason"]:
            assert t["disabled_reason"] in text
    assert "manual: not run by CI" in text and text.startswith(chk.GENERATED_NOTICE)


def test_a_stale_or_hand_edited_document_is_found(tmp_path):
    (tmp_path / "docs").mkdir()
    doc = chk.render_docs(PROFILES)
    (tmp_path / "docs" / "QA_INSTALL_PROFILES.md").write_text(doc, encoding="utf-8")
    assert chk.docs_problems(PROFILES, tmp_path) == []
    (tmp_path / "docs" / "QA_INSTALL_PROFILES.md").write_text(doc + "x", encoding="utf-8")
    assert chk.docs_problems(PROFILES, tmp_path)
    (tmp_path / "docs" / "QA_INSTALL_PROFILES.md").unlink()
    assert "is missing" in joined(chk.docs_problems(PROFILES, tmp_path))


# ------------------------------------------------------------------------------------------------ freshness
def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-C", str(cwd), *args],
                          capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture()
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "f").write_text("1")
    git(tmp_path, "add", "f")
    git(tmp_path, "commit", "-q", "-m", "one")
    on_main = git(tmp_path, "rev-parse", "HEAD")
    git(tmp_path, "checkout", "-q", "-b", "side")
    (tmp_path / "f").write_text("2")
    git(tmp_path, "commit", "-q", "-am", "two")
    off = git(tmp_path, "rev-parse", "HEAD")
    git(tmp_path, "checkout", "-q", "main")
    return tmp_path, on_main, off


def with_commits(pinned, run_sha=None):
    m = fresh()
    m["source"]["pinned_commit"] = pinned
    for p in m["profiles"]:
        for h in p["hosts"]:
            h["verified_by"] = None
    if run_sha:
        profile(m, "local-python-robot")["hosts"][0]["verified_by"] = {"head_sha": run_sha}
    return m


def test_the_pinned_commit_and_every_recorded_run_must_be_ancestors_of_main(repo):
    root, on_main, off = repo
    assert chk.freshness_problems(with_commits(on_main, on_main), root) == []
    assert "source pinned_commit" in joined(chk.freshness_problems(with_commits(off), root)) and "not an ancestor" in joined(chk.freshness_problems(with_commits(off), root))
    assert "head_sha" in joined(chk.freshness_problems(with_commits(on_main, off), root))
    assert "is not a commit" in joined(chk.freshness_problems(with_commits("d" * 40), root))


def test_a_run_of_a_commit_that_is_only_on_the_checked_branch_is_not_fresh(repo):
    root, on_main, off = repo
    git(root, "checkout", "-q", "side")                      # HEAD is on a branch that is not main, and off is an ancestor of HEAD
    assert "not an ancestor of main" in joined(chk.freshness_problems(with_commits(on_main, off), root, main_ref="main"))
    assert chk.freshness_problems(with_commits(on_main, on_main), root, main_ref="main") == []


def test_no_main_is_a_finding_not_a_skip(tmp_path):
    git(tmp_path, "init", "-q", "-b", "other")
    (tmp_path / "f").write_text("1")
    git(tmp_path, "add", "f")
    git(tmp_path, "commit", "-q", "-m", "one")
    assert "cannot resolve the main branch" in joined(chk.freshness_problems(fresh(), tmp_path))


# ------------------------------------------------------------------------------------------------ re-checking runs (opt in)
class Api:
    def __init__(self, m, **bad):
        self.items = [(h["verified_by"]) for p in m["profiles"] for h in p["hosts"] if h["verified_by"]]
        self.bad = bad

    def __call__(self, url):
        if self.bad.get("error"):
            raise OSError("down")
        mine = [vb for vb in self.items if f"/runs/{vb['run_id']}" in url]
        assert mine, url
        if "/jobs" in url:
            return {"jobs": [{"id": self.bad.get("job_id", vb["job_id"]), "name": vb["job_name"] + " (x)", "conclusion": self.bad.get("conclusion", "success"),
                              "completed_at": self.bad.get("completed", vb["completed_on"]) + "T00:00:00Z"} for vb in mine]}
        return {"head_sha": self.bad.get("head", mine[0]["head_sha"]), "conclusion": self.bad.get("run_conclusion", mine[0]["run_conclusion"])}


def test_re_checking_the_recorded_runs():
    m = fresh()
    if not Api(m).items:
        m, p, h = verified_copy()
    repo_name = "redevops-io/redevops-qa"
    assert chk.verify_ci_problems(m, repo_name, Api(m)) == []
    assert "head is" in joined(chk.verify_ci_problems(m, repo_name, Api(m, head="e" * 40)))
    assert "concluded failure" in joined(chk.verify_ci_problems(m, repo_name, Api(m, conclusion="failure")))
    assert "as a whole concluded failure" in joined(chk.verify_ci_problems(m, repo_name, Api(m, run_conclusion="failure")))
    assert "has no job" in joined(chk.verify_ci_problems(m, repo_name, Api(m, job_id=1)))
    assert "completed on" in joined(chk.verify_ci_problems(m, repo_name, Api(m, completed="2025-01-01")))
    assert "cannot read run" in joined(chk.verify_ci_problems(m, repo_name, Api(m, error=True)))


# ------------------------------------------------------------------------------------------------ the log of a recorded run (opt in)
def log_for(vb, *, sha=None, counts=None, checkout=True):
    """A job log shaped like the real one: the checkout line (printed by the install step and again by the uninstall step) and one pytest summary per suite."""
    sha = sha or vb["source_commit"]
    counts = counts if counts is not None else [int(x) for x in chk.SUMMARY_COUNTS.search(vb["summary"]).group(1).split(" + ")]
    lines = ["2026-11-03T20:22:50.0000000Z ##[group]Run python tools/run_install_profile.py"]
    if checkout:
        lines.append(f"2026-11-03T20:22:54.9296431Z checkout verified: HEAD is the pinned commit {sha}, clean tree")
    lines += [f"2026-11-03T20:23:1{i}.8464763Z {n} passed in 8.86s" for i, n in enumerate(counts)]
    if checkout:
        lines.append(f"2026-11-03T20:23:46.6420489Z checkout verified: HEAD is the pinned commit {sha}, clean tree")
    return "\n".join(lines) + "\n"


class Logs:
    def __init__(self, m, **kw):
        self.by_job = {vb["job_id"]: log_for(vb, **kw) for p in m["profiles"] for h in p["hosts"] for vb in [h["verified_by"]] if vb}
        self.error = False

    def __call__(self, url):
        if self.error:
            raise OSError("expired")
        return self.by_job[int(url.split("/jobs/")[1].split("/")[0])]


def recorded_runs():
    m = fresh()
    assert [vb for p in m["profiles"] for h in p["hosts"] for vb in [h["verified_by"]] if vb], "the repository records at least one run"
    return m


def test_a_recorded_run_whose_log_confirms_the_commit_and_the_counts_is_accepted_and_reported_as_confirmed():
    m = recorded_runs()
    problems, confirmed = chk.verify_ci_report(m, "o/r", Api(m), Logs(m), head_on_main=lambda sha: False)
    assert problems == [] and confirmed == {(p["id"], h["os_arch"]) for p in m["profiles"] for h in p["hosts"] if h["verified_by"]}


def test_a_log_that_shows_another_installed_commit_is_refused():
    m = recorded_runs()
    problems, confirmed = chk.verify_ci_report(m, "o/r", Api(m), Logs(m, sha="5e9c8da6248f9c4e170b77ab4ff202b519c970a8"), head_on_main=lambda sha: False)
    assert problems and confirmed == set()                              # a refused log never opens the freshness exception
    assert "installed " + "5e9c8da" in joined(chk.verify_ci_problems(m, "o/r", Api(m), Logs(m, sha="5e9c8da6248f9c4e170b77ab4ff202b519c970a8")))


def test_the_old_record_that_names_the_new_pin_for_the_old_runs_numbers_is_refused():
    m = recorded_runs()
    for p in m["profiles"]:
        for h in p["hosts"]:
            if h["verified_by"]:
                h["verified_by"]["summary"] = h["verified_by"]["summary"].replace("369 + 154 + 12", "359 + 135 + 11").replace("369 + 188 + 13", "359 + 133 + 10")
    old_logs = Logs(m, sha="5e9c8da6248f9c4e170b77ab4ff202b519c970a8")      # what the run of 2026-11-01 printed
    found = joined(chk.verify_ci_problems(m, "o/r", Api(m), old_logs))
    assert "installed 5e9c8da6248f9c4e170b77ab4ff202b519c970a8, the record says " + m["source"]["pinned_commit"] in found


def test_logged_counts_that_differ_from_the_recorded_ones_are_refused():
    m = recorded_runs()
    assert "passed tests, the record says" in joined(chk.verify_ci_problems(m, "o/r", Api(m), Logs(m, counts=[1, 2, 3])))
    assert "shows no passed tests" in joined(chk.verify_ci_problems(m, "o/r", Api(m), Logs(m, counts=[])))


def test_a_log_without_the_checkout_line_is_refused():
    m = recorded_runs()
    assert "cannot be confirmed" in joined(chk.verify_ci_problems(m, "o/r", Api(m), Logs(m, checkout=False)))


def test_a_summary_without_counts_is_refused():
    m = recorded_runs()
    for p in m["profiles"]:
        for h in p["hosts"]:
            if h["verified_by"]:
                h["verified_by"]["summary"] = "it passed"
    logs = Logs(recorded_runs())
    assert "does not state the passed counts" in joined(chk.verify_ci_problems(m, "o/r", Api(m), logs))


def test_an_unreadable_log_fails_closed_for_a_head_that_is_not_on_main_and_is_tolerated_for_one_that_is():
    m = recorded_runs()
    logs = Logs(m)
    logs.error = True
    assert "failing closed" in joined(chk.verify_ci_problems(m, "o/r", Api(m), logs, head_on_main=lambda sha: False))
    assert chk.verify_ci_problems(m, "o/r", Api(m), logs, head_on_main=lambda sha: True) == []
    assert "failing closed" in joined(chk.verify_ci_problems(m, "o/r", Api(m), None, head_on_main=lambda sha: False))
    problems, confirmed = chk.verify_ci_report(m, "o/r", Api(m), logs, head_on_main=lambda sha: True)
    assert confirmed == set()                                           # tolerated is not confirmed: it never opens the exception for a head that is off main


def test_a_log_that_disagrees_is_refused_even_when_the_head_is_on_main():
    m = recorded_runs()
    assert joined(chk.verify_ci_problems(m, "o/r", Api(m), Logs(m, counts=[1]), head_on_main=lambda sha: True))


def test_a_head_that_is_only_an_ancestor_of_the_commit_under_test_is_fresh_only_when_its_log_confirmed_it(repo):
    root, on_main, off = repo
    git(root, "checkout", "-q", "side")                                   # HEAD is on a branch that is not main; off is HEAD, an ancestor of itself
    m = with_commits(on_main, off)
    key = ("local-python-robot", profile(m, "local-python-robot")["hosts"][0]["os_arch"])
    assert "not an ancestor of main" in joined(chk.freshness_problems(m, root, main_ref="main"))
    assert "--verify-ci" in joined(chk.freshness_problems(m, root, main_ref="main"))
    assert chk.freshness_problems(m, root, main_ref="main", head_ok=frozenset({key})) == []
    assert "not an ancestor of main" in joined(chk.freshness_problems(m, root, main_ref="main", head_ok=frozenset({("other", "linux-x86_64")})))


def test_a_head_that_is_in_neither_history_stays_refused_even_when_confirmed(repo):
    root, on_main, off = repo                                             # HEAD is main (on_main); off is on the side branch only
    m = with_commits(on_main, off)
    key = ("local-python-robot", profile(m, "local-python-robot")["hosts"][0]["os_arch"])
    found = joined(chk.freshness_problems(m, root, main_ref="main", head_ok=frozenset({key})))
    assert "not an ancestor of main" in found and "--verify-ci" not in found


def test_the_pinned_commit_never_gets_the_exception(repo):
    root, on_main, off = repo
    git(root, "checkout", "-q", "side")
    m = with_commits(off)                                                  # the pin is only on the side branch
    everything = frozenset((p["id"], h["os_arch"]) for p in m["profiles"] for h in p["hosts"])
    assert "source pinned_commit" in joined(chk.freshness_problems(m, root, main_ref="main", head_ok=everything))


def test_the_log_is_read_through_the_redirect_without_sending_the_credential(monkeypatch):
    import http.server
    import threading
    seen = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen[self.path] = self.headers.get("Authorization")
            if self.path == "/api/logs":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_address[1]}/blob")
                self.end_headers()
                return
            body = b"log text"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    server = http.server.HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    monkeypatch.setenv("GH_TOKEN", "x" * 8)
    try:
        assert chk.api_get_log(f"http://127.0.0.1:{server.server_address[1]}/api/logs") == "log text"
    finally:
        server.shutdown()
        server.server_close()
    assert seen["/api/logs"] == "Bearer " + "x" * 8 and seen["/blob"] is None


# ------------------------------------------------------------------------------------------------ the runner
def make_checkout(tmp_path):
    co = tmp_path / "co"
    co.mkdir()
    git(co, "init", "-q", "-b", "main")
    (co / "f").write_text("1")
    git(co, "add", "f")
    git(co, "commit", "-q", "-m", "one")
    return co, git(co, "rev-parse", "HEAD")


def write_profiles(tmp_path, commit):
    m = fresh()
    m["source"]["pinned_commit"] = commit
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps(m), encoding="utf-8")
    return path


class Recorder:
    def __init__(self, fail_on=None, create_evidence=True, keep_venv=False):
        self.calls, self.fail_on, self.create_evidence, self.keep_venv = [], fail_on, create_evidence, keep_venv

    def __call__(self, argv, env, cwd):
        self.calls.append((argv, env, cwd))
        if self.fail_on and self.fail_on in " ".join(argv):
            return 1
        for a in argv:
            if a.startswith("--junitxml=") and self.create_evidence:
                p = Path(a.split("=", 1)[1])
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("<testsuite/>")
        return 0


def run_main(monkeypatch, tmp_path, rec, *extra, profile_id="local-python-robot", commit=None, phases="install,smoke,check", channel="experimental", host="linux-x86_64"):
    co, head = make_checkout(tmp_path)
    profiles = write_profiles(tmp_path, commit or head)
    monkeypatch.setattr(runner, "run", rec)
    argv = ["--profile", profile_id, "--host", host, "--channel", channel, "--work", str(tmp_path / "work"), "--checkout", str(co), "--phases", phases,
            "--profiles-file", str(profiles), *extra]
    return runner.main(argv)


def test_the_runner_executes_the_generated_steps_in_order_in_a_scrubbed_environment(monkeypatch, tmp_path, capsys):
    rec = Recorder()
    assert run_main(monkeypatch, tmp_path, rec) == 0
    assert len(rec.calls) == 4 + 3 + 3          # four install steps, three smoke steps, three check steps; the source phase is not requested
    for argv, env, cwd in rec.calls:
        assert set(env) <= {"HOME", "PATH", "LANG", "PYTHONDONTWRITEBYTECODE", "QA_CHROME_BINARY", "QA_CHROMEDRIVER_PATH", "QA_APPIUM_URL"}
        assert cwd == str(tmp_path / "work") and not any(k for k in env if re.search(r"TOKEN|SECRET|KEY|PASSWORD", k, re.I))
    out = capsys.readouterr().out
    assert "checkout verified" in out and "manifest digest sha256:" in out and "OK profile local-python-robot" in out
    kinds = ["venv" if c[0][1:3] == ["-m", "venv"] else "pip" if c[0][1:4] == ["-m", "pip", "install"] else "pytest" if c[0][1:3] == ["-m", "pytest"]
             else "check" if c[0][1].endswith("check_junit.py") else "other" for c in rec.calls]
    assert kinds == ["venv", "pip", "pip", "other"] + ["pytest"] * 3 + ["check"] * 3


def test_the_runner_uses_the_same_steps_the_configurator_prints(monkeypatch, tmp_path):
    rec = Recorder()
    run_main(monkeypatch, tmp_path, rec)
    caps = CAPS
    work = tmp_path / "work"
    m = json.loads((tmp_path / "profiles.json").read_text())
    cfg = gen.generate({"engines": ["robotframework"], "target": "local-python", "host": "linux-x86_64", "verifier": False, "channel": "experimental",
                        "venv_dir": str(work / "venv"), "evidence_dir": str(work / "evidence"), "checkout_dir": str(tmp_path / "co")}, caps, m)["config"]
    expected = [s["argv"] for phase in ("install", "smoke", "check") for s in cfg["steps"][phase]]
    assert [c[0] for c in rec.calls] == expected


def test_manual_steps_are_printed_and_never_run(monkeypatch, tmp_path, capsys):
    rec = Recorder()
    assert run_main(monkeypatch, tmp_path, rec, profile_id="local-python-appium-android") == 0
    assert "manual step: printed, not run" in capsys.readouterr().out
    assert not [c for c in rec.calls if "appium_android" in " ".join(c[0]) or "junit-appium-android" in " ".join(c[0])]


def test_a_failing_step_fails_the_run_and_stops_it(monkeypatch, tmp_path, capsys):
    rec = Recorder(fail_on=" -m pytest ")
    assert run_main(monkeypatch, tmp_path, rec) == 1
    assert "FAIL step kit-offline exited 1" in capsys.readouterr().out
    assert not [c for c in rec.calls if "check_junit" in " ".join(c[0])]


def test_missing_evidence_after_the_smoke_phase_fails_the_run(monkeypatch, tmp_path, capsys):
    assert run_main(monkeypatch, tmp_path, Recorder(create_evidence=False)) == 1
    assert "evidence files missing" in capsys.readouterr().out


def test_a_checkout_that_is_not_the_pinned_commit_is_refused_before_anything_runs(monkeypatch, tmp_path, capsys):
    rec = Recorder()
    assert run_main(monkeypatch, tmp_path, rec, commit="a" * 40) == 1
    assert "is not at the pinned commit" in capsys.readouterr().out and rec.calls == []


def test_a_dirty_checkout_is_refused(monkeypatch, tmp_path, capsys):
    co, head = make_checkout(tmp_path)
    (co / "extra").write_text("x")
    profiles = write_profiles(tmp_path, head)
    monkeypatch.setattr(runner, "run", Recorder())
    code = runner.main(["--profile", "local-python-robot", "--host", "linux-x86_64", "--channel", "experimental", "--work", str(tmp_path / "w"), "--checkout", str(co),
                        "--profiles-file", str(profiles)])
    assert code == 1 and "local changes" in capsys.readouterr().out


def test_a_profile_or_host_that_is_not_offered_is_refused_with_the_generators_reason(monkeypatch, tmp_path, capsys):
    rec = Recorder()
    assert run_main(monkeypatch, tmp_path, rec, profile_id="local-python-appium-ios", host="macos-arm64") == 2 and rec.calls == []
    assert "PROFILE_PLANNED" in capsys.readouterr().out
    other = tmp_path / "b"
    other.mkdir()
    assert run_main(monkeypatch, other, Recorder(), profile_id="local-python-nothing") == 2
    assert "unknown profile" in capsys.readouterr().out


def test_the_uninstall_phase_fails_while_the_virtual_environment_is_still_there(monkeypatch, tmp_path, capsys):
    (tmp_path / "work" / "venv").mkdir(parents=True)
    assert run_main(monkeypatch, tmp_path, Recorder(), phases="uninstall") == 1
    assert "still there after the uninstall phase" in capsys.readouterr().out


def test_an_unknown_phase_is_refused(monkeypatch, tmp_path, capsys):
    assert run_main(monkeypatch, tmp_path, Recorder(), phases="install,deploy") == 2


# ------------------------------------------------------------------------------------------------ the two code strings
def test_the_removal_code_removes_only_a_virtual_environment(tmp_path):
    venv = tmp_path / "v"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("home = x\n")
    other = tmp_path / "o"
    other.mkdir()
    (other / "precious").write_text("x")
    ok = subprocess.run([sys.executable, "-c", chk.CODE_REMOVE, str(venv)], capture_output=True, text=True)
    refused = subprocess.run([sys.executable, "-c", chk.CODE_REMOVE, str(other)], capture_output=True, text=True)
    assert ok.returncode == 0 and not venv.exists()
    assert refused.returncode != 0 and (other / "precious").exists() and "refusing" in refused.stderr
    assert subprocess.run([sys.executable, "-c", chk.CODE_REMOVE, str(tmp_path / "missing")], capture_output=True).returncode != 0


def test_the_import_location_code_accepts_only_modules_under_the_given_directory(tmp_path):
    ok = subprocess.run([sys.executable, "-I", "-c", chk.CODE_ASSERT, str(Path(sys.prefix).resolve()), "json"], capture_output=True, text=True)
    bad = subprocess.run([sys.executable, "-I", "-c", chk.CODE_ASSERT, str(tmp_path), "json"], capture_output=True, text=True)
    assert bad.returncode != 0 and "not imported from the virtual environment: json" in bad.stderr
    assert ok.returncode in (0, 1)


# ------------------------------------------------------------------------------------------------ the bundle profile (local-python-qa)
def qa_mutation(fn):
    m = copy.deepcopy(PROFILES)
    fn(profile(m, "local-python-qa"), m)
    return semantic(m)


def test_the_bundle_profile_is_offered_with_the_verifier_and_passes_every_check():
    p = profile(PROFILES, "local-python-qa")
    assert p["kind"] == "bundle" and p["verifier"] is True and sorted(p["engines"]) == ["playwright", "robotframework"]
    assert PROFILES["verifier"]["supported"] is True and "local-python-qa" in PROFILES["verifier"]["reason"]
    assert chk.check_all(ROOT, freshness=False) == []
    assert p["pip_pins"] == [] and p["packages"] == [] and p["evidence"]["files"] == []


def test_the_bundle_profile_is_experimental_until_a_run_on_main_is_recorded_and_says_why():
    p = profile(PROFILES, "local-python-qa")
    h = host(p, "linux-x86_64")
    assert p["status"] == "experimental" and h["status"] == "experimental" and h["verified_by"] is None
    assert "no run on the main branch" in json.dumps(gen.generate(sel_qa(), CAPS, PROFILES)["warnings"]) and "recorded" in h["note"]


def sel_qa(**over):
    sel = {"engines": ["playwright", "robotframework"], "target": "local-python", "host": "linux-x86_64", "verifier": True, "channel": "experimental", "bundle_dir": "/tmp/b", "install_dir": "/tmp/i"}
    sel.update(over)
    return sel


def test_the_steps_of_the_bundle_profile_are_exactly_the_expected_ones_and_every_deviation_is_found():
    p = profile(PROFILES, "local-python-qa")
    name = chk.bundle_name(ROOT)
    assert name == "redevops-qa-bundle-0.1.0.dev0-cp312-linux-x86_64"
    assert {ph: [s["argv"] for s in steps] for ph, steps in p["steps"].items()} == chk.expected_bundle_steps(name, "python3.12")

    def change(phase, i, argv):
        return lambda q, m: q["steps"][phase][i].__setitem__("argv", argv)
    for label, fn, needle in (
        ("an extra option in the install", change("install", 0, ["x"] + p["steps"]["install"][0]["argv"][1:]), "install steps must be exactly"),
        ("another executable", change("smoke", 1, ["sh", "-c", "true"]), "smoke steps must be exactly"),
        ("a download tool", lambda q, m: q["steps"]["source"].insert(0, {"id": "fetch", "title": "t", "argv": ["curl", "https://example.invalid/x.tar"]}), "source steps must be exactly"),
        ("an environment on a step", lambda q, m: q["steps"]["check"][0].__setitem__("env", {"QA_CHROME_BINARY": "/bin/sh"}), "no environment"),
        ("a manual step", lambda q, m: q["steps"]["check"][0].__setitem__("manual", True), "no environment and no manual step"),
        ("a verify that is not run", lambda q, m: q["steps"].__setitem__("check", []), "check steps must be exactly"),
        ("a different digest check", lambda q, m: q["steps"]["source"][0]["argv"].__setitem__(3, "print(1)"), "source steps must be exactly"),
    ):
        assert needle in joined(qa_mutation(fn)), label


@pytest.mark.parametrize("label,fn,needle", [
    ("a pin of its own", lambda q, m: q["pip_pins"].append({"name": "robotframework", "version": "7.5"}), "pins nothing itself"),
    ("a package", lambda q, m: q["packages"].append("packages/qa-robot"), "pins nothing itself"),
    ("the verifier switched off", lambda q, m: q.__setitem__("verifier", False), "installs and runs the verifier"),
    ("another engine set", lambda q, m: q.__setitem__("engines", ["robotframework"]), "exactly the engines of the bundle"),
    ("another python", lambda q, m: (q["python"].__setitem__("version", "3.11"), q["python"].__setitem__("executable", "python3.11")), "the bundle is for Python 3.12"),
    ("an evidence file", lambda q, m: q["evidence"]["files"].append("x.xml"), "not JUnit files"),
    ("another parameter", lambda q, m: q["params"]["bundle_dir"].__setitem__("required", False), "the parameters must be exactly"),
    ("a macOS host that is not planned", lambda q, m: q["hosts"].append({"os_arch": "macos-x86_64", "status": "experimental", "prerequisites": ["x"], "verified_by": None, "disabled_reason": None, "note": ""}),
     "for linux-x86_64 only"),
    ("a verified status", lambda q, m: (q.__setitem__("status", "verified"), host(q, "linux-x86_64").__setitem__("status", "verified")), "not supported yet"),
    ("the verifier flag on a checkout profile", lambda q, m: profile(m, "local-python-robot").__setitem__("verifier", True), "only a bundle profile installs the verifier"),
    ("a top-level verifier claim without a profile", lambda q, m: q.__setitem__("status", "planned"), "verifier: supported must be true exactly when"),
])
def test_a_bundle_profile_that_strays_from_the_bundle_is_found(label, fn, needle):
    m = copy.deepcopy(PROFILES)
    fn(profile(m, "local-python-qa"), m)
    assert needle in joined(chk.semantic_problems(m, CAPS, ROOT)) or needle in joined(qj.validate(m, SCHEMA)), label


def test_the_ci_job_of_the_bundle_profile_runs_every_phase_from_the_bundle_job_and_every_deviation_is_found():
    base = chk.bundle_problems(profile(PROFILES, "local-python-qa"), ROOT, WORKFLOW)
    assert base == []

    def with_job(fn):
        wf = copy.deepcopy(WORKFLOW)
        fn(wf["jobs"]["profile-local-python-qa"])
        return joined(chk.bundle_problems(profile(PROFILES, "local-python-qa"), ROOT, wf))
    assert "needs: bundle" in with_job(lambda j: j.__setitem__("needs", "pins"))
    assert "no condition, no continue-on-error and no matrix" in with_job(lambda j: j.__setitem__("if", "always()"))
    assert "no condition" in with_job(lambda j: j["steps"][0].__setitem__("continue-on-error", True))
    assert "--channel experimental" in with_job(lambda j: [s.__setitem__("run", s["run"].replace("--channel experimental", "--channel stable")) for s in j["steps"] if "run" in s])
    assert "does not run the uninstall phase" in with_job(lambda j: [s.__setitem__("run", s["run"].replace("uninstall", "nothing")) for s in j["steps"] if "run" in s])
    assert "phases source,install,smoke,check" in with_job(lambda j: [s.__setitem__("run", s["run"].replace("source,install,smoke,check", "install,smoke,check")) for s in j["steps"] if "run" in s])
    assert "NOT a required check until proven" in with_job(lambda j: j.__setitem__("name", "profile"))
    assert "runs on" in with_job(lambda j: j.__setitem__("runs-on", "ubuntu-22.04"))
    assert "no job profile-local-python-qa" in joined(chk.bundle_problems(profile(PROFILES, "local-python-qa"), ROOT, {"jobs": {}}))


def test_the_generator_gives_the_bundle_profile_its_steps_and_a_manifest_that_says_a_verifier_is_enabled_and_no_commit_is_installed():
    r = gen.generate(sel_qa(), CAPS, PROFILES)
    assert r["ok"], r["errors"]
    cfg = r["config"]
    assert cfg["manifest"]["verifier"] == {"enabled": True} and cfg["manifest"]["source"] == {"repository": "redevops-io/redevops-qa", "commit": None, "kind": "bundle-archive"}
    assert cfg["manifest"]["pins"] == {"python": "3.12", "pip": []} and cfg["manifest"]["params"] == {"bundle_dir": "/tmp/b", "evidence_dir": "qa-evidence", "install_dir": "/tmp/i"}
    assert [w["code"] for w in r["warnings"]] == ["SOURCE_IS_A_BUNDLE_ARCHIVE", "EXPERIMENTAL_PROFILE", "VERIFIER_INCLUDED"]
    assert cfg["steps"]["install"][0]["argv"][:3] == ["redevops-qa-bundle-0.1.0.dev0-cp312-linux-x86_64/install.sh", "--prefix", "/tmp/i"]
    assert cfg["steps"]["smoke"][1]["argv"][-4:] == ["--out", "qa-evidence", "--run-id", "profile-demo"]
    assert gen.generate(sel_qa(verifier=False), CAPS, PROFILES)["config"]["manifest"]["verifier"] == {"enabled": True}      # the verifier is part of this profile


def test_the_generator_still_refuses_a_verifier_for_every_engine_set_that_has_no_profile_with_one_and_requires_the_parameters():
    for engines in (["robotframework"], ["selenium"], ["playwright"], ["selenium", "robotframework"]):
        r = gen.generate({"engines": engines, "target": "local-python", "host": "linux-x86_64", "verifier": True, "channel": "experimental"}, CAPS, PROFILES)
        assert ("VERIFIER_UNAVAILABLE", "verifier") in [(e["code"], e["field"]) for e in r["errors"]], engines
    missing = gen.generate(sel_qa(), CAPS, PROFILES)
    assert missing["ok"]
    r = gen.generate({k: v for k, v in sel_qa().items() if k not in ("bundle_dir", "install_dir")}, CAPS, PROFILES)
    assert [(e["code"], e["field"]) for e in r["errors"]] == [("MISSING_PARAM", "bundle_dir"), ("MISSING_PARAM", "install_dir")]
    r = gen.generate(sel_qa(venv_dir="x"), CAPS, PROFILES)
    assert [(e["code"], e["field"]) for e in r["errors"]] == [("UNEXPECTED_PARAM", "venv_dir")]
    r = gen.generate(sel_qa(channel="stable"), CAPS, PROFILES)
    assert [(e["code"], e["field"]) for e in r["errors"]] == [("NEEDS_EXPERIMENTAL_CHANNEL", "channel")]
    r = gen.generate(sel_qa(host="macos-arm64"), CAPS, PROFILES)
    assert [(e["code"], e["field"]) for e in r["errors"]] == [("HOST_NOT_SUPPORTED", "host")] and "linux x86_64 only" in r["errors"][0]["message"]


def test_the_runner_takes_only_the_parameters_the_profile_declares_and_needs_no_checkout_for_a_bundle_profile(tmp_path):
    p = profile(PROFILES, "local-python-qa")

    class A:
        host, channel, work, checkout = "linux-x86_64", "experimental", str(tmp_path), None
    sel = runner.selection_for(p, A, {"bundle_dir": "/tmp/b"})
    assert sel["verifier"] is True and set(sel) == {"engines", "target", "host", "verifier", "channel", "evidence_dir", "install_dir", "bundle_dir"}
    done = subprocess.run([sys.executable, str(ROOT / "tools" / "run_install_profile.py"), "--profile", "local-python-robot", "--host", "linux-x86_64", "--channel", "stable", "--work", str(tmp_path),
                           "--phases", "install"], capture_output=True, text=True)
    assert done.returncode == 2 and "--checkout is required" in done.stdout


def test_the_generated_page_names_the_one_profile_that_installs_the_verifier():
    text = (ROOT / "docs" / "QA_INSTALL_PROFILES.md").read_text(encoding="utf-8")
    assert "Re-verification in a separate process: offered by `local-python-qa` only." in text and "installs from a bundle archive instead" in text
    assert "Independent verifier" not in text and "not independent of the harness and the libraries" in text and "unkeyed" in text
    assert "linux-x86_64 | experimental" in text and "No bundle is published" in text


def test_the_generated_page_renders_no_empty_list_and_no_unbalanced_parenthesis():
    text = (ROOT / "docs" / "QA_INSTALL_PROFILES.md").read_text(encoding="utf-8")
    assert "pinned pip packages: ." not in text and "Files: ." not in text and "Files: ," not in text
    assert "none of its own (every wheel is pinned by hash" in text
    for line in text.splitlines():
        assert line.count("(") == line.count(")") or "```" in line or line.startswith(("#", "python", "git", "tar", "redevops", "{", "pytest")) or "`" in line, line[:120]


def test_the_page_generator_leaves_out_the_files_sentence_for_a_profile_without_evidence_files_and_keeps_it_for_the_others():
    prof = json.loads(json.dumps(PROFILES))
    text = chk.render_docs(prof)
    assert text.count("Files: `") == 3                      # robot, selenium, appium-android write JUnit files; the bundle profile does not
    q = profile(prof, "local-python-qa")
    q["pip_pins"] = [{"name": "x", "version": "1"}]
    assert "pinned pip packages: `x==1`." in chk.render_docs(prof)
