# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""qa-capabilities.json: schema, evidence resolution, agreement with the repository and with the adapters' own manifests, freshness and the generated
document. Offline. The ancestor check runs on a throwaway git repository here; on the real repository it runs in the dedicated CI job, which has the
full history."""
import copy
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_capabilities", ROOT / "tools" / "check_capabilities.py")
chk = importlib.util.module_from_spec(SPEC)
sys.modules["check_capabilities"] = chk
SPEC.loader.exec_module(chk)
qj = chk.qa_jsonschema

REAL = json.loads((ROOT / "qa-capabilities.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((ROOT / "schemas" / "qa-capabilities.schema.json").read_text(encoding="utf-8"))
WORKFLOW = yaml.safe_load((ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8"))
LEVELS = ["none", "offline-fake", "engine-backed-ci", "device-backed-local", "device-backed-ci"]


def fresh():
    return copy.deepcopy(REAL)


def entry(manifest, engine):
    return next(e for e in manifest["engines"] if e["engine"] == engine)


def ev(e, evidence_id):
    return next(x for x in e["evidence"] if x["id"] == evidence_id)


def joined(problems):
    return "\n".join(problems)


# ------------------------------------------------------------------------------------------------ the real file
def test_the_manifest_in_the_repository_passes_every_offline_check():
    assert chk.check_all(ROOT, freshness=False) == []


def test_the_schema_is_a_plain_json_schema_the_strict_validator_fully_supports():
    qj.check_schema(SCHEMA)


def test_the_closed_test_level_vocabulary():
    assert chk.LEVEL_ORDER == LEVELS
    assert SCHEMA["$defs"]["level"]["enum"] == LEVELS
    assert list(REAL["test_levels"]) == LEVELS
    assert set(SCHEMA["properties"]["test_levels"]["required"]) == set(LEVELS)


def test_the_engines_the_plan_names_are_present_and_nothing_else():
    assert [e["engine"] for e in REAL["engines"]] == ["playwright", "selenium", "robotframework", "appium-android", "appium-ios"]


def test_what_each_engine_claims_is_what_the_history_shows():
    got = {e["engine"]: (e["test_level"], [v["os_arch"] for v in e["os_arch"]]) for e in REAL["engines"]}
    assert got == {"playwright": ("engine-backed-ci", ["linux-x86_64"]),
                   "selenium": ("engine-backed-ci", ["linux-x86_64"]),
                   "robotframework": ("engine-backed-ci", ["linux-x86_64"]),
                   "appium-android": ("device-backed-local", ["macos-arm64", "linux-x86_64"]),
                   "appium-ios": ("none", [])}
    assert not [e for e in REAL["engines"] if e["test_level"] == "device-backed-ci"]


def test_ios_has_no_evidence_of_any_run_and_android_is_not_claimed_in_ci():
    ios = entry(REAL, "appium-ios")
    assert ios["test_level"] == "none" and ios["os_arch"] == [] and ios["last_verified_sha"] is None and ios["last_verified_date"] is None
    assert ios["example_id"] is None
    assert any("UNAVAILABLE" in x for x in ios["limitations"]) and any("No evidence" in x for x in ios["limitations"])
    android = entry(REAL, "appium-android")
    device_envs = [v for v in android["os_arch"] if v["test_level"].startswith("device-backed")]
    assert [v["test_level"] for v in device_envs] == ["device-backed-local"]
    local = ev(android, "ev-aa-local")
    assert local["observed_on"] == "2026-11-01" and local["runs"] == 3 and "Android 17" in local["environment"]
    assert any("never run in CI" in x for x in android["limitations"])


def test_every_engine_backed_claim_names_a_green_run_and_one_head_commit_per_run():
    jobs = [x for e in REAL["engines"] for x in e["evidence"] if x["kind"] == "ci-job"]
    assert jobs and all(j["conclusion"] == "success" for j in jobs)
    shas = {}
    for j in jobs:
        assert re.fullmatch(r"[0-9a-f]{40}", j["head_sha"]) and shas.setdefault(j["run_id"], j["head_sha"]) == j["head_sha"]
        assert j["url"] == f"https://github.com/redevops-io/redevops-qa/actions/runs/{j['run_id']}/job/{j['job_id']}"


def test_the_licence_wording_is_the_family_licence_and_never_open_source():
    text = json.dumps(REAL) + (ROOT / "docs" / "QA_CAPABILITIES.md").read_text(encoding="utf-8")
    assert not re.search(r"(?<!not )open[ -]source", text, re.IGNORECASE)
    wording = "source-available under the family licence (AGPL-3.0-or-later with the Commons Clause), not open source"
    assert REAL["distribution"]["licence_wording"] == wording
    assert all(e["license"]["adapter_wording"] == wording for e in REAL["engines"])
    assert "private" not in text.lower()
    assert REAL["distribution"]["published_packages"] is False


# ------------------------------------------------------------------------------------------------ schema rules
def schema_errors(manifest):
    return chk.schema_problems(manifest, SCHEMA)


def mutate(path, value):
    def apply(m):
        node = m
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = value
    return apply


def remove(path):
    def apply(m):
        node = m
        for step in path[:-1]:
            node = node[step]
        del node[path[-1]]
    return apply


SCHEMA_CASES = [
    ("a level outside the vocabulary", mutate(("engines", 0, "test_level"), "device-backed"), "test_level"),
    ("a level in an environment outside the vocabulary", mutate(("engines", 0, "os_arch", 0, "test_level"), "real"), "test_level"),
    ("a missing last_verified_sha", remove(("engines", 0, "last_verified_sha")), "last_verified_sha"),
    ("a short sha", mutate(("engines", 0, "last_verified_sha"), "938eb48"), "last_verified_sha"),
    ("a malformed date", mutate(("engines", 0, "last_verified_date"), "1 Nov 2026"), "last_verified_date"),
    ("a mode outside interactive and suite", mutate(("engines", 0, "execution_modes"), ["batch"]), "execution_modes"),
    ("no mode", mutate(("engines", 0, "execution_modes"), []), "execution_modes"),
    ("an unknown host", mutate(("engines", 0, "os_arch", 0, "os_arch"), "beos-x86_64"), "os_arch"),
    ("a published package", mutate(("distribution", "published_packages"), True), "published_packages"),
    ("the wrong licence wording", mutate(("engines", 0, "license", "adapter_wording"), "open source"), "adapter_wording"),
    ("a ci evidence item without a run url", remove(("engines", 0, "evidence", 0, "run_url")), "run_url"),
    ("a ci evidence item whose whole run is not green", mutate(("engines", 0, "evidence", 0, "run_conclusion"), "failure"), "run_conclusion"),
    ("a ci evidence item that does not say the run is green", remove(("engines", 0, "evidence", 0, "run_conclusion")), "run_conclusion"),
    ("an absolute docs path", mutate(("engines", 0, "docs_url"), "/etc/passwd"), "docs_url"),
    ("a docs path that climbs out", mutate(("engines", 0, "docs_url"), "../x.md"), "docs_url"),
    ("a url docs path", mutate(("engines", 0, "docs_url"), "https://example.com/x"), "docs_url"),
    ("an extra property on an entry", mutate(("engines", 0, "confidence"), "high"), "confidence"),
    ("an unpinned dependency without a note", mutate(("engines", 0, "dependencies", 3, "note"), ""), "note"),
    ("a pinned dependency without a literal", mutate(("engines", 0, "dependencies", 2, "pin_literal"), None), "pin_literal"),
    ("a ci evidence item without a job id", remove(("engines", 0, "evidence", 0, "job_id")), "job_id"),
    ("a ci evidence item that is not green", mutate(("engines", 0, "evidence", 0, "conclusion"), "failure"), "conclusion"),
    ("a local run without the commit that records it", remove(("engines", 3, "evidence", 0, "recorded_in_sha")), "recorded_in_sha"),
    ("a verified level without any host", mutate(("engines", 0, "os_arch"), []), "os_arch"),
    ("level none with a sha", mutate(("engines", 4, "last_verified_sha"), "938eb486b508b7a7ca7be55661a3f937d1de4bea"), "last_verified_sha"),
    ("level none with a host", mutate(("engines", 4, "os_arch"), copy.deepcopy(REAL["engines"][2]["os_arch"])), "os_arch"),
    ("an install method that is a published package", mutate(("engines", 0, "install_method", "published_to_registry"), True), "published_to_registry"),
]


@pytest.mark.parametrize("label,apply,needle", SCHEMA_CASES, ids=[c[0] for c in SCHEMA_CASES])
def test_the_schema_refuses(label, apply, needle):
    m = fresh()
    apply(m)
    found = schema_errors(m)
    assert found and needle in joined(found), (label, found)


# ------------------------------------------------------------------------------------------------ semantic rules (each is a rule that can be disabled)
def semantic(manifest):
    assert schema_errors(manifest) == [], schema_errors(manifest)
    return chk.semantic_problems(manifest, ROOT)


def set_dep_literal(e, name, literal):
    next(d for d in e["dependencies"] if d["name"] == name)["pin_literal"] = literal


def case_pin_not_in_source(m):
    set_dep_literal(entry(m, "playwright"), "playwright", "playwright==1.0.0")


def case_exact_pin_literal_mismatch(m):
    d = next(d for d in entry(m, "selenium")["dependencies"] if d["name"] == "selenium")
    d["pin"] = "4.52.0"
    d["pin_literal"] = "selenium==4.52.0 "


def case_missing_pin_source(m):
    next(d for d in entry(m, "robotframework")["dependencies"] if d["name"] == "robotframework")["pin_source"] = "packages/qa-robot/nope.toml"


def case_extra_not_declared(m):
    entry(m, "robotframework")["install_method"]["extras"] = ["chrome"]


def case_package_without_pyproject(m):
    entry(m, "robotframework")["install_method"]["packages"] = ["packages/qa-nothing"]


def case_evidence_path_missing(m):
    ev(entry(m, "playwright"), "ev-pw-tests")["path"] = "packages/qa-playwright/tests/none"


def case_local_run_date_not_in_document(m):
    ev(entry(m, "appium-android"), "ev-aa-local")["observed_on"] = "2026-12-24"
    entry(m, "appium-android")["last_verified_date"] = "2026-12-24"


def case_unknown_job(m):
    ev(entry(m, "robotframework"), "ev-rb-real-lane")["job_key"] = "robot-imaginary"


def case_job_name_differs(m):
    ev(entry(m, "robotframework"), "ev-rb-real-lane")["job_name"] = "robot gold lane"


def case_url_differs(m):
    ev(entry(m, "robotframework"), "ev-rb-real-lane")["url"] = "https://github.com/redevops-io/redevops-qa/actions/runs/1/job/2"


def case_run_url_differs(m):
    ev(entry(m, "robotframework"), "ev-rb-real-lane")["run_url"] = "https://github.com/redevops-io/redevops-qa/actions/runs/1"


def case_two_head_commits_for_one_run(m):
    ev(entry(m, "robotframework"), "ev-rb-offline")["head_sha"] = "a" * 40


def case_job_cited_twice(m):
    ev(entry(m, "robotframework"), "ev-rb-offline")["job_id"] = ev(entry(m, "robotframework"), "ev-rb-real-lane")["job_id"]
    ev(entry(m, "robotframework"), "ev-rb-offline")["url"] = ev(entry(m, "robotframework"), "ev-rb-real-lane")["url"]


def case_engine_backed_by_offline_job_only(m):
    e = entry(m, "robotframework")
    e["os_arch"][0]["evidence"] = ["ev-rb-offline"]


def case_engine_backed_with_no_ci_job(m):
    e = entry(m, "robotframework")
    e["os_arch"][0]["evidence"] = ["ev-rb-offline"]
    e["os_arch"][0]["test_level"] = "engine-backed-ci"
    e["evidence"] = [x for x in e["evidence"] if x["id"] != "ev-rb-real-lane"]
    e["evidence"].append({"id": "ev-rb-real-lane", "kind": "repo-path", "path": "packages/qa-robot/README.md", "claim": "a document"})
    e["os_arch"][0]["evidence"] = ["ev-rb-real-lane"]


def case_device_level_without_local_run(m):
    e = entry(m, "appium-android")
    e["os_arch"][0]["evidence"] = ["ev-aa-manual-workflow"]


def case_device_ci_without_device_workflow(m):
    e = entry(m, "appium-android")
    e["os_arch"][0]["test_level"] = "device-backed-ci"
    e["test_level"] = "device-backed-ci"


def case_offline_level_without_ci(m):
    e = entry(m, "appium-android")
    e["os_arch"][1]["test_level"] = "offline-fake"
    e["os_arch"][1]["evidence"] = ["ev-aa-manual-workflow"]


def case_entry_level_weaker_than_environment(m):
    entry(m, "appium-android")["test_level"] = "engine-backed-ci"


def case_entry_level_stronger_than_environment(m):
    entry(m, "playwright")["test_level"] = "device-backed-local"


def case_environment_references_unknown_evidence(m):
    entry(m, "playwright")["os_arch"][0]["evidence"] = ["ev-pw-ghost"]


def case_sha_differs_from_backing_evidence(m):
    entry(m, "robotframework")["last_verified_sha"] = "b" * 40


def case_date_differs_from_backing_evidence(m):
    entry(m, "robotframework")["last_verified_date"] = "2026-10-01"


def case_basis_wrong(m):
    entry(m, "robotframework")["last_verified_sha_basis"] = "documented-in"


def case_local_sha_differs(m):
    entry(m, "appium-android")["last_verified_sha"] = "c" * 40


def case_licence_spdx_differs(m):
    entry(m, "selenium")["license"]["components"][0]["spdx"] = "MIT"


def case_licence_redistribution_differs(m):
    entry(m, "robotframework")["license"]["components"][0]["redistribution"] = "redistributable"


def case_licence_component_unknown(m):
    entry(m, "robotframework")["license"]["components"][0]["matrix_component"] = "robotframework-gold"


def case_runtime_differs_from_matrix(m):
    entry(m, "robotframework")["runtime_version"] = "7.4"


def case_docs_missing(m):
    entry(m, "robotframework")["docs_url"] = "packages/qa-robot/NOPE.md"


def case_example_unknown(m):
    entry(m, "robotframework")["example_id"] = "robot-gold"


def case_example_path_missing(m):
    m["examples"]["robotframework-real-lane"]["path"] = "packages/qa-robot/tests/real/nope.py"


def case_duplicate_engine(m):
    m["engines"].append(copy.deepcopy(entry(m, "robotframework")))


def case_adapter_listed_twice(m):
    entry(m, "robotframework")["adapter_ids"] = ["robot-suite", "selenium-suite"]


def case_open_source_wording(m):
    entry(m, "robotframework")["summary"] = "An open source integration."


def case_duplicate_evidence_id(m):
    e = entry(m, "robotframework")
    e["evidence"].append(copy.deepcopy(e["evidence"][0]))


SEMANTIC_CASES = [
    (case_pin_not_in_source, "is not in packages/qa-playwright/pyproject.toml"),
    (case_exact_pin_literal_mismatch, "an exact pip pin must read"),
    (case_missing_pin_source, "does not exist"),
    (case_extra_not_declared, "declared by none of the install packages"),
    (case_package_without_pyproject, "has no pyproject.toml"),
    (case_evidence_path_missing, "does not exist"),
    (case_local_run_date_not_in_document, "does not mention the day it was observed"),
    (case_unknown_job, "has no job"),
    (case_job_name_differs, "is not named"),
    (case_url_differs, "url must be"),
    (case_run_url_differs, "run_url must be"),
    (case_two_head_commits_for_one_run, "two different head commits"),
    (case_job_cited_twice, "cited twice"),
    (case_engine_backed_by_offline_job_only, "engine-backed-ci needs a CI job that installs the pinned engine"),
    (case_engine_backed_with_no_ci_job, "engine-backed-ci needs a CI job that installs the pinned engine"),
    (case_device_level_without_local_run, "device-backed-local needs a recorded local run"),
    (case_device_ci_without_device_workflow, "device-backed-ci needs a run of the device workflow"),
    (case_offline_level_without_ci, "offline-fake needs a CI job"),
    (case_entry_level_weaker_than_environment, "but the strongest verified environment is device-backed-local"),
    (case_entry_level_stronger_than_environment, "but the strongest verified environment is engine-backed-ci"),
    (case_environment_references_unknown_evidence, "is not defined in this entry"),
    (case_sha_differs_from_backing_evidence, "last_verified_sha/date must be"),
    (case_date_differs_from_backing_evidence, "last_verified_sha/date must be"),
    (case_basis_wrong, "last_verified_sha/date must be"),
    (case_local_sha_differs, "last_verified_sha/date must be"),
    (case_licence_spdx_differs, "but the matrix says"),
    (case_licence_redistribution_differs, "but the matrix says"),
    (case_licence_component_unknown, "is not in the licence matrix"),
    (case_runtime_differs_from_matrix, "but the matrix pins"),
    (case_docs_missing, "docs_url"),
    (case_example_unknown, "is not in examples"),
    (case_example_path_missing, "does not exist"),
    (case_duplicate_engine, "duplicate engine id"),
    (case_adapter_listed_twice, "listed by two engines"),
    (case_open_source_wording, "never 'open source'"),
    (case_duplicate_evidence_id, "duplicate evidence id"),
]


@pytest.mark.parametrize("apply,needle", SEMANTIC_CASES, ids=[c[0].__name__ for c in SEMANTIC_CASES])
def test_the_semantic_check_refuses(apply, needle):
    m = fresh()
    apply(m)
    found = semantic(m)
    assert needle in joined(found), found


def test_every_evidence_reference_resolves_to_the_repository_or_a_ci_run_id_pattern():
    for e in REAL["engines"]:
        for x in e["evidence"]:
            if x["kind"] in ("repo-path", "local-run"):
                assert (ROOT / x["path"]).exists(), x["id"]
            else:
                assert isinstance(x["run_id"], int) and isinstance(x["job_id"], int)
                assert re.fullmatch(r"https://github\.com/redevops-io/redevops-qa/actions/runs/\d+/job/\d+", x["url"])
                assert x["url"].startswith(x["run_url"] + "/job/")
                job = chk._workflow_jobs(ROOT, x["workflow"])[x["job_key"]]
                assert job["name"].startswith(x["job_name"])
        for v in e["os_arch"]:
            assert set(v["evidence"]) <= {x["id"] for x in e["evidence"]}


def test_every_cited_real_engine_job_installs_the_pinned_engine_and_fails_instead_of_skipping():
    for e in REAL["engines"]:
        for v in e["os_arch"]:
            if v["test_level"] != "engine-backed-ci":
                continue
            for x in (ev(e, i) for i in v["evidence"]):
                if x["kind"] != "ci-job" or x["job_key"] in ("selenium-offline", "robot-offline", "appium-offline"):
                    continue
                text = chk._job_text(WORKFLOW["jobs"][x["job_key"]])
                assert "tools/check_junit.py" in text, "the job must fail on zero tests or any skip"
                assert any(d["pin_literal"] in text for d in e["dependencies"] if d["kind"] in ("pip", "npm", "driver") and d["pin_literal"]), x["id"]


# ------------------------------------------------------------------------------------------------ the adapters' own manifests
def test_the_code_declares_exactly_the_adapters_the_manifest_lists():
    code = chk.code_manifests(ROOT)
    assert set(code) == {a for e in REAL["engines"] for a in e["adapter_ids"]}
    assert code["appium-ios-interactive"]["mode"] == "interactive" and code["selenium-suite"]["mode"] == "suite" and code["robot-suite"]["mode"] == "suite"
    assert code["qa-playwright"] == {"adapter_version": "0.1.0.dev0", "mode": "interactive", "engine_version": "1.64.1", "engine_name": "playwright"}


@pytest.mark.parametrize("label,apply,needle", [
    ("an adapter version", lambda m: entry(m, "selenium").__setitem__("adapter_version", "0.2.0"), "is version 0.1.0 in code"),
    ("an engine version", lambda m: entry(m, "selenium").__setitem__("runtime_version", "4.53.0"), "pins engine version 4.52.0 in code"),
    ("a mode added", lambda m: entry(m, "robotframework").__setitem__("execution_modes", ["suite", "interactive"]), "execution modes are"),
    ("a mode dropped", lambda m: entry(m, "selenium").__setitem__("execution_modes", ["interactive"]), "execution modes are"),
    ("an adapter id the code does not declare", lambda m: entry(m, "robotframework").__setitem__("adapter_ids", ["robot-suite", "robot-ghost"]), "is not declared in code"),
    ("an adapter missing from every entry", lambda m: entry(m, "selenium").__setitem__("adapter_ids", ["selenium-suite"]), "is in no manifest entry"),
    ("the playwright adapter version", lambda m: entry(m, "playwright").__setitem__("adapter_version", "0.1.0"), "is version 0.1.0.dev0 in code"),
    ("the android engine version", lambda m: entry(m, "appium-android").__setitem__("runtime_version", "3.8.0"), "pins engine version 3.9.0 in code"),
    ("the ios mode", lambda m: entry(m, "appium-ios").__setitem__("execution_modes", ["suite"]), "execution modes are"),
])
def test_the_manifest_and_the_code_must_agree(label, apply, needle):
    m = fresh()
    apply(m)
    assert needle in joined(chk.code_agreement_problems(m, ROOT)), label


def test_the_real_manifest_agrees_with_the_code():
    assert chk.code_agreement_problems(REAL, ROOT) == []


# ------------------------------------------------------------------------------------------------ the generated document
def test_the_checked_in_document_equals_the_generated_one():
    assert (ROOT / "docs" / "QA_CAPABILITIES.md").read_text(encoding="utf-8") == chk.render_docs(REAL)


def test_generation_is_deterministic_and_independent_of_key_order():
    shuffled = json.loads(json.dumps(REAL), object_pairs_hook=lambda pairs: dict(reversed(pairs)))
    assert chk.render_docs(REAL) == chk.render_docs(copy.deepcopy(REAL)) == chk.render_docs(shuffled)


def test_the_document_explains_every_level_and_carries_the_appium_and_ios_caveats():
    text = chk.render_docs(REAL)
    for level, meaning in REAL["test_levels"].items():
        assert f"`{level}`" in text and meaning["meaning"] in text and meaning["does_not_mean"] in text
    for group in REAL["caveats"].values():
        for line in group:
            assert line in text
    assert "Linux containers are not a complete iOS solution." in text and "Never imply that a device or emulator is bundled" in text
    assert text.startswith(chk.GENERATED_NOTICE) and "timestamp" not in text.lower()


def test_a_hand_edit_or_a_stale_document_is_found(tmp_path):
    root = tmp_path
    (root / "docs").mkdir()
    doc = chk.render_docs(REAL)
    (root / "docs" / "QA_CAPABILITIES.md").write_text(doc, encoding="utf-8")
    assert chk.docs_problems(REAL, root) == []
    (root / "docs" / "QA_CAPABILITIES.md").write_text(doc.replace("engine-backed-ci", "device-backed-ci", 1), encoding="utf-8")
    assert "differs from the document generated" in joined(chk.docs_problems(REAL, root))
    (root / "docs" / "QA_CAPABILITIES.md").unlink()
    assert "is missing" in joined(chk.docs_problems(REAL, root))
    changed = fresh()
    entry(changed, "robotframework")["summary"] = "Changed."
    (root / "docs" / "QA_CAPABILITIES.md").write_text(doc, encoding="utf-8")
    assert chk.docs_problems(changed, root)


def test_table_cells_cannot_break_the_table():
    assert chk._cell("a|b\nc") == "a\\|b c"


# ------------------------------------------------------------------------------------------------ freshness (throwaway repository)
def git(cwd, *args):
    out = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-C", str(cwd), *args],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


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
    off_main = git(tmp_path, "rev-parse", "HEAD")
    git(tmp_path, "checkout", "-q", "main")
    return tmp_path, on_main, off_main


def tiny(sha, evidence_sha=None):
    ev_items = [{"id": "ev-x", "head_sha": evidence_sha}] if evidence_sha else []
    return {"main_branch": "main", "engines": [{"engine": "x", "last_verified_sha": sha, "evidence": ev_items}]}


def test_a_sha_on_main_is_fresh_and_a_null_sha_is_ignored(repo):
    root, on_main, _ = repo
    assert chk.freshness_problems(tiny(on_main), root) == []
    assert chk.freshness_problems(tiny(None), root) == []


def test_a_sha_that_is_not_an_ancestor_of_main_fails(repo):
    root, _, off_main = repo
    assert "is not an ancestor of main" in joined(chk.freshness_problems(tiny(off_main), root))


def test_an_unknown_sha_fails(repo):
    root, _, _ = repo
    assert "is not a commit of this repository" in joined(chk.freshness_problems(tiny("d" * 40), root))


def test_a_stale_evidence_commit_fails_even_when_the_entry_sha_is_fresh(repo):
    root, on_main, off_main = repo
    assert "evidence ev-x head_sha" in joined(chk.freshness_problems(tiny(on_main, off_main), root))


def test_no_main_ref_is_a_finding_not_a_skip(tmp_path):
    git(tmp_path, "init", "-q", "-b", "other")
    (tmp_path / "f").write_text("1")
    git(tmp_path, "add", "f")
    git(tmp_path, "commit", "-q", "-m", "one")
    sha = git(tmp_path, "rev-parse", "HEAD")
    assert "cannot resolve the main branch" in joined(chk.freshness_problems(tiny(sha), tmp_path))
    assert chk.freshness_problems(tiny(sha), tmp_path, main_ref="other") == []


def test_origin_main_is_preferred_when_it_exists(repo):
    root, on_main, off_main = repo
    git(root, "update-ref", "refs/remotes/origin/main", off_main)
    assert chk.resolve_main_ref(root, None, "main") == "origin/main"
    assert chk.freshness_problems(tiny(off_main), root) == []
    assert chk.freshness_problems(tiny(on_main), root) == []         # an ancestor of origin/main too


def test_the_real_manifest_names_commits_that_exist_in_a_full_clone_only_and_never_a_branch():
    shas = {e["last_verified_sha"] for e in REAL["engines"] if e["last_verified_sha"]}
    shas |= {x[k] for e in REAL["engines"] for x in e["evidence"] for k in ("head_sha", "recorded_in_sha") if k in x}
    assert shas and all(re.fullmatch(r"[0-9a-f]{40}", s) for s in shas)


# ------------------------------------------------------------------------------------------------ re-checking the CI evidence (network, opt in)
class FakeApi:
    def __init__(self, manifest, **override):
        self.runs, self.jobs = {}, {}
        for e in list(manifest["engines"]) + list(manifest.get("product_capabilities", [])):
            for x in e["evidence"]:
                if x["kind"] == "ci-job":
                    self.runs[x["run_id"]] = {"head_sha": x["head_sha"], "conclusion": x["run_conclusion"]}
                    if not any(j["id"] == x["job_id"] for j in self.jobs.get(x["run_id"], [])):
                        self.jobs.setdefault(x["run_id"], []).append({"id": x["job_id"], "name": x["job_name"] + " (full name)", "conclusion": "success",
                                                                      "completed_at": x["completed_on"] + "T01:00:00Z"})
        self.override = override

    def __call__(self, url):
        m = re.search(r"/runs/(\d+)(/jobs)?", url)
        run_id = int(m.group(1))
        if self.override.get("error"):
            raise OSError("down")
        if m.group(2):
            return {"jobs": self.override.get("jobs", self.jobs)[run_id] if isinstance(self.override.get("jobs"), dict) else self.jobs[run_id]}
        return self.override.get("run", self.runs[run_id])


def test_re_checking_the_ci_evidence_passes_for_the_recorded_runs():
    assert chk.verify_ci_problems(REAL, FakeApi(REAL)) == []


def test_re_checking_finds_a_different_head_a_failed_job_a_missing_job_and_an_api_error():
    api = FakeApi(REAL)
    run_id = REAL["engines"][0]["evidence"][0]["run_id"]
    assert "head is" in joined(chk.verify_ci_problems(REAL, FakeApi(REAL, run={"head_sha": "e" * 40, "conclusion": "success"})))
    red = FakeApi(REAL)
    for run in red.runs.values():
        run["conclusion"] = "failure"
    assert "as a whole concluded failure" in joined(chk.verify_ci_problems(REAL, red))
    api.jobs[run_id][0]["conclusion"] = "failure"
    assert "concluded failure" in joined(chk.verify_ci_problems(REAL, api))
    api = FakeApi(REAL)
    api.jobs[run_id][0]["id"] = 1
    assert "has no job" in joined(chk.verify_ci_problems(REAL, api))
    api = FakeApi(REAL)
    api.jobs[run_id][0]["name"] = "something else"
    assert "is named" in joined(chk.verify_ci_problems(REAL, api))
    api = FakeApi(REAL)
    api.jobs[run_id][0]["completed_at"] = "2025-01-01T00:00:00Z"
    assert "completed on" in joined(chk.verify_ci_problems(REAL, api))
    assert "cannot read run" in joined(chk.verify_ci_problems(REAL, FakeApi(REAL, error=True)))


# ------------------------------------------------------------------------------------------------ the CI job
def test_the_capabilities_job_cannot_be_skipped_and_checks_everything():
    job = WORKFLOW["jobs"]["capabilities"]
    steps = job["steps"]
    run = "\n".join(str(s.get("run", "")) for s in steps)
    assert not {"if", "needs", "continue-on-error", "strategy"} & set(job)
    assert not [s for s in steps if "if" in s or "continue-on-error" in s]
    triggers = WORKFLOW.get(True) or WORKFLOW.get("on")
    assert all(not ({"paths", "paths-ignore"} & set(triggers.get(name) or {})) for name in ("push", "pull_request"))
    checkout = steps[0]
    assert checkout["uses"].startswith("actions/checkout@") and checkout["with"]["fetch-depth"] == 0 and checkout["with"]["persist-credentials"] is False
    assert "tools/check_capabilities.py" in run and "--cross-check" in run
    assert "tests/test_capabilities.py" in run and "tests/test_qa_jsonschema.py" in run and "tools/check_junit.py" in run and "env -i HOME=" in run
    assert "--no-freshness" not in run
    assert "jsonschema==" in run
    assert "NOT a required check" not in job["name"]


def test_the_cross_check_reports_a_disagreement_with_the_full_validator(monkeypatch):
    import types

    class Disagreeing:
        class Draft202012Validator:
            @staticmethod
            def check_schema(schema):
                pass

            def __init__(self, schema):
                pass

            def is_valid(self, doc):
                return False          # says invalid for everything, the strict validator says valid for the manifest
    monkeypatch.setitem(sys.modules, "jsonschema", types.SimpleNamespace(Draft202012Validator=Disagreeing.Draft202012Validator))
    assert "the strict validator says valid, jsonschema says invalid" in joined(chk.cross_check_problems(SCHEMA, REAL))


def test_the_cross_check_agrees_with_a_validator_that_behaves_the_same(monkeypatch):
    import types

    class Same:
        @staticmethod
        def check_schema(schema):
            pass

        def __init__(self, schema):
            self.schema = schema

        def is_valid(self, doc):
            return not qj.validate(doc, self.schema)
    monkeypatch.setitem(sys.modules, "jsonschema", types.SimpleNamespace(Draft202012Validator=Same))
    assert chk.cross_check_problems(SCHEMA, REAL) == []


def test_the_manifest_is_linked_from_the_readme():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "qa-capabilities.json" in readme and "docs/QA_CAPABILITIES.md" in readme


# ------------------------------------------------------------------------------------------------ product capabilities (features of the redevops-qa command)
def row(m, rid):
    return next(r for r in m["product_capabilities"] if r["id"] == rid)


def sem(m):
    assert qj.validate(m, SCHEMA) == []
    return chk.semantic_problems(m, ROOT)


def test_the_two_product_rows_are_backed_by_ci_jobs_of_the_main_branch_and_pass_every_check():
    assert [r["id"] for r in REAL["product_capabilities"]] == ["qa-runner-two-lane-run", "qa-verify-recompute"]
    assert sem(REAL) == []
    for r in REAL["product_capabilities"]:
        assert r["test_level"] == "engine-backed-ci" and any(e["kind"] == "ci-job" for e in r["evidence"])


def test_the_product_rows_say_what_they_do_not_show():
    text = json.dumps(REAL["product_capabilities"])
    assert "fixture app" in text and "not an independent implementation" in text and "unkeyed" in text and "does not show that the application under test is correct" in text
    assert not re.search(r"(?<!not )open[ -]source|tamper-proof|soc 2", text, re.IGNORECASE)


@pytest.mark.parametrize("label,fn,needle", [
    ("an unknown job key", lambda m: row(m, "qa-runner-two-lane-run")["evidence"][0].__setitem__("job_key", "no-such-job"), "has no job"),
    ("a job named differently", lambda m: row(m, "qa-runner-two-lane-run")["evidence"][0].__setitem__("job_name", "something else"), "is not named"),
    ("a url that does not match the ids", lambda m: row(m, "qa-runner-two-lane-run")["evidence"][0].__setitem__("job_id", 5), "run_url and url must be built"),
    ("a repo path that does not exist", lambda m: row(m, "qa-runner-two-lane-run")["evidence"][1].__setitem__("path", "packages/nothing"), "does not exist"),
    ("a docs path that does not exist", lambda m: row(m, "qa-runner-two-lane-run").__setitem__("docs_url", "docs/NOTHING.md"), "docs_url"),
    ("a local run as evidence", lambda m: row(m, "qa-runner-two-lane-run")["evidence"].__setitem__(1, {"id": "ev-x", "kind": "local-run", "claim": "c"}), "not by a local run"),
    ("a device level", lambda m: row(m, "qa-runner-two-lane-run").__setitem__("test_level", "device-backed-ci"), "cannot be at a device level"),
    ("a level without a CI job", lambda m: row(m, "qa-runner-two-lane-run").__setitem__("evidence", [row(m, "qa-runner-two-lane-run")["evidence"][1]]), "needs a CI job"),
    ("engine-backed without the engines", lambda m: row(m, "qa-verify-recompute").__setitem__("evidence", [e for e in row(m, "qa-verify-recompute")["evidence"]
                                                                                                    if e["kind"] != "ci-job" or e["job_key"] == "runner"]),
     "installs the pinned Playwright and Robot Framework"),
    ("a duplicate id", lambda m: m["product_capabilities"].append(copy.deepcopy(row(m, "qa-verify-recompute"))), "duplicate id"),
    ("a job cited twice in one row", lambda m: row(m, "qa-verify-recompute")["evidence"].insert(0, copy.deepcopy(row(m, "qa-verify-recompute")["evidence"][0]) | {"id": "ev-again"}), "cited twice"),
])
def test_a_product_row_that_strays_from_its_evidence_is_found(label, fn, needle):
    m = fresh()
    fn(m)
    found = joined(chk.semantic_problems(m, ROOT)) + joined(qj.validate(m, SCHEMA))
    assert needle in found, (label, found)


def test_a_product_row_cites_commits_that_must_be_on_main(tmp_path):
    m = fresh()
    row(m, "qa-runner-two-lane-run")["evidence"][0]["head_sha"] = "e" * 40
    assert "is not a commit of this repository" in joined(chk.freshness_problems(m, ROOT, "HEAD"))


def test_re_checking_product_rows_against_the_api_finds_a_different_head():
    assert "head is" in joined(chk.verify_ci_problems(REAL, FakeApi(REAL, run={"head_sha": "e" * 40, "conclusion": "success"})))


def test_the_generated_page_has_the_product_section_with_its_caveats():
    text = (ROOT / "docs" / "QA_CAPABILITIES.md").read_text(encoding="utf-8")
    assert "## Product capabilities (the `redevops-qa` command)" in text and "not an independent implementation" in text
    assert "get their rows once a run on the main branch exists" in text
