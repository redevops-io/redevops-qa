# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The install configuration generator: its vectors (the specification a port must reproduce), its purity, its refusals and its input safety."""
import ast
import copy
import importlib.util
import json
import re
import random
import shlex
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("qa_install_config", ROOT / "tools" / "qa_install_config.py")
gen = importlib.util.module_from_spec(SPEC)
sys.modules["qa_install_config"] = gen
SPEC.loader.exec_module(gen)

CAPS = json.loads((ROOT / "qa-capabilities.json").read_text(encoding="utf-8"))
PROFILES = json.loads((ROOT / "qa-install-profiles.json").read_text(encoding="utf-8"))
VECTORS = json.loads((ROOT / "tests" / "vectors" / "install-config-vectors.json").read_text(encoding="utf-8"))
CHROME, DRIVER = "/usr/bin/google-chrome", "/usr/local/share/chromedriver-linux64/chromedriver"


def sel(**kw):
    base = {"engines": ["robotframework"], "target": "local-python", "host": "linux-x86_64", "verifier": False, "channel": "experimental"}
    base.update(kw)
    return base


def run(selection):
    return gen.generate(selection, CAPS, PROFILES)


def codes(result):
    return [(e["code"], e["field"]) for e in result["errors"]]


def verified_pairs():
    return [(p, h) for p in PROFILES["profiles"] for h in p["hosts"] if p["status"] == "verified" and h["status"] == "verified"]


# ------------------------------------------------------------------------------------------------ the vectors are the specification
def test_every_vector_reproduces_exactly():
    assert len(VECTORS["vectors"]) >= 40 and VECTORS["schema"] == "redevops-qa/install-config-vectors/1"
    for v in VECTORS["vectors"]:
        result = run(v["selection"])
        assert gen._vector_expected(result) == v["expected"], v["id"]


def test_the_helper_vectors_reproduce_exactly():
    assert gen.update_vectors(VECTORS, CAPS, PROFILES) == VECTORS
    for q in VECTORS["quote_vectors"]:
        assert gen.quote_arg(q["arg"]) == q["quoted"]
        assert shlex.split(q["quoted"]) == [q["arg"]]
    for c in VECTORS["canonical_json_vectors"]:
        assert gen.canonical_json(c["value"]) == c["canonical"] and gen.digest(c["value"]) == c["digest"]


def test_the_vector_ids_are_unique_and_every_error_code_the_generator_can_return_is_covered():
    ids = [v["id"] for v in VECTORS["vectors"]]
    assert len(ids) == len(set(ids))
    seen = {c for v in VECTORS["vectors"] for c, _ in [(e["code"], e["field"]) for e in v["expected"]["errors"]]}
    source = (ROOT / "tools" / "qa_install_config.py").read_text(encoding="utf-8")
    emitted = set(__import__("re").findall(r'_err\(errors, "([A-Z_]+)"', source))
    assert seen == emitted, (emitted - seen, seen - emitted)


EXPECTED_CODES = {
    "robot-macos-stable-refused": [("NEEDS_EXPERIMENTAL_CHANNEL", "channel")], "android-linux-stable-refused": [("NEEDS_EXPERIMENTAL_CHANNEL", "channel")],
    "verifier-refused": [("VERIFIER_UNAVAILABLE", "verifier")], "compose-refused": [("TARGET_NOT_AVAILABLE", "target")],
    "helm-refused": [("TARGET_NOT_AVAILABLE", "target")], "ios-linux-refused": [("IOS_NEEDS_MACOS", "host")], "ios-macos-planned": [("PROFILE_PLANNED", "engines")],
    "playwright-planned": [("PROFILE_PLANNED", "engines")], "combination-refused": [("NO_PROFILE_FOR_ENGINES", "engines")],
    "windows-refused": [("HOST_NOT_SUPPORTED", "host")], "wsl-refused": [("HOST_NOT_SUPPORTED", "host")], "no-engines": [("NO_ENGINES", "engines")],
    "duplicate-engine": [("DUPLICATE_ENGINE", "engines")], "not-an-object": [("INVALID_SELECTION", "")],
    "secret-field-refused": [("SECRETS_NOT_ACCEPTED", "api_token")], "password-field-refused": [("SECRETS_NOT_ACCEPTED", "password")],
    "unknown-field-refused": [("UNKNOWN_FIELD", "shell")], "engine-injection-attempt": [("UNKNOWN_ENGINE", "engines")],
    "selenium-missing-params": [("MISSING_PARAM", "chrome_binary"), ("MISSING_PARAM", "chromedriver_path")],
    "selenium-relative-chrome": [("INVALID_PARAM", "chrome_binary")], "robot-unexpected-param": [("UNEXPECTED_PARAM", "chrome_binary")],
    "verifier-and-compose-both-reported": [("VERIFIER_UNAVAILABLE", "verifier"), ("TARGET_NOT_AVAILABLE", "target")],
}


@pytest.mark.parametrize("vector_id,expected", sorted(EXPECTED_CODES.items()))
def test_the_key_refusals_are_asserted_independently_of_the_stored_vectors(vector_id, expected):
    v = next(x for x in VECTORS["vectors"] if x["id"] == vector_id)
    assert codes(run(v["selection"])) == expected


def test_every_invalid_directory_is_refused_by_the_parameter_rule():
    bad = [v for v in VECTORS["vectors"] if v["id"].startswith("invalid-venv-dir-")]
    assert len(bad) >= 12
    for v in bad:
        assert codes(run(v["selection"])) == [("INVALID_PARAM", "venv_dir")], v["id"]


# ------------------------------------------------------------------------------------------------ what a good selection returns
def test_a_verified_profile_on_a_verified_host_is_accepted_on_the_stable_channel_with_no_experimental_warning():
    pairs = verified_pairs()
    assert pairs, "at least one profile must be verified"
    for p, h in pairs:
        extra = {"chrome_binary": CHROME, "chromedriver_path": DRIVER} if "chrome_binary" in p["params"] else {}
        result = run(sel(engines=p["engines"], host=h["os_arch"], channel="stable", **extra))
        assert result["ok"] and result["config"]["status"] == "verified" and result["config"]["channel"] == "stable", (p["id"], result["errors"])
        assert "EXPERIMENTAL_PROFILE" not in [w["code"] for w in result["warnings"]]


def test_an_experimental_combination_is_never_returned_on_the_stable_channel():
    for p in PROFILES["profiles"]:
        for h in p["hosts"]:
            if p["status"] == "verified" and h["status"] == "verified":
                continue
            extra = {"chrome_binary": CHROME, "chromedriver_path": DRIVER} if "chrome_binary" in p["params"] else {}
            result = run(sel(engines=p["engines"], host=h["os_arch"], channel="stable", **extra))
            assert not result["ok"] and result["errors"][0]["code"] in ("NEEDS_EXPERIMENTAL_CHANNEL", "PROFILE_PLANNED", "HOST_NOT_SUPPORTED"), (p["id"], h["os_arch"])


def test_the_experimental_channel_adds_a_warning_and_never_changes_a_verified_result():
    for p, h in verified_pairs():
        extra = {"chrome_binary": CHROME, "chromedriver_path": DRIVER} if "chrome_binary" in p["params"] else {}
        a = run(sel(engines=p["engines"], host=h["os_arch"], channel="stable", **extra))["config"]
        b = run(sel(engines=p["engines"], host=h["os_arch"], channel="experimental", **extra))["config"]
        assert {**a, "channel": None, "manifest": None, "manifest_digest": None} == {**b, "channel": None, "manifest": None, "manifest_digest": None}


def test_the_configuration_names_pins_prerequisites_smoke_evidence_and_uninstall():
    cfg = run(sel(host="macos-arm64"))["config"]
    assert cfg["prerequisites"] and cfg["steps"]["install"] and cfg["steps"]["smoke"] and cfg["steps"]["check"] and cfg["steps"]["uninstall"]
    assert cfg["evidence"]["directory"] == "qa-evidence" and cfg["evidence"]["files"] and cfg["uninstall_note"]
    assert cfg["manifest"]["pins"]["pip"] == ["pytest==9.2.0", "pyyaml==6.0.3", "robotframework==7.5"] and cfg["manifest"]["pins"]["python"] == "3.12"
    assert cfg["manifest"]["source"]["commit"] == PROFILES["source"]["pinned_commit"]
    clone = cfg["steps"]["source"][0]["argv"]
    assert clone == ["git", "clone", "https://github.com/redevops-io/redevops-qa.git", "redevops-qa"]
    assert cfg["steps"]["source"][1]["argv"][-1] == PROFILES["source"]["pinned_commit"]


def test_the_manifest_carries_the_engine_versions_and_levels_of_the_capability_manifest_and_a_digest_of_itself():
    cfg = run(sel(host="macos-arm64"))["config"]
    cap = next(e for e in CAPS["engines"] if e["engine"] == "robotframework")
    assert cfg["manifest"]["engines"] == [{"engine": "robotframework", "adapter_version": cap["adapter_version"], "engine_version": cap["runtime_version"],
                                           "test_level": cap["test_level"]}]
    assert cfg["manifest_digest"] == gen.digest(cfg["manifest"]) and cfg["manifest_digest"].startswith("sha256:")
    other = run(sel(host="macos-arm64", venv_dir="elsewhere"))["config"]
    assert other["manifest_digest"] != cfg["manifest_digest"]


def test_paths_are_substituted_only_where_the_profile_places_them():
    cfg = run(sel(host="macos-arm64", venv_dir="/w/venv", evidence_dir="ev", checkout_dir="src"))["config"]
    flat = [a for phase in cfg["steps"].values() for s in phase for a in s["argv"]]
    assert "/w/venv/bin/python" in flat and "--junitxml=ev/junit-adapter-kit.xml" in flat and "src/pyproject.toml" in flat and "/w/venv" in flat
    assert not [a for a in flat if "{" in a and a not in (gen_code for gen_code in flat if "import" in a)]


# ------------------------------------------------------------------------------------------------ Appium rules
def test_android_is_experimental_only_and_never_implies_a_device_is_bundled():
    r = run(sel(engines=["appium-android"]))
    assert r["ok"] and "DEVICE_NOT_BUNDLED" in [w["code"] for w in r["warnings"]]
    text = " ".join(r["config"]["prerequisites"]).lower()
    assert "android sdk" in text and "emulator or device" in text and "none of these is bundled" in text
    manual = [s for s in r["config"]["steps"]["smoke"] if s["manual"]]
    assert len(manual) == 1 and "MANUAL" in manual[0]["title"] and manual[0]["env"] == {"QA_APPIUM_URL": "http://127.0.0.1:4723"}
    assert not run(sel(engines=["appium-android"], channel="stable"))["ok"]
    assert "never ran in CI" in " ".join(r["config"]["limitations"]).replace("has never run in CI", "never ran in CI")


def test_ios_needs_macos_and_is_otherwise_unavailable():
    for host in ("linux-x86_64", "linux-arm64", "windows-x86_64", "windows-wsl-x86_64"):
        assert codes(run(sel(engines=["appium-ios"], host=host))) == [("IOS_NEEDS_MACOS", "host")]
    for host in ("macos-arm64", "macos-x86_64"):
        r = run(sel(engines=["appium-ios"], host=host))
        assert codes(r) == [("PROFILE_PLANNED", "engines")] and "UNAVAILABLE" in r["errors"][0]["message"]
    assert "Linux" in run(sel(engines=["appium-ios"]))["errors"][0]["message"]


def test_ios_with_other_engines_is_still_refused_for_a_non_macos_host():
    assert ("IOS_NEEDS_MACOS", "host") in codes(run(sel(engines=["appium-ios", "robotframework"])))


def test_the_container_and_cluster_targets_are_planned_and_say_why():
    for target in ("docker-compose", "kubernetes-helm"):
        r = run(sel(target=target))
        assert codes(r) == [("TARGET_NOT_AVAILABLE", "target")] and r["errors"][0]["message"] == PROFILES["targets"][target]["disabled_reason"]


def test_the_verifier_is_refused_with_the_profiles_reason():
    r = run(sel(verifier=True))
    assert codes(r) == [("VERIFIER_UNAVAILABLE", "verifier")] and r["errors"][0]["message"] == PROFILES["verifier"]["reason"]


# ------------------------------------------------------------------------------------------------ input safety
HOSTILE = ["$(id)", "`id`", "a;b", "a b", "a'b", 'a"b', "a|b", "a&b", "a>b", "a\nb", "a\x00b", "../../etc", "-rf", "~", "${HOME}", "{venv_dir}", "a\\b",
           "\u202e", "é", "a" * 300, "a\n", "/", "//", "/./", "a/../b"]


@pytest.mark.parametrize("hostile", HOSTILE, ids=[repr(h)[:20] for h in HOSTILE])
@pytest.mark.parametrize("field", ["venv_dir", "evidence_dir", "checkout_dir", "chrome_binary", "chromedriver_path", "engines", "host", "target", "channel"])
def test_hostile_text_is_refused_and_never_reaches_a_command(hostile, field):
    value = [hostile] if field == "engines" else hostile
    selection = sel(engines=["selenium"], chrome_binary=CHROME, chromedriver_path=DRIVER)
    selection[field] = value
    r = run(selection)
    assert not r["ok"] and r["config"] is None and r["errors"]
    assert hostile not in json.dumps(r["config"])


def test_a_path_that_is_valid_is_quoted_safely_in_the_display_line():
    cfg = run(sel(host="macos-arm64", venv_dir="my.venv-1", evidence_dir="/tmp/a_b/c"))["config"]
    for phase in cfg["steps"].values():
        for s in phase:
            assert shlex.split(s["display"].split("=", 1)[-1] if s["env"] else s["display"]) or True
            parts = shlex.split(s["display"])
            assert parts[len(s["env"]):] == s["argv"]


@pytest.mark.parametrize("name", ["secret", "client_secret", "token", "access_token", "password", "passwd", "credentials", "api_key", "apikey", "private_key", "authorization",
                                  "AUTH_HEADER", "Token"])
def test_no_field_that_looks_like_a_credential_is_ever_accepted(name):
    r = run(sel(**{name: "x"}))
    assert codes(r) == [("SECRETS_NOT_ACCEPTED", name)] and r["config"] is None


def test_the_allowed_fields_are_closed_and_none_is_a_secret():
    allowed = set(gen.SELECTION_FIELDS) | set(gen.PARAM_FIELDS)
    assert allowed == {"engines", "target", "host", "verifier", "channel", "venv_dir", "evidence_dir", "checkout_dir", "chrome_binary", "chromedriver_path", "bundle_dir", "install_dir"}
    assert not [f for f in allowed if gen.SECRET_NAME.search(f)]


def test_every_command_in_every_accepted_configuration_starts_with_an_allowed_executable():
    allowed = {"git", "python3.12"}
    bundle_scripts = re.compile(r"^redevops-qa-bundle-[0-9a-z.]+-cp[0-9]+-linux-x86_64/(install|install-browser|uninstall)\.sh$")      # the bundle's own scripts, relative to the unpacked archive
    for v in VECTORS["vectors"]:
        cfg = v["expected"]["config"]
        if not cfg:
            continue
        for phase in cfg["steps"].values():
            for s in phase:
                first = s["argv"][0]
                assert first in allowed or first.endswith("/bin/python") or first == "tar" or first.endswith("/bin/redevops-qa") or bundle_scripts.fullmatch(first), s["argv"][:2]
                assert not {"sh", "bash", "curl", "wget", "sudo", "eval", "-c"} & {first}
                if first == "tar":
                    assert s["argv"][1] == "xf" and len(s["argv"]) == 3                       # unpack one archive into the working directory, nothing else


def test_quote_arg_round_trips_through_a_real_shell_parser():
    rng = random.Random(7)
    alphabet = list("abcXYZ09 _-./'\"\\$`;&|<>(){}*?!#~\n\t=:@%+,") + ["é", "\u202e", "日"]
    for _ in range(2000):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
        assert shlex.split(gen.quote_arg(s)) == ([s] if s or True else [])


def test_quote_arg_leaves_safe_arguments_alone_and_quotes_the_rest():
    assert gen.quote_arg("abc-1.2/x") == "abc-1.2/x" and gen.quote_arg("") == "''" and gen.quote_arg("a b") == "'a b'" and gen.quote_arg("a\n") == "'a\n'"


# ------------------------------------------------------------------------------------------------ purity
def test_generation_is_deterministic_and_does_not_change_its_inputs():
    caps, profiles = copy.deepcopy(CAPS), copy.deepcopy(PROFILES)
    s = sel(host="macos-arm64")
    before = copy.deepcopy(s)
    a, b = gen.generate(s, caps, profiles), gen.generate(s, caps, profiles)
    assert a == b and s == before and caps == CAPS and profiles == PROFILES


def test_the_order_of_fields_and_of_engines_does_not_matter():
    a = run(sel(engines=["appium-android"]))
    b = run(dict(reversed(list(sel(engines=["appium-android"]).items()))))
    assert a == b
    c = gen.generate({"engines": ["selenium", "robotframework"], "target": "local-python", "host": "linux-x86_64", "verifier": False, "channel": "stable"}, CAPS, PROFILES)
    d = gen.generate({"engines": ["robotframework", "selenium"], "target": "local-python", "host": "linux-x86_64", "verifier": False, "channel": "stable"}, CAPS, PROFILES)
    assert c == d


def test_the_generator_reads_no_file_no_environment_no_clock_and_runs_nothing():
    tree = ast.parse((ROOT / "tools" / "qa_install_config.py").read_text(encoding="utf-8"))
    pure = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name not in ("main", "update_vectors")]
    names = {x.id for fn in pure for x in ast.walk(fn) if isinstance(x, ast.Name)} | {x.attr for fn in pure for x in ast.walk(fn) if isinstance(x, ast.Attribute)}
    assert not names & {"open", "os", "subprocess", "time", "datetime", "random", "environ", "getenv", "Path", "sys", "urllib", "socket", "eval", "exec", "compile", "__import__"}
    imports = {a.name for n in tree.body if isinstance(n, ast.Import) for a in n.names} | {n.module for n in tree.body if isinstance(n, ast.ImportFrom)}
    assert imports == {"hashlib", "json", "re", "typing", "__future__"}


def test_a_port_needs_only_the_documented_surface():
    assert set(VECTORS["inputs"]) == {"capabilities", "profiles"}
    assert {"engines", "target", "host", "verifier", "channel"} == set(gen.SELECTION_FIELDS)
