# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The receipt-generation CLI, end to end in subprocesses: missing dependency, zero collected, skip detected, tamper and
stale pins. A stub tests directory stands in for the real conformance tests where the point is the accounting."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from receipt_helpers import make_repo

ROOT = Path(__file__).resolve().parents[3]
BRIDGE_SRC = ROOT / "packages" / "qa-bridge" / "src"
PIN_SET = os.environ.get("REDEVOPS_QA_PIN_SET", "c4")
PASSING = {f"CHK{i}" for i in range(1, 8)}


def _site_packages():
    return [p for p in sys.path if "site-packages" in p]


def run_cli(args, *, pins_file, env_extra=None, cwd=None):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(pins_file.parent), "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONPATH": os.pathsep.join([str(BRIDGE_SRC), *_site_packages()]), "REDEVOPS_QA_PIN_SET": PIN_SET}
    env.update(env_extra or {})
    done = subprocess.run([sys.executable, "-m", "redevops_qa_bridge.conformance.cli", "--pins", str(pins_file), *args],
                          env=env, capture_output=True, text=True, cwd=cwd or str(pins_file.parent), timeout=300)
    return done


def pinned_env(pins):
    return {"QA_PIN_CONTRACTS_PATH": str(pins.contracts.resolved_path), "QA_PIN_HARNESS_QA_PATH": str(pins.harness_qa.resolved_path)}


@pytest.fixture()
def workdir(tmp_path):
    root = make_repo(tmp_path / "work", commit=False)
    import re
    text = (ROOT / "pins.toml").read_text(encoding="utf-8")
    # the stub tests stand in for the real items, so the not-applicable declarations of a pin set do not apply to them
    text = re.sub(r"\[\[sets\.\w+\.not_applicable\]\]\n(?:[^\[\n][^\n]*\n|\n)*", "", text)
    (root / "pins.toml").write_text(text, encoding="utf-8")
    from receipt_helpers import git
    git(root, "add", "pins.toml")
    git(root, "commit", "-q", "-m", "pins")
    return root


def stub_tests(root: Path, *, skip=None, drop=(), stray=False, fail=None, na=None) -> Path:
    d = root.parent / "stub_tests"
    d.mkdir()
    (d / "pytest.ini").write_text("[pytest]\nmarkers =\n    check(id): conformance check\n    not_applicable: n/a\n")
    for i in sorted(PASSING - set(drop)):
        body = "import pytest\n"
        if skip == i:
            body += f"\n@pytest.mark.check('{i}')\n@pytest.mark.skip(reason='no')\ndef test_a():\n    pass\n"
        elif fail == i:
            body += f"\n@pytest.mark.check('{i}')\ndef test_a():\n    from redevops_qa_bridge.conformance.model import fail\n    fail('HASH_DIVERGENCE', 'x')\n"
        elif na == i:
            body += f"\n@pytest.mark.check('{i}')\n@pytest.mark.not_applicable\ndef test_a():\n    pass\n"
        else:
            body += f"\n@pytest.mark.check('{i}')\ndef test_a():\n    pass\n"
        (d / f"test_{i.lower()}.py").write_text(body)
    if stray:
        (d / "test_stray.py").write_text("def test_stray():\n    pass\n")
    return d


def load(path):
    return json.loads(Path(path).read_text())


def test_a_clean_stub_run_passes_and_its_receipt_verifies(pins, workdir):
    tests = stub_tests(workdir)
    out = workdir.parent / "receipt.json"
    done = run_cli(["run", "--receipt", str(out), "--tests-dir", str(tests)], pins_file=workdir / "pins.toml",
                   env_extra=pinned_env(pins))
    assert done.returncode == 0, done.stdout + done.stderr
    r = load(out)
    assert r["result"] == "PASS" and r["collected_tests"] == 7 and r["skipped_tests"] == 0 and r["failed_tests"] == 0
    assert r["subjects"]["pin_set"] == PIN_SET and r["dependencies_available"] == {"contracts": True, "harness_qa": True}
    ver = run_cli(["verify", str(out)], pins_file=workdir / "pins.toml", env_extra=pinned_env(pins))
    assert ver.returncode == 0 and ver.stdout.splitlines()[0] == "VALID", ver.stdout + ver.stderr


def test_a_tampered_receipt_fails_verification(pins, workdir):
    tests = stub_tests(workdir)
    out = workdir.parent / "receipt.json"
    run_cli(["run", "--receipt", str(out), "--tests-dir", str(tests)], pins_file=workdir / "pins.toml", env_extra=pinned_env(pins))
    r = load(out)
    r["collected_tests"] = 999
    out.write_text(json.dumps(r))
    ver = run_cli(["verify", str(out)], pins_file=workdir / "pins.toml", env_extra=pinned_env(pins))
    assert ver.returncode == 1 and ver.stdout.splitlines()[0] == "TAMPERED"


def test_changing_a_pin_makes_the_previous_receipt_stale(pins, workdir):
    tests = stub_tests(workdir)
    out = workdir.parent / "receipt.json"
    run_cli(["run", "--receipt", str(out), "--tests-dir", str(tests)], pins_file=workdir / "pins.toml", env_extra=pinned_env(pins))
    text = (workdir / "pins.toml").read_text()
    old = pins.contracts.commit
    (workdir / "pins.toml").write_text(text.replace(old, "f" * 40))
    ver = run_cli(["verify", str(out), "--skip-redevops-commit"], pins_file=workdir / "pins.toml", env_extra=pinned_env(pins))
    assert ver.returncode == 2 and ver.stdout.splitlines()[0] == "STALE" and "contracts.commit" in ver.stdout


def test_a_missing_dependency_fails_the_run_and_is_never_skipped(pins, workdir, tmp_path):
    out = workdir.parent / "receipt.json"
    env = pinned_env(pins)
    env["QA_PIN_CONTRACTS_PATH"] = str(tmp_path / "does-not-exist")
    real = ROOT / "packages" / "qa-bridge" / "tests" / "conformance"
    done = run_cli(["run", "--receipt", str(out), "--tests-dir", str(real)], pins_file=workdir / "pins.toml", env_extra=env)
    assert done.returncode == 1, done.stdout + done.stderr
    r = load(out)
    assert r["result"] == "FAIL" and r["dependencies_available"] == {"contracts": False, "harness_qa": True}
    assert r["collected_tests"] == 7 and r["skipped_tests"] == 0 and r["failed_tests"] == 7
    assert all(c["status"] == "FAIL" and c["failure_codes"] == ["DEPENDENCY_UNAVAILABLE"] for c in r["checks"])


def test_a_missing_harness_is_a_failure_too(pins, workdir, tmp_path):
    out = workdir.parent / "receipt.json"
    env = pinned_env(pins)
    env["QA_PIN_HARNESS_QA_PATH"] = str(tmp_path / "does-not-exist")
    real = ROOT / "packages" / "qa-bridge" / "tests" / "conformance"
    done = run_cli(["run", "--receipt", str(out), "--tests-dir", str(real)], pins_file=workdir / "pins.toml", env_extra=env)
    r = load(out)
    assert done.returncode == 1 and r["result"] == "FAIL" and r["dependencies_available"]["harness_qa"] is False


def test_zero_collected_tests_fails_the_run(pins, workdir):
    empty = workdir.parent / "empty_tests"
    empty.mkdir()
    (empty / "pytest.ini").write_text("[pytest]\nmarkers =\n    check(id): conformance check\n")
    out = workdir.parent / "receipt.json"
    done = run_cli(["run", "--receipt", str(out), "--tests-dir", str(empty)], pins_file=workdir / "pins.toml", env_extra=pinned_env(pins))
    r = load(out)
    assert done.returncode == 1 and r["result"] == "FAIL" and r["collected_tests"] == 0
    assert all("NO_TESTS_COLLECTED" in c["failure_codes"] for c in r["checks"])


def test_a_skipped_test_fails_the_run(pins, workdir):
    out = workdir.parent / "receipt.json"
    done = run_cli(["run", "--receipt", str(out), "--tests-dir", str(stub_tests(workdir, skip="CHK4"))],
                   pins_file=workdir / "pins.toml", env_extra=pinned_env(pins))
    r = load(out)
    assert done.returncode == 1 and r["result"] == "FAIL" and r["skipped_tests"] == 1
    assert r["checks"][3]["status"] == "FAIL" and "SKIPPED_TESTS" in r["checks"][3]["failure_codes"]


def test_a_failing_test_names_its_code_in_the_receipt(pins, workdir):
    out = workdir.parent / "receipt.json"
    run_cli(["run", "--receipt", str(out), "--report", str(workdir.parent / "report.json"),
             "--tests-dir", str(stub_tests(workdir, fail="CHK2"))], pins_file=workdir / "pins.toml", env_extra=pinned_env(pins))
    r = load(out)
    assert r["result"] == "FAIL" and r["checks"][1]["failure_codes"] == ["HASH_DIVERGENCE"] and r["failed_tests"] == 1
    report = load(workdir.parent / "report.json")
    assert report["groups"]["additional"]["count"] == 1


def test_a_not_applicable_test_is_reported_as_such_and_never_as_a_skip_but_an_undeclared_one_cannot_pass(pins, workdir):
    out = workdir.parent / "receipt.json"
    tests = stub_tests(workdir, na="CHK3")
    (tests / "test_chk3.py").write_text(
        "import pytest\n\n@pytest.mark.check('CHK3')\ndef test_a():\n    pass\n\n"
        "@pytest.mark.check('CHK3')\n@pytest.mark.not_applicable\ndef test_b():\n    pass\n")
    done = run_cli(["run", "--receipt", str(out), "--tests-dir", str(tests)], pins_file=workdir / "pins.toml", env_extra=pinned_env(pins))
    r = load(out)
    chk3 = r["checks"][2]
    assert (chk3["collected"], chk3["passed"], chk3["not_applicable"], chk3["skipped"]) == (2, 1, 1, 0)
    assert r["skipped_tests"] == 0 and r["not_applicable_tests"] == 1 and len(r["not_applicable"]) == 1
    # nothing in pins.toml declares it (the stub pins declare none): an unexplained not-applicable item cannot give PASS
    assert r["not_applicable"][0]["reason"] == "" and r["result"] == "FAIL" and done.returncode == 1


def test_a_test_outside_the_seven_checks_fails_the_run(pins, workdir):
    out = workdir.parent / "receipt.json"
    done = run_cli(["run", "--receipt", str(out), "--tests-dir", str(stub_tests(workdir, stray=True))],
                   pins_file=workdir / "pins.toml", env_extra=pinned_env(pins))
    assert done.returncode == 1 and load(out)["result"] == "FAIL"


def test_a_dirty_working_tree_fails_the_run(pins, workdir):
    (workdir / "pins.toml").write_text((workdir / "pins.toml").read_text() + "\n# local edit\n")
    out = workdir.parent / "receipt.json"
    done = run_cli(["run", "--receipt", str(out), "--tests-dir", str(stub_tests(workdir))],
                   pins_file=workdir / "pins.toml", env_extra=pinned_env(pins))
    r = load(out)
    assert done.returncode == 1 and r["subjects"]["redevops_qa"]["worktree_clean"] is False and r["result"] == "FAIL"


def test_the_real_suite_produces_a_receipt_whose_hash_verifies_and_a_report(pins, workdir):
    out = workdir.parent / "receipt.json"
    done = run_cli(["run", "--receipt", str(out), "--report", str(workdir.parent / "report.json"), "--report-md",
                    str(workdir.parent / "report.md"), "--tests-dir", str(ROOT / "packages" / "qa-bridge" / "tests" / "conformance")],
                   pins_file=workdir / "pins.toml", env_extra=pinned_env(pins))
    assert done.returncode in (0, 1), done.stdout + done.stderr
    r = load(out)
    assert r["collected_tests"] > 500 and r["skipped_tests"] == 0 and len(r["checks"]) == 7
    assert len(r["vectors"]["items"]) > 100
    ver = run_cli(["verify", str(out)], pins_file=workdir / "pins.toml", env_extra=pinned_env(pins))
    assert ver.stdout.splitlines()[0] in ("VALID", "FAILED"), ver.stdout
    report = load(workdir.parent / "report.json")
    assert report["receipt_hash"] == r["receipt_hash"] and (workdir.parent / "report.md").read_text().startswith("# Divergence report")


def test_an_unknown_pin_set_is_refused_by_the_cli(pins, workdir):
    done = run_cli(["--pin-set", "nope", "run", "--receipt", str(workdir.parent / "r.json")], pins_file=workdir / "pins.toml")
    assert done.returncode == 3 and "PINS_INVALID" in done.stderr
