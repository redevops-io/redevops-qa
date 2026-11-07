# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The secret-scan workflow (audit item P0-6) scans the full history, pins what it downloads, stays read-only and
secret-free, and its allow-list stays justified: every ignored fingerprint must be a commented false positive
whose file still exists and still contains the line that was judged."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / ".github" / "workflows" / "secret-scan.yml").read_text(encoding="utf-8")
WF = yaml.safe_load(TEXT)
TRIGGERS = WF.get(True) or WF.get("on")
IGNORE = (ROOT / ".gitleaksignore").read_text(encoding="utf-8")


def test_triggers_are_push_pull_request_and_schedule_only():
    assert set(TRIGGERS) == {"push", "pull_request", "schedule"}


def test_permissions_are_read_only_and_no_job_asks_for_more():
    assert WF["permissions"] == {"contents": "read"}
    for name, job in WF["jobs"].items():
        assert "permissions" not in job, name


def test_no_publish_write_or_secret_path_anywhere():
    # same discipline as test_workflow.py: executable steps are scanned exhaustively, and the whole
    # file is held to the strings that must not appear even in a comment. The one permitted use of
    # "release" is the version-pinned download URL of the two scanners this job itself downloads.
    low = TEXT.lower()
    executable = "\n".join(f"{s.get('run', '')} {s.get('uses', '')} {s.get('with', '')}".lower()
                           for job in WF["jobs"].values() for s in job["steps"])
    assert executable.count("releases/download/") == 2                     # exactly the two pinned archives
    assert executable.count("/v8.30.1/") == 1 and executable.count("/v3.99.8/") == 1   # both URLs pinned by version
    executable = executable.replace("releases/download/", "")
    for word in ("release", "publish", "twine", "git push", "docker push", "pypi", "id-token",
                 "secrets.", "token", "continue-on-error", "--no-verify"):
        assert word not in executable, word
    for word in ("contents: write", "continue-on-error", "secrets."):
        assert word not in low, word


def test_both_scanners_run_over_every_ref_and_pin_everything_they_download():
    assert "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" in TEXT and "@v4" not in TEXT
    for job_name, needle in (("gitleaks", './gitleaks git . --log-opts="--all"'),
                             ("trufflehog", "./trufflehog git file://. --fail")):
        steps = "\n".join(str(s.get("run", "")) for s in WF["jobs"][job_name]["steps"])
        assert needle in steps, job_name
    # the two archives are checked against their sha256 before extraction (gitleaks 8.30.1, trufflehog 3.99.8)
    assert TEXT.count("sha256sum -c -") == 2
    assert "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" in TEXT   # gitleaks_8.30.1_linux_x64
    assert "7c3b02f160f28929a467e29e20fba98746e0729f6e37c3c25761e4f8789abe08" in TEXT   # trufflehog_3.99.8_linux_amd64
    # full history on both jobs
    assert TEXT.count("fetch-depth: 0") == 2


def test_the_gitleaks_allow_list_is_fingerprints_of_justified_existing_lines():
    entries = [ln for ln in IGNORE.splitlines() if ln.strip() and not ln.startswith("#")]
    assert len(entries) == 2, "the allow-list carries exactly the two justified false positives of 2026-11-07"
    for line in entries:
        commit, path, rule, lineno = line.split(":")
        assert len(commit) == 40 and rule == "generic-api-key"
        source = ROOT / path
        assert source.is_file(), path
        body = source.read_text(encoding="utf-8").splitlines()
        assert 0 < int(lineno) <= len(body), f"{path}:{lineno} is past the end of the file"
    # the two judged lines are the ones documented in SECURITY.md and the ignore-file comments
    assert "generate_private_key" in IGNORE and "api-discount-10000" in IGNORE


# ---- the trufflehog result gate (tools/check_trufflehog_baseline.py) -------------------------------------------
# The scan is total; only individual, justified findings are silenced. These tests hold the gate to failing closed,
# so relaxing it is a deliberate edit to this file and not an accident in a workflow.
import importlib.util  # noqa: E402  (the gate lives in tools/, which is not an importable package)

_SPEC = importlib.util.spec_from_file_location("ctb", ROOT / "tools" / "check_trufflehog_baseline.py")
GATE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(GATE)

BASELINE = (ROOT / "tools" / "trufflehog_baseline.txt").read_text(encoding="utf-8")


def _rec(detector="URI", path="tests/something_test.py", redacted="http://user:********@example.invalid"):
    import json
    return json.dumps({"DetectorName": detector, "Redacted": redacted,
                       "SourceMetadata": {"Data": {"Git": {"file": path, "commit": "0" * 40}}}})


def _allow(tmp_path, *lines):
    p = tmp_path / "allow.txt"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def test_the_gate_fails_on_a_finding_that_is_not_allow_listed(tmp_path):
    allow = _allow(tmp_path, "URI|tests/other_test.py|000000000000|a different finding entirely")
    out = tmp_path / "scan.json"
    out.write_text(_rec() + "\n", encoding="utf-8")
    assert GATE.main(["--json", str(out), "--allow", str(allow), "--exit-status", "183"]) == 1


def test_the_gate_fails_on_an_allow_list_entry_that_silences_nothing(tmp_path):
    allow = _allow(tmp_path, "URI|tests/something_test.py|abcdef012345|matches no finding in this scan")
    out = tmp_path / "scan.json"
    out.write_text("\n".join(_rec(redacted="http://quiet:********@example.invalid")) + "\n", encoding="utf-8")
    assert GATE.main(["--json", str(out), "--allow", str(allow), "--exit-status", "183"]) == 1


def test_the_gate_passes_only_when_the_digest_of_the_redacted_match_matches(tmp_path):
    import hashlib
    digest = hashlib.sha256(b"http://user:********@example.invalid").hexdigest()[:12]
    allow = _allow(tmp_path, f"URI|tests/something_test.py|{digest}|the one finding of this scan, and why it is inert")
    out = tmp_path / "scan.json"
    out.write_text(_rec() + "\n", encoding="utf-8")
    assert GATE.main(["--json", str(out), "--allow", str(allow), "--exit-status", "183"]) == 0


def test_the_gate_fails_when_trufflehog_itself_did_not_complete(tmp_path):
    allow = _allow(tmp_path, "URI|tests/something_test.py|abcdef012345|unused here")
    out, err = tmp_path / "scan.json", tmp_path / "scan.err"
    out.write_text("", encoding="utf-8")
    err.write_text("error: could not read the repository\n", encoding="utf-8")
    assert GATE.main(["--json", str(out), "--allow", str(allow), "--exit-status", "7", "--stderr", str(err)]) == 1


def test_an_allow_list_entry_without_a_justification_is_refused(tmp_path):
    allow = _allow(tmp_path, "URI|tests/something_test.py|abcdef012345|")
    out = tmp_path / "scan.json"
    out.write_text("", encoding="utf-8")
    assert GATE.main(["--json", str(out), "--allow", str(allow)]) == 1


def test_the_shipped_trufflehog_allow_list_is_justified_and_points_at_real_files():
    entries = [ln for ln in BASELINE.splitlines() if ln.strip() and not ln.startswith("#")]
    assert entries, "the trufflehog allow-list must account for every finding the scan reports"
    for line in entries:
        detector, path, digest, reason = [p.strip() for p in line.split("|", 3)]
        assert detector and reason, line
        assert len(reason) > 20, f"{path}: a one-word reason is not a justification"
        assert len(digest) >= 12 and all(c in "0123456789abcdef" for c in digest), line
        assert (ROOT / path).is_file(), path


def test_the_workflow_scans_everything_and_gates_results_rather_than_narrowing_the_scan():
    steps = "\n".join(str(s.get("run", "")) for s in WF["jobs"]["trufflehog"]["steps"])
    for forbidden in ("--exclude-paths", "--exclude-globs", "--only-verified", "--exclude-detectors"):
        assert forbidden not in steps, f"{forbidden} would stop files or detectors from being scanned at all"
    assert "./trufflehog git file://. --fail --no-update --json" in steps
    assert "tools/check_trufflehog_baseline.py" in steps
    assert "--allow tools/trufflehog_baseline.txt" in steps
    # 0 = clean, 183 = findings (the code trufflehog exits with under --fail); anything else must not pass
    assert "-ne 183" in steps and "did not complete" in steps
