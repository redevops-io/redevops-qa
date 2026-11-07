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