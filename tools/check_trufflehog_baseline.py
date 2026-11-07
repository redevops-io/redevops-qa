#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""trufflehog result gate: the scan is never narrowed; findings are allowed one by one, with a reason.

Why not ``--exclude-paths``: that stops trufflehog reading whole files, so a real secret added to one of those
files later would go unseen. This gate reads every finding the scan produced and fails on any finding that is not
individually allow-listed, so coverage is identical to a bare run; the only thing the allow-list buys is silence
about a specific, justified, hash-pinned finding.

Allow-list (``tools/trufflehog_baseline.txt``), one finding per line:
    <DetectorName>|<repo-relative path>|<first 12 hex of sha256 of the REDACTED match>|<justification>
A finding is identified by the sha256 of trufflehog's own redacted rendering, so the list carries no secret and no
fixture text. Blank lines and lines starting with ``#`` are ignored; a justification is mandatory. An entry that
matches nothing is a failure (``stale``), so the list cannot outlive its need.

Exit codes: 0 when every finding is allow-listed; 1 for any unallow-listed finding, any stale entry, or a trufflehog
failure with no findings to explain it. Nothing this prints ever contains a secret: detector names, paths and
digest prefixes only.

Usage: check_trufflehog_baseline.py --json <trufflehog.json> --allow <file> [--exit-status N] [--stderr <file>]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Iterable, List, NamedTuple, Sequence, Tuple


class AllowEntry(NamedTuple):
    detector: str
    path: str
    digest: str
    reason: str
    lineno: int


class Finding(NamedTuple):
    detector: str
    path: str
    digest: str


def key(detector: str, path: str, digest: str) -> Tuple[str, str, str]:
    return (detector.strip(), path.strip(), digest.strip().lower())


def load_allow(path: Path) -> List[AllowEntry]:
    """Parse the allow-list. A line without a justification is a load-time failure, not a warning."""
    out: List[AllowEntry] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|", 3)]
        if len(parts) != 4 or not all(parts):
            raise ValueError(f"{path}:{lineno}: expected <detector>|<path>|<12 hex digest>|<justification>")
        if len(parts[2]) < 12 or any(c not in "0123456789abcdef" for c in parts[2].lower()):
            raise ValueError(f"{path}:{lineno}: the third field must be at least 12 hex characters")
        out.append(AllowEntry(parts[0], parts[1], parts[2].lower(), parts[3], lineno))
    return out


def parse_findings(text: str) -> List[Finding]:
    """Every finding in a trufflehog --json stream, as (detector, path, redacted digest). Non-JSON lines are logs."""
    out: List[Finding] = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if "DetectorName" not in rec or "SourceMetadata" not in rec:
            continue
        git = (rec.get("SourceMetadata") or {}).get("Data", {}).get("Git") or {}
        redacted = str(rec.get("Redacted") or "")
        digest = hashlib.sha256(redacted.encode("utf-8")).hexdigest()[:12]
        out.append(Finding(str(rec.get("DetectorName") or ""), str(git.get("file") or ""), digest))
    return out


def classify(findings: Sequence[Finding], allow: Sequence[AllowEntry]) -> Tuple[List[Finding], List[AllowEntry]]:
    """(unallow-listed findings, stale allow entries)."""
    allowed = {key(e.detector, e.path, e.digest) for e in allow}
    seen, unexpected = set(), []
    for f in findings:
        k = key(f.detector, f.path, f.digest)
        if k in allowed:
            seen.add(k)
        else:
            unexpected.append(f)
    stale = [e for e in allow if key(e.detector, e.path, e.digest) not in seen]
    return unexpected, stale


def main(argv: Iterable[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", required=True, type=Path, help="trufflehog --json output")
    ap.add_argument("--allow", required=True, type=Path, help="the allow-list")
    ap.add_argument("--exit-status", type=int, default=0, help="trufflehog's own exit status")
    ap.add_argument("--stderr", type=Path, default=None, help="trufflehog's stderr, shown only when it failed")
    a = ap.parse_args(list(argv))

    try:
        allow = load_allow(a.allow)
    except ValueError as exc:
        print(f"trufflehog gate: unreadable allow-list: {exc}", file=sys.stderr)
        return 1

    findings = parse_findings(a.json.read_text(encoding="utf-8", errors="replace"))
    unexpected, stale = classify(findings, allow)

    for f in unexpected:
        print(f"trufflehog finding not allow-listed: {f.detector} in {f.path} (digest {f.digest})")
    for e in stale:
        print(f"{a.allow}:{e.lineno}: stale allow-list entry (it silences nothing): {e.detector} in {e.path}")
    if unexpected or stale:
        print(f"trufflehog gate: {len(findings)} finding(s), {len(unexpected)} unexpected, {len(stale)} stale")
        return 1
    if a.exit_status != 0 and not findings:
        print(f"trufflehog itself failed (exit {a.exit_status}) with no findings to justify it — the scan did not complete")
        if a.stderr and a.stderr.exists():
            for line in a.stderr.read_text(encoding="utf-8", errors="replace").splitlines()[-8:]:
                print(f"  trufflehog stderr: {line}")
        return 1
    print(f"OK trufflehog gate: {len(findings)} finding(s), all allow-listed with justification; "
          f"{len(allow)} allow-list entries, none stale; the scan covered every tracked file")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
