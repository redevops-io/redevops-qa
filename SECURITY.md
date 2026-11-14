# Security policy

`redevops-qa` runs test specifications against targets and drives real browsers and devices, so its isolation and redaction behaviour matters.

## Reporting a vulnerability
Please report it privately through GitHub: open the **Security** tab of this repository and choose **Report a vulnerability** (private vulnerability reporting).
Do not open a public issue or pull request for a vulnerability. Include what you found, the commit or version, and the smallest way to reproduce it. We will
acknowledge a report and keep you informed; we do not publish a service-level commitment for response times.

## Scope
Of most interest: a way to make the runner reach a host its egress policy forbids, to read or leak a value the redaction rules withhold (passwords, secrets),
to run a command or read a path outside the adapter allow-lists, to alter evidence after it is recorded, or to make a verifier report a verdict the evidence
does not support.

## Supported versions
There is no tagged release yet, so only the default branch is supported. This will be stated here when the first release is tagged.

## Secret scanning
Two scanners run over the **full public history** (`--all`) on every push, every pull request and weekly
(`.github/workflows/secret-scan.yml`): gitleaks 8.30.1 and trufflehog 3.99.8, each pinned by exact version and by the
sha256 of the exact release archive it downloads. **Neither scan is ever narrowed** — no `--exclude-paths`, no
`--exclude-globs`, no `--only-verified`. A finding fails the job unless it appears, one by one, in an allow-list that
carries a written justification for that specific finding: `.gitleaksignore` for gitleaks (per line) and
`tools/trufflehog_baseline.txt` for trufflehog (per detector + file + digest of the redacted match), enforced by
`tools/check_trufflehog_baseline.py`, which also fails on an allow-list entry that silences nothing and on a scan that
exits with anything other than "clean" (0) or "findings" (183).

Scan record, re-measured on the default branch on 2026-11-11 with the pinned tools: gitleaks found **2** findings, both
false positives (`generic-api-key` on a test identifier `generate_private_key` that asserts no key is generated, and on
the fixture order id `api-discount-10000`), both ignored with a per-line justification in `.gitleaksignore`. trufflehog
found **0 verified and 5 unverified** findings, all false positives: four credential-shaped URLs that exist *so that*
redaction and proxy-rejection can be tested (`http://alice:…@127.0.0.1`, fake proxies under `.example`/`.test`, which
RFC 6761 and RFC 2606 reserve) in `tests/test_bundle_browser.py`, `packages/qa-runner/tests/test_qr_browser_pin.py` and
`packages/qa-selenium/tests/test_sel_adapter.py`, plus one SHA-256 deny-list digest in `tools/check_neutral_wording.py`
that the `PhraseAccessToken` detector reads as a token; each is allow-listed with its reason. An earlier record here
(2026-11-07) stated a clean trufflehog run; that figure could not be reproduced on a fresh clone of the same commit and
is superseded by this one — the correction is part of the record, not a change to what is scanned.
Added 2026-11-14: one more entry in each list for the P2-1 acceptance test (`packages/qa-runner/tests/test_p21_external_target_acceptance.py`, commit 3e2ad31): a credential-shaped literal and a
userinfo-shaped example URL that the test feeds to the target validator to prove they are refused; the current text assembles them at run time, and only that one earlier revision is flagged.
The public history is not rewritten (owner decision D3, 2026-11-07): the scanning record and the allow-lists are the
disclosure. A clean scan is not proof that no secret ever existed — the regex audit of 2026-11-05 and these tools agree
on "no live credential", and new findings are handled through the private report channel above.
