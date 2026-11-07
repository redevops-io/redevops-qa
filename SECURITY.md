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
sha256 of the exact release archive it downloads. A finding fails the job; a new entry in `.gitleaksignore` needs a
comment saying why.

One-time history scan, 2026-11-07: gitleaks found 2 findings, both false positives (`generic-api-key` on a test
identifier `generate_private_key` that asserts no key is generated, and on the fixture order id `api-discount-10000`);
both are ignored with a per-line justification in `.gitleaksignore`. trufflehog (3.99.8) found 0 verified and 0
unverified findings across 3,950 chunks, which is why its job gates on *any* finding. The public history is not
rewritten (owner decision D3, 2026-11-07): the scanning record and the allow-list are the disclosure. A clean scan is
not proof that no secret ever existed — the regex audit of 2026-11-05 and these tools agree on "clean", and new findings
are handled through the private report channel above.
