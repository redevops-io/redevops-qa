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
