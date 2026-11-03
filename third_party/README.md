# third_party

`adapter-license-matrix.yaml` records the licence facts for the optional execution-adapter frameworks (Selenium, Robot
Framework, Appium, Playwright) and the toolchains around them: project, pinned release and tag, SPDX licence, licence URL and file
hash, artifacts, bundled and direct dependencies, notices, trademark constraints and the redistribution status.

This is technical triage, not legal advice. Each fact says how it was checked (`verified` against the upstream file at the pinned tag,
`registry-metadata`, or `unverified`); an unverified fact never supports a redistribution claim.

`python tools/check_adapter_licenses.py` fails on an unknown or incompatible redistributable, on a package that an adapter package or
workflow installs without a matrix entry, and on a pin that differs from the matrix. `--verify-upstream` re-fetches each licence file
at its tag and compares hashes (network; not part of the offline test run). Commercial SDKs and Apple toolchains are listed as
`excluded_by_default` and are never bundled or downloaded.

The pinned bundle (`bundle/`, built by `tools/build_bundle.py`) carries unmodified wheels of Playwright, Robot Framework, PyYAML, greenlet, pyee and typing_extensions, named with
their digests in `bundle/third-party.lock.json`. Every one of them is recorded in the matrix under `shipped_wheels` with the licence and notice files the wheel itself carries, and the
status `staged_unmodified`: **private staging only; public distribution requires an owner decision.** `tools/check_adapter_licenses.py` fails when a wheel of the lock has no such entry
(same name, version, file name and sha256), when a recorded wheel is not in the lock, or when a shipped wheel sits under any other status.

What the two large wheels contain, from unpacking them: the Playwright wheel holds a Node.js runtime binary (`playwright/driver/node`, licence file `playwright/driver/LICENSE`), the
Playwright driver with 79 npm packages inlined into `lib/utilsBundle.js` and 2 into `lib/serverRegistry.js` (sidecar `.LICENSE` files) and libwebp (`lib/webp_codec.LICENSE`), none of
which is classified one by one. The Robot Framework wheel holds five report assets in `robot/htmldata/lib`; the licence of two of them (`jquery.min.js`, `jquery.tablesorter.min.js`)
could not be established from the wheel and is recorded as unverified. Nothing here is a clearance.
