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

The pinned bundle (`bundle/`, built by `tools/build_bundle.py`) carries unmodified wheels of Playwright, Robot Framework and their dependencies (named with their digests in
`bundle/third-party.lock.json`), each with the licence files it ships. This matrix still records Playwright, Robot Framework and the direct dependencies of Playwright as
`optional_extra` (not shipped by ReDevOps): a decision to publish a bundle that contains them is the owner's and is not made by the build, which only produces a workflow artifact.
