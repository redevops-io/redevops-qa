# redevops-qa

QA runner that executes versioned test specifications against a target, checks
immutable assertions deterministically, and keeps reproducible evidence.

**Scope first, from the opening screen (audit item P0-4):** today `run` and `demo` **run only against the bundled fixture app**
(`packages/qa-fixture-app`): `orchestrate.py` hard-wires the target to `fixture-app`, and no external application can be pointed at it yet —
the external target is audit item P2-1, still design work ([docs/P2_1_EXTERNAL_TARGET_DESIGN.md](docs/P2_1_EXTERNAL_TARGET_DESIGN.md)). Do not describe this as general-purpose QA support until P2-1 ships.
Supported platform: CPython 3.12 (the fixture-app CI also runs 3.11) on Linux x86_64 only — macOS and Windows are not claimed,
the real-device Android lane has run only by hand on one emulator, and there is no iOS evidence.

**Status: pre-release.** There is no tagged release of this repository yet, and no package is published to PyPI; you work from a checkout. It is built
against pinned *releases* of its dependencies, [`runtime-contracts`](https://github.com/redevops-io/runtime-contracts) (`v0.3.15` and `v0.3.16`) and
[`agent-harness`](https://github.com/redevops-io/agent-harness) (`v0.2.0`), recorded with their digests in [pins.toml](pins.toml); it does not vendor them.

**Licence:** source-available, not open source: AGPL-3.0-or-later as modified by the Commons Clause, the same terms as the other ReDevOps runtime
packages. See [LICENSE.md](LICENSE.md).

## What runs in CI today
The push and pull-request workflow runs the offline test suites, the `qa/v1` conformance suite against both pinned contract states, and jobs that exercise a real
engine: Playwright with Chromium, Selenium with Chrome, Robot Framework, and the Appium server with the UiAutomator2 driver (no device). The `redevops-qa` command
is run end to end with real Chromium and Robot Framework together (`runner-e2e`), and the public demo (`demo` jobs) runs it three times from the installed bundle against the
fixture app: with no defect (verified), with a seeded discount defect (the Robot lane fails) and with a seeded settings defect (the Playwright lane fails); each evidence bundle is
kept as a workflow artifact and re-verified in a second job. The real-device Android lane is a separate manual workflow, because hosted runners have no emulator: it passed locally on
one Android 17 emulator and has never run in CI. There is no iOS evidence; the iOS adapter reports `UNAVAILABLE`. An engine's own PASS is a framework result, not an independent
verdict. Details per package are in the READMEs below; vulnerability reporting is in [SECURITY.md](SECURITY.md).

## Install and run

From a pinned bundle (CPython 3.12 on Linux x86_64 only; nothing is published, so you build it from a checkout or take the archive of a workflow run): the steps, the checks the install makes
and what it does not check are in [bundle/README.md](bundle/README.md); `python tools/build_bundle.py build --out DIR` builds it. The installer profile `local-python-qa`
([docs/QA_INSTALL_PROFILES.md](docs/QA_INSTALL_PROFILES.md)) lists the same steps as data and is run by CI. A real run, with its output, is in [docs/QA_DEMO.md](docs/QA_DEMO.md).
Chromium is downloaded by the bundle's separate browser step and checked against `bundle/browser.lock.json`: the sha256 of the three archives before they are unpacked, then every file and mode of the unpacked tree (in a bundle installation `doctor` and `run` repeat the tree check; a source checkout has no pin and no check); the operating system libraries and the availability of the download host are outside that check. macOS and Windows are not claimed.

## Developer checkout (from a fresh clone, three commands)

A source checkout needs the two pinned upstreams fetched into `.pinned/` at their exact pinned commits before `pytest` can even collect
(`agent_harness` and `runtime_contracts` are imported from those paths, never installed; nothing else about them is hard-coded anywhere
but [pins.toml](pins.toml)). `tools/fetch_pins.py` does the fetch and the verification CI does — HEAD at the pinned commit, clean tree,
distribution and vector digests — over plain HTTPS with no token. Requires a CPython 3.12 on `PATH` (macOS and Windows are not claimed;
on a machine where 3.12 is not the default `python3`, point the first command at it):

<!-- bundle-commands: dev-checkout -->
```bash
python3.12 -m venv .venv && .venv/bin/python -m pip install -q "pytest>=8,<10" "pyyaml>=6,<7" "jsonschema==4.26.0"
.venv/bin/python tools/fetch_pins.py
.venv/bin/python -m pytest -q
```
A CI job (`dev-checkout` in `tests.yml`) runs exactly these three lines, extracted from this README by `tools/readme_block.py` — if the
README lies, CI says so. `.venv/` and `.pinned/` are gitignored; `git status` stays clean, as other CI jobs insist.

## Layout
Packages (under `packages/`): `qa-runner`, `qa-playwright`, `qa-evidence`, `qa-bridge`, `qa-egress`, `qa-adapter-kit`, `qa-selenium`, `qa-robot`, `qa-appium`, `qa-checks`, `qa-fixture-app`.
Also in the repository: the pinned bundle (`bundle/`, `tools/build_bundle.py`), the tools of the CI checks (`tools/`), the licence matrix (`third_party/`), and examples that ship with the runner
(`packages/qa-runner/examples`). **Not in this repository:** `qa-api`, `qa-ui`, a `deploy/` directory (no Compose file, no Dockerfile, no Helm chart), standalone examples and benchmarks; earlier text
named them, and none of them exists.

Configuration of the pinned upstream versions: [pins.toml](pins.toml). The contracts bridge is in
[packages/qa-bridge](packages/qa-bridge/README.md).
The browser adapter is in [packages/qa-playwright](packages/qa-playwright/README.md).
The egress gateway and the browser launch configuration are in [packages/qa-egress](packages/qa-egress/README.md).
The licence matrix for optional adapter frameworks is in [third_party](third_party/README.md).
The shared adapter protocol, models and supervisor are in [packages/qa-adapter-kit](packages/qa-adapter-kit/README.md).
The Selenium adapters are in [packages/qa-selenium](packages/qa-selenium/README.md).
The Robot Framework adapter is in [packages/qa-robot](packages/qa-robot/README.md).
The Appium adapters are in [packages/qa-appium](packages/qa-appium/README.md).
The portable evidence bundle (layout, run-report schema, offline verifier, reader) is in [packages/qa-evidence](packages/qa-evidence/README.md).
The deterministic fixture web app with seeded defects, the target of the end-to-end tests, is in [packages/qa-fixture-app](packages/qa-fixture-app/README.md).
The `redevops-qa` command (`doctor`, `freeze`, `run`, `verify`, `report`, `inspect`, `demo`; Playwright Chromium and Robot Framework lanes) is in [packages/qa-runner](packages/qa-runner/README.md); its section "What verification does and does not prove" says what `verify` shows and what unkeyed hashes cannot, and its section "Egress matrix by engine" says what limits the network traffic of the browser lane and of the Robot lane, what the experiments measured, and what is not stopped.
The engine capability manifest (what each engine has been shown to do, with its evidence) is [qa-capabilities.json](qa-capabilities.json)
with its schema in [schemas](schemas/qa-capabilities.schema.json); the generated matrix is [docs/QA_CAPABILITIES.md](docs/QA_CAPABILITIES.md).
`python tools/check_capabilities.py` checks it (schema, pins, evidence, agreement with the adapters, freshness against `main`).
The install profiles (exact pins, prerequisites per host, smoke commands, evidence, uninstall, and which profile is verified by which CI job) are
[qa-install-profiles.json](qa-install-profiles.json), rendered in [docs/QA_INSTALL_PROFILES.md](docs/QA_INSTALL_PROFILES.md); the configuration
generator the installer page is built from is `tools/qa_install_config.py`, specified by `tests/vectors/install-config-vectors.json`.
