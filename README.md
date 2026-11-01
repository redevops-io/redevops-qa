# redevops-qa

QA runner that executes versioned test specifications against a target, checks
immutable assertions deterministically, and keeps reproducible evidence.

**Status: pre-release.** There is no tagged release of this repository yet, and no package is published to PyPI; you work from a checkout. It is built
against pinned *releases* of its dependencies, [`runtime-contracts`](https://github.com/redevops-io/runtime-contracts) (`v0.3.15` and `v0.3.16`) and
[`agent-harness`](https://github.com/redevops-io/agent-harness) (`v0.2.0`), recorded with their digests in [pins.toml](pins.toml); it does not vendor them.

**Licence:** source-available, not open source: AGPL-3.0-or-later as modified by the Commons Clause, the same terms as the other ReDevOps runtime
packages. See [LICENSE.md](LICENSE.md).

## What runs in CI today
The push and pull-request workflow runs the offline test suites, the `qa/v1` conformance suite against both pinned contract states, and four jobs that
exercise a real engine: Playwright with Chromium, Selenium with Chrome, Robot Framework, and the Appium server with the UiAutomator2 driver (no device).
The real-device Android lane is a separate manual workflow, because hosted runners have no emulator: it passed locally on one Android 17 emulator and has
never run in CI. There is no iOS evidence; the iOS adapter reports `UNAVAILABLE`. An engine's own PASS is a framework result, not an independent
verdict. Details per package are in the READMEs below; vulnerability reporting is in [SECURITY.md](SECURITY.md).

## Layout
Product packages (`qa-api`, `qa-ui`, `qa-runner`, `qa-playwright`, `qa-evidence`, `qa-bridge`, `qa-egress`, `qa-adapter-kit`, `qa-selenium`,
`qa-robot`, `qa-appium`, `qa-checks`), deployment (`deploy/`), examples and benchmarks.

Configuration of the pinned upstream versions: [pins.toml](pins.toml). The contracts bridge is in
[packages/qa-bridge](packages/qa-bridge/README.md).
The browser adapter is in [packages/qa-playwright](packages/qa-playwright/README.md).
The egress gateway and the browser launch configuration are in [packages/qa-egress](packages/qa-egress/README.md).
The licence matrix for optional adapter frameworks is in [third_party](third_party/README.md).
The shared adapter protocol, models and supervisor are in [packages/qa-adapter-kit](packages/qa-adapter-kit/README.md).
The Selenium adapters are in [packages/qa-selenium](packages/qa-selenium/README.md).
The Robot Framework adapter is in [packages/qa-robot](packages/qa-robot/README.md).
The Appium adapters are in [packages/qa-appium](packages/qa-appium/README.md).
