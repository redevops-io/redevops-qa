<!-- Generated from qa-capabilities.json by tools/check_capabilities.py --write-docs. Do not edit by hand. -->

# ReDevOps QA: engine capability matrix

This page is generated from [`qa-capabilities.json`](../qa-capabilities.json), which is checked in CI against its schema, the repository's pins, the adapters' own manifests and the CI history. Every claim below points to evidence in this repository or to a named CI job. Licence: source-available under the family licence (AGPL-3.0-or-later with the Commons Clause), not open source. The repository is public and pre-release: no release tag exists and nothing is published to a package registry. Every install path is a checkout of this repository at a named commit, so a package-registry install command does not exist.

## What the test levels mean

A test level says what kind of evidence stands behind an engine entry. It is not a readiness grade, and the order below is by closeness to a real device, not by how easily anyone can repeat the run.

| Test level | What it means | What it does not mean |
|---|---|---|
| `none` | No test in this repository exercises the engine through the adapter. An entry may still describe an interface, for example one that reports `unavailable`. | That the engine or the adapter is broken; only that nothing has been shown. |
| `offline-fake` | The adapter logic is tested against a fake driver or recorded engine output. The engine itself is not installed and nothing touches a browser or a device. | That the engine works with the adapter; a fake only shows what the adapter does with what the fake returns. |
| `engine-backed-ci` | A CI job installs the pinned engine (and the browser or server it needs) and runs the adapter against it; the job fails, never skips, when a dependency is missing or no test is collected. | Support for other engine versions, browsers, operating systems or architectures than the one named, or that a real device or emulator was driven. |
| `device-backed-local` | A real device or emulator was driven through the adapter by hand on a named machine and the run is recorded in the repository. No CI job repeats it. | That CI re-runs it, that it holds on another machine, API level or device, or that the run is reproducible by anyone without the same setup. |
| `device-backed-ci` | A CI job drives a real device or emulator through the adapter and fails, never skips, when none is attached. | Coverage beyond the device, operating system version and host named in the evidence. |

## Matrix

| Engine | Adapter | Engine version | Modes | Test level | Verified on | Last verified |
|---|---|---|---|---|---|---|
| Playwright (Python) | qa-playwright 0.1.0.dev0 | 1.64.1 | interactive | `engine-backed-ci` | linux-x86_64 (engine-backed-ci) | 2026-11-01 at `938eb486b508` |
| Selenium (Python) | selenium-interactive, selenium-suite 0.1.0 | 4.52.0 | interactive, suite | `engine-backed-ci` | linux-x86_64 (engine-backed-ci) | 2026-11-01 at `938eb486b508` |
| Robot Framework | robot-suite 0.1.0 | 7.5 | suite | `engine-backed-ci` | linux-x86_64 (engine-backed-ci) | 2026-11-01 at `938eb486b508` |
| Appium (Android, UiAutomator2) | appium-android-interactive 0.1.0 | 3.9.0 | interactive | `device-backed-local` | macos-arm64 (device-backed-local); linux-x86_64 (engine-backed-ci) | 2026-11-01 at `958d906360b0` |
| Appium (iOS, XCUITest) | appium-ios-interactive 0.1.0 | 3.9.0 | interactive | `none` | nowhere | never |

Each `Last verified` commit is an ancestor of the main branch; for a local run it is the commit that records the run, because the tested tree is not recorded.

## Appium caveats

### Android

* Android needs a compatible SDK, platform tools, a device or an emulator, the UiAutomator2 driver and host acceleration.
* Starting the Appium server is not a successful real UI session: only an attached device or emulator driven through the adapter shows that.
* The Android SDK, system images and emulator are the operator's, provisioned under Google's terms; they are never bundled or downloaded here.

### iOS

* iOS needs macOS, Xcode, WebDriverAgent and a supported simulator or device.
* Linux containers are not a complete iOS solution.
* The adapter reports UNAVAILABLE without a real, licensed worker; no iOS session has been run.

### Both

* A selected Appium adapter may generate client configuration while directing users to external device workers.
* Never imply that a device or emulator is bundled with the runtime.

## Engines

### Playwright (Python)

* Engine id: `playwright`; adapters: `qa-playwright`; adapter version 0.1.0.dev0; engine version 1.64.1.
* Test level: `engine-backed-ci`. Scope: interactive mode, Chromium only, on a GitHub-hosted Linux x86_64 runner.
* A real Chromium session is driven through the adapter in a CI job that fails rather than skips; only Chromium on Linux x86_64 has been exercised.
* Execution modes: interactive.
* Install: source-checkout-pip of `packages/qa-playwright` with extras `browser`. Installed with pip from a checkout of this public repository at a named commit; there is no release tag and nothing is published to a package registry. The browser comes from a separate `python -m playwright install --with-deps chromium` step, and the adapter imports the pinned agent-harness QA module named in pins.toml.
* Documentation: [packages/qa-playwright/README.md](../packages/qa-playwright/README.md). Example: `playwright-browser-lane` ([packages/qa-playwright/tests/browser/test_pw_browser_loop.py](../packages/qa-playwright/tests/browser/test_pw_browser_loop.py)).

Verified on:

| Host | Environment | Level | Scope |
|---|---|---|---|
| linux-x86_64 | GitHub-hosted ubuntu-24.04 runner, Chromium (Chrome for Testing 156.0.8078.4, Playwright chromium v1248) | `engine-backed-ci` | real Chromium driven by the pinned Playwright driver against pages the test serves from loopback |

Dependencies:

| Dependency | Kind | Pin | Provided by | Note |
|---|---|---|---|---|
| python | interpreter | requires-python = ">=3.11" | operator | the packages require 3.11 or newer; CI runs 3.12 |
| qa-playwright | source-package | version = "0.1.0.dev0" | install | the adapter package |
| playwright | pip | playwright==1.64.1 | install | the `browser` extra |
| chromium | browser-binary | not pinned here | operator | fetched by `playwright install`; the build is chosen by Playwright 1.64.1 (Chrome for Testing 156.0.8078.4 in the CI run recorded below) |
| agent-harness | pinned-source-tree | tag = "v0.2.0" | operator | the harness QA module the adapter imports; pinned by tag and commit in pins.toml and not on a package index |

Evidence:

* [CI run 41261799543](https://github.com/redevops-io/redevops-qa/actions/runs/41261799543) (whole run green), [job 124716422274](https://github.com/redevops-io/redevops-qa/actions/runs/41261799543/job/124716422274) (browser lane; 28 passed, 0 skipped, 0 failed): real Chromium through Playwright 1.64.1; the job runs the browser tests of qa-playwright and of qa-egress and fails on zero tests or any skip. Head commit `938eb486b508`, completed 2026-11-01.
* [packages/qa-playwright/tests/browser](../packages/qa-playwright/tests/browser): the tests the browser lane runs for this adapter.

Limitations:

* Chromium only; Firefox and WebKit are not exercised.
* Verified on a Linux x86_64 hosted runner only; macOS, Windows and Linux arm64 have no run.
* The real driver is exercised against pages served from loopback, not against an external site.
* Pre-release adapter (0.1.0.dev0); nothing is published, and the adapter needs the pinned harness tree from pins.toml on its import path.
* The lane is not fully deterministic: the popup test failed once and passed on re-run against the same commit (job 124725855749, run 41264993239, attempt 1; attempt 2 passed), so a green run is evidence, not a guarantee.
* Network isolation is the egress gateway's job (packages/qa-egress); the adapter's request gate is a second layer.
* A native PASS or FAIL from the engine is not the verifier's verdict: the canonical status stays UNVERIFIED until an independent verifier supplies one, and no install profile in this repository installs a verifier yet.

Licences: the adapter is source-available under the family licence (AGPL-3.0-or-later with the Commons Clause), not open source (LicenseRef-AGPL-3.0-or-later-with-Commons-Clause). Components: playwright-python Apache-2.0 (optional_extra). Technical triage in [third_party](../third_party/README.md), not legal advice.

### Selenium (Python)

* Engine id: `selenium`; adapters: `selenium-interactive`, `selenium-suite`; adapter version 0.1.0; engine version 4.52.0.
* Test level: `engine-backed-ci`. Scope: interactive and suite modes, Chrome only, on a GitHub-hosted Linux x86_64 runner.
* Both modes ran against real Chrome and ChromeDriver in CI; the scope is one browser on one runner image.
* Execution modes: interactive, suite.
* Install: source-checkout-pip of `packages/qa-adapter-kit`, `packages/qa-selenium` with extras `browser`. Installed with pip from a checkout of this public repository at a named commit; there is no release tag and nothing is published to a package registry. Chrome and ChromeDriver are the host's; the adapter is given their paths and never downloads a browser or a driver.
* Documentation: [packages/qa-selenium/README.md](../packages/qa-selenium/README.md). Example: `selenium-browser-lane` ([packages/qa-selenium/tests/browser/test_sel_browser.py](../packages/qa-selenium/tests/browser/test_sel_browser.py)).

Verified on:

| Host | Environment | Level | Scope |
|---|---|---|---|
| linux-x86_64 | GitHub-hosted ubuntu-24.04 runner, the runner's Google Chrome and ChromeDriver 156.0.8078.47 | `engine-backed-ci` | real Chrome and ChromeDriver through Selenium 4.52.0; the interactive adapter against a loopback page and a real pytest-based Selenium suite imported through the suite adapter |

Dependencies:

| Dependency | Kind | Pin | Provided by | Note |
|---|---|---|---|---|
| python | interpreter | requires-python = ">=3.11" | operator | the packages require 3.11 or newer; CI runs 3.12 |
| qa-adapter-kit | source-package | version = "0.1.0.dev0" | install | shared protocol, models and supervisor; standard library only |
| qa-selenium | source-package | version = "0.1.0.dev0" | install | the adapter package |
| selenium | pip | selenium==4.52.0 | install | the `browser` extra |
| pytest | pip | pytest>=8,<10 | operator | needed by the suite mode, which runs a pytest-based suite |
| google-chrome | browser-binary | not pinned here | operator | the host's own Chrome; the CI run recorded below used 156.0.8078.47 |
| chromedriver | driver | not pinned here | operator | the host's own ChromeDriver matching its Chrome; 156.0.8078.47 in the CI run recorded below |

Evidence:

* [CI run 41261799543](https://github.com/redevops-io/redevops-qa/actions/runs/41261799543) (whole run green), [job 124716398989](https://github.com/redevops-io/redevops-qa/actions/runs/41261799543/job/124716398989) (selenium browser lane; 11 passed, 0 skipped, 0 failed): real Chrome and ChromeDriver through Selenium 4.52.0: the interactive driver against a loopback page and a real Selenium suite run under the supervisor. Head commit `938eb486b508`, completed 2026-11-01.
* [CI run 41261799543](https://github.com/redevops-io/redevops-qa/actions/runs/41261799543) (whole run green), [job 124716398886](https://github.com/redevops-io/redevops-qa/actions/runs/41261799543/job/124716398886) (selenium adapter (offline; 135 passed, 0 skipped, 0 failed): the adapter against a fake browser and recorded pytest JUnit reports, with real pytest under the supervisor; no Selenium installed. Head commit `938eb486b508`, completed 2026-11-01.

Limitations:

* Chrome and ChromeDriver only; Firefox, Edge and Safari are not exercised.
* Verified on a Linux x86_64 hosted runner only; the browser and driver come from that runner image, so other versions are untested.
* Pages are served from loopback; navigation is default deny and is a check on navigation, not a network filter.
* The suite mode imports JUnit XML from pytest-based Selenium suites only; it does not steer a test.
* Pre-release adapter (0.1.0); nothing is published.
* A native PASS or FAIL from the engine is not the verifier's verdict: the canonical status stays UNVERIFIED until an independent verifier supplies one, and no install profile in this repository installs a verifier yet.

Licences: the adapter is source-available under the family licence (AGPL-3.0-or-later with the Commons Clause), not open source (LicenseRef-AGPL-3.0-or-later-with-Commons-Clause). Components: selenium-python Apache-2.0 (optional_extra); google-chrome LicenseRef-Proprietary-Google-Chrome (excluded_by_default). Technical triage in [third_party](../third_party/README.md), not legal advice.

### Robot Framework

* Engine id: `robotframework`; adapters: `robot-suite`; adapter version 0.1.0; engine version 7.5.
* Test level: `engine-backed-ci`. Scope: suite mode, Robot Framework 7.5 only, on a GitHub-hosted Linux x86_64 runner.
* Real Robot Framework 7.5 suites ran through the adapter in a CI job that fails rather than skips; nothing else about the engine is claimed.
* Execution modes: suite.
* Install: source-checkout-pip of `packages/qa-adapter-kit`, `packages/qa-robot` with extras `robot`. Installed with pip from a checkout of this public repository at a named commit; there is no release tag and nothing is published to a package registry.
* Documentation: [packages/qa-robot/README.md](../packages/qa-robot/README.md). Example: `robotframework-real-lane` ([packages/qa-robot/tests/real/test_rb_real.py](../packages/qa-robot/tests/real/test_rb_real.py)).

Verified on:

| Host | Environment | Level | Scope |
|---|---|---|---|
| linux-x86_64 | GitHub-hosted ubuntu-24.04 runner, Robot Framework 7.5 (no browser) | `engine-backed-ci` | real Robot Framework 7.5 started by the supervisor through the suite adapter, output.xml imported |

Dependencies:

| Dependency | Kind | Pin | Provided by | Note |
|---|---|---|---|---|
| python | interpreter | requires-python = ">=3.11" | operator | the packages require 3.11 or newer; CI runs 3.12 |
| qa-adapter-kit | source-package | version = "0.1.0.dev0" | install | shared protocol, models and supervisor; standard library only |
| qa-robot | source-package | version = "0.1.0.dev0" | install | the adapter package |
| robotframework | pip | robotframework==7.5 | install | the `robot` extra |

Evidence:

* [CI run 41261799543](https://github.com/redevops-io/redevops-qa/actions/runs/41261799543) (whole run green), [job 124716399117](https://github.com/redevops-io/redevops-qa/actions/runs/41261799543/job/124716399117) (robot real lane; 10 passed, 0 skipped, 0 failed): real Robot Framework 7.5 run by the supervisor through the suite adapter: native statuses, selectors, library refusals, timeout, scrubbed environment. Head commit `938eb486b508`, completed 2026-11-01.
* [CI run 41261799543](https://github.com/redevops-io/redevops-qa/actions/runs/41261799543) (whole run green), [job 124716399114](https://github.com/redevops-io/redevops-qa/actions/runs/41261799543/job/124716399114) (robot adapter (offline; 133 passed, 0 skipped, 0 failed): the importer against output.xml files recorded from real runs and against hostile ones, plus the allowlist scan; no Robot Framework installed. Head commit `938eb486b508`, completed 2026-11-01.

Limitations:

* Suite mode only; the adapter does not steer a test.
* Robot Framework 7.5 only, on a Linux x86_64 hosted runner; macOS and Windows have no run.
* Only allowlisted libraries run (BuiltIn, Collections, DateTime, String, XML); browser and process libraries are refused, so this is not a browser lane.
* The library scan is a guard, not a sandbox; a hostile suite is contained by the worker.
* Pre-release adapter (0.1.0); nothing is published.
* A native PASS or FAIL from the engine is not the verifier's verdict: the canonical status stays UNVERIFIED until an independent verifier supplies one, and no install profile in this repository installs a verifier yet.

Licences: the adapter is source-available under the family licence (AGPL-3.0-or-later with the Commons Clause), not open source (LicenseRef-AGPL-3.0-or-later-with-Commons-Clause). Components: robotframework Apache-2.0 (optional_extra). Technical triage in [third_party](../third_party/README.md), not legal advice.

### Appium (Android, UiAutomator2)

* Engine id: `appium-android`; adapters: `appium-android-interactive`; adapter version 0.1.0; engine version 3.9.0.
* Test level: `device-backed-local`. Scope: interactive mode on one Android 17 arm64 emulator on an Apple-silicon Mac, observed locally; CI shows only the server without a device.
* One emulator session passed three times in a row by hand; the manual device workflow has never run in CI, and CI proves only server start-up and client wiring without a device.
* Execution modes: interactive.
* Install: source-checkout-pip of `packages/qa-adapter-kit`, `packages/qa-selenium`, `packages/qa-appium` with extras `android`. Installed with pip from a checkout of this public repository at a named commit; there is no release tag and nothing is published to a package registry. The Appium server, the UiAutomator2 driver, the Android SDK and the emulator or device belong to the worker's operator: nothing here installs, downloads or bundles them.
* Documentation: [packages/qa-appium/README.md](../packages/qa-appium/README.md). Example: `appium-android-device-lane` ([packages/qa-appium/tests/real/test_ap_android_device.py](../packages/qa-appium/tests/real/test_ap_android_device.py)).

Verified on:

| Host | Environment | Level | Scope |
|---|---|---|---|
| macos-arm64 | an Apple-silicon Mac with an Android 17 (API 37, arm64-v8a, Google APIs with Play) emulator; macOS version not recorded | `device-backed-local` | one test: the Settings app opens on the attached emulator and a screenshot is a real PNG; three runs in a row, observed by hand and not in CI |
| linux-x86_64 | GitHub-hosted ubuntu-24.04 runner, Appium 3.9.0 server and client 6.1.1, no Android SDK and no device | `engine-backed-ci` | the client talks to the real server, the UiAutomator2 driver accepts the adapter's capabilities and a worker without a device is reported unavailable; no app is driven |

Dependencies:

| Dependency | Kind | Pin | Provided by | Note |
|---|---|---|---|---|
| python | interpreter | requires-python = ">=3.11" | operator | the packages require 3.11 or newer; CI runs 3.12 |
| qa-adapter-kit | source-package | version = "0.1.0.dev0" | install | shared protocol, models and supervisor; standard library only |
| qa-selenium | source-package | version = "0.1.0.dev0" | install | imported for the driver fault vocabulary |
| qa-appium | source-package | version = "0.1.0.dev0" | install | the adapter package |
| Appium-Python-Client | pip | Appium-Python-Client==6.1.1 | install | the `android` extra |
| appium | npm | appium@3.9.0 | operator | the server, installed by the operator on the worker |
| appium-uiautomator2-driver | driver | uiautomator2@8.7.3 | operator | installed into the operator's Appium home |
| nodejs | toolchain | not pinned here | operator | needed for the Appium server; the version is not pinned in this repository |
| android-sdk-and-emulator | toolchain | not pinned here | operator | Android SDK, platform tools, a system image and host acceleration, provisioned under Google's terms; never bundled |

Evidence:

* [packages/qa-appium/README.md](../packages/qa-appium/README.md): local run observed on 2026-11-01, Apple-silicon Mac, Android 17 (API 37, arm64-v8a, Google APIs with Play) emulator, Appium 3.9.0, UiAutomator2 8.7.3, client 6.1.1; 3 run(s); one test (the Settings app opens on the attached device and the screenshot is a real PNG): 0 skipped, 0 failed in each of three runs; a full adapter session on the same emulator also passed open_app, read, check, tap, type and back but is not part of the suite. a real Android emulator session through the adapter, recorded in the package README; the tested tree is not recorded, so the commit that records it is used.
* [CI run 41261799543](https://github.com/redevops-io/redevops-qa/actions/runs/41261799543) (whole run green), [job 124716399113](https://github.com/redevops-io/redevops-qa/actions/runs/41261799543/job/124716399113) (appium server lane; 5 passed, 1 deselected (the device test), 0 skipped, 0 failed): real Appium 3.9.0 server and client 6.1.1 on loopback with no Android SDK and no device; drives no app. Head commit `938eb486b508`, completed 2026-11-01.
* [CI run 41261799543](https://github.com/redevops-io/redevops-qa/actions/runs/41261799543) (whole run green), [job 124716399045](https://github.com/redevops-io/redevops-qa/actions/runs/41261799543/job/124716399045) (appium adapters (offline; 69 passed, 0 skipped, 0 failed): the adapter against a fake device, capabilities and server policy; no Appium installed. Head commit `938eb486b508`, completed 2026-11-01.
* [.github/workflows/appium-android.yml](../.github/workflows/appium-android.yml): the manual device workflow (Run workflow, naming a worker with an emulator or device); it has no run in Actions.

Limitations:

* Device-backed validation is local and manual: a single test on one emulator, observed three times in a row; the manual workflow has never run in CI and hosted runners have no emulator.
* Not verified: other API levels, x86_64 or non-Play images, physical devices, Linux or Windows hosts with a device, and any CI runner with a device.
* A running Appium server is not a real UI session: the CI lane proves server start-up and client wiring only.
* Needs a compatible Android SDK, platform tools, a device or emulator, the UiAutomator2 driver and host acceleration, all provided by the operator; no device is bundled.
* Drives an app that is already installed: no APK install, no permission grant, no adb commands, XPath not supported.
* A native PASS or FAIL from the engine is not the verifier's verdict: the canonical status stays UNVERIFIED until an independent verifier supplies one, and no install profile in this repository installs a verifier yet.

Licences: the adapter is source-available under the family licence (AGPL-3.0-or-later with the Commons Clause), not open source (LicenseRef-AGPL-3.0-or-later-with-Commons-Clause). Components: appium-server Apache-2.0 (optional_extra); appium-python-client Apache-2.0 (optional_extra); appium-uiautomator2-driver Apache-2.0 (optional_extra); android-sdk-and-emulator LicenseRef-Proprietary-Android-SDK-License (excluded_by_default). Technical triage in [third_party](../third_party/README.md), not legal advice.

### Appium (iOS, XCUITest)

* Engine id: `appium-ios`; adapters: `appium-ios-interactive`; adapter version 0.1.0; engine version 3.9.0.
* Test level: `none`. Scope: no test drives iOS; the adapter is an interface that reports UNAVAILABLE for every action unless an operator supplies a driver for their own licensed worker.
* No iOS session has ever been run. The adapter reports UNAVAILABLE; it is not a pass and not a skip.
* Execution modes: interactive.
* Install: source-checkout-pip of `packages/qa-adapter-kit`, `packages/qa-selenium`, `packages/qa-appium`. Installed with pip from a checkout of this public repository at a named commit; there is no release tag and nothing is published to a package registry. Installing the package gives an interface that reports unavailable; it does not install or drive any iOS tooling.
* Documentation: [packages/qa-appium/README.md](../packages/qa-appium/README.md). No example exists.

Verified on:

Nowhere: no run exists.

Dependencies:

| Dependency | Kind | Pin | Provided by | Note |
|---|---|---|---|---|
| python | interpreter | requires-python = ">=3.11" | operator | the packages require 3.11 or newer; CI runs 3.12 |
| qa-adapter-kit | source-package | version = "0.1.0.dev0" | install | shared protocol, models and supervisor; standard library only |
| qa-selenium | source-package | version = "0.1.0.dev0" | install | imported for the driver fault vocabulary |
| qa-appium | source-package | version = "0.1.0.dev0" | install | the adapter package |
| appium-xcuitest-driver | driver | 12.22.8 | operator | listed in the licence matrix; no workflow installs or runs it |
| apple-toolchain | toolchain | not pinned here | operator | macOS, Xcode, WebDriverAgent and a supported simulator or device on a licensed worker; never bundled |

Evidence:

* [packages/qa-appium/tests/test_ap_android_ios.py](../packages/qa-appium/tests/test_ap_android_ios.py): the offline test that the iOS interface reports UNAVAILABLE; it is not an iOS session and is not evidence that iOS works.

Limitations:

* No evidence of any kind that iOS automation works with this adapter.
* Needs macOS, Xcode, WebDriverAgent and a supported simulator or device; Linux containers are not an iOS solution.
* Every action reports UNAVAILABLE unless an operator supplies a driver factory for their own licensed worker from outside this repository.
* The Apple toolchain is excluded by default and is never bundled or downloaded.
* A native PASS or FAIL from the engine is not the verifier's verdict: the canonical status stays UNVERIFIED until an independent verifier supplies one, and no install profile in this repository installs a verifier yet.

Licences: the adapter is source-available under the family licence (AGPL-3.0-or-later with the Commons Clause), not open source (LicenseRef-AGPL-3.0-or-later-with-Commons-Clause). Components: appium-server Apache-2.0 (optional_extra); appium-xcuitest-driver Apache-2.0 (excluded_by_default); apple-toolchain LicenseRef-Proprietary-Apple-Xcode-SLA (excluded_by_default). Technical triage in [third_party](../third_party/README.md), not legal advice.
