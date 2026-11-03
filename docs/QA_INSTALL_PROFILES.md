<!-- Generated from qa-install-profiles.json by tools/check_install_profiles.py --write-docs. Do not edit by hand. -->

# ReDevOps QA: install profiles

This page is generated from [`qa-install-profiles.json`](../qa-install-profiles.json), the data the installer configurator is built from. Every profile but `local-python-qa` installs from a clone of https://github.com/redevops-io/redevops-qa at the pinned commit `55c746e35412a92a287ebbbc239a69de0fbebf10`; The repository is public and pre-release: it has no release tag and nothing is published to a package registry, so every profile is a clone of the repository at the pinned commit. The dependency release tags are the pins in pins.toml; the verified profiles do not need them. The profile `local-python-qa` installs from a bundle archive instead (see its section).

A profile is **verified** only when a CI job runs that exact profile, step by step, on the host named; **experimental** means the steps are written and partly or not at all run for that host; **planned** means nothing is offered yet and the reason is given.

## Targets

| Target | Status | Reason |
|---|---|---|
| local-python | available |  |
| docker-compose | planned | The main branch of this repository ships no Compose file, no Dockerfile and no runner service. A Compose packaging exists only as unmerged work and its files have been validated statically, never started; a Compose profile will be offered only when one is merged and run in CI. |
| kubernetes-helm | planned | This repository ships no Helm chart and no Kubernetes manifests for the runner, so there is nothing to test; the cluster checks in qa-checks inspect other people's manifests and are not a deployment of this runtime. |

Re-verification in a separate process: offered by `local-python-qa` only. Re-verification of a run's evidence in a separate process (`redevops-qa verify`: the same code the run used, so not independent of the harness and the libraries, and the hash chain it checks is unkeyed) is installed and run only by the profile local-python-qa (Playwright Chromium and Robot Framework, Linux x86_64); no other profile installs it, and an engine's own pass or fail is not a verdict.

## Profiles

| Profile | Engines | Status | Hosts |
|---|---|---|---|
| [local-python-robot](#local-python-robot) | robotframework | verified | linux-x86_64 (verified); linux-arm64 (experimental); macos-arm64 (experimental) |
| [local-python-selenium](#local-python-selenium) | selenium | verified | linux-x86_64 (verified); macos-arm64 (experimental) |
| [local-python-appium-android](#local-python-appium-android) | appium-android | experimental | macos-arm64 (experimental); linux-x86_64 (experimental) |
| [local-python-playwright](#local-python-playwright) | playwright | planned | none |
| [local-python-appium-ios](#local-python-appium-ios) | appium-ios | planned | none |
| [local-python-qa](#local-python-qa) | playwright, robotframework | experimental | linux-x86_64 (experimental); linux-arm64 (planned); macos-arm64 (planned) |

## local-python-robot

Robot Framework suites in a local Python environment. Status: **verified**.

Python 3.12 (`python3.12`); pinned pip packages: `pytest==9.2.0`, `pyyaml==6.0.3`, `robotframework==7.5`.

Prerequisites:

* Python 3.12 available as `python3.12` (the packages require 3.11 or newer; 3.12 is the version the steps were run with).
* git, and network access to https://github.com/redevops-io/redevops-qa (a public repository).
* Network access to a Python package index for the pinned packages and for the build backend (setuptools 77 or newer, not pinned here).
* All commands are run from one working directory, the one that contains the checkout, using a POSIX shell.

Hosts:

| Host | Status | Prerequisites | Verified by |
|---|---|---|---|
| linux-x86_64 | verified | Linux x86_64 with a POSIX shell; run on a GitHub-hosted ubuntu-24.04 runner. | [run 41712009322](https://github.com/redevops-io/redevops-qa/actions/runs/41712009322) (whole run green, head `036861144582`), [job 126182197434](https://github.com/redevops-io/redevops-qa/actions/runs/41712009322/job/126182197434), installed from the pinned commit `55c746e35412`, 2026-11-03: install, smoke and check phases then uninstall: 369 + 188 + 13 tests passed, 0 skipped, 0 failed, installed from the pinned commit in a clean virtual environment; the whole run is green |
| linux-arm64 | experimental | Linux arm64 with a POSIX shell. | The same steps are written for this host but no CI job runs them here. |
| macos-arm64 | experimental | macOS on Apple silicon with Python 3.12 as `python3.12`. | The same steps are written for this host but no CI job runs them here. |

Parameters:

* `checkout_dir`: where the repository is cloned (default `redevops-qa`)
* `evidence_dir`: where the smoke steps write their JUnit evidence (default `qa-evidence`)
* `venv_dir`: where the virtual environment is created (default `.venv-qa`)

### Get the source

```text
# Clone the repository
git clone https://github.com/redevops-io/redevops-qa.git redevops-qa
# Check out the pinned commit
git -C redevops-qa checkout --detach 55c746e35412a92a287ebbbc239a69de0fbebf10
```

### Install

```text
# Create a clean virtual environment
python3.12 -m venv .venv-qa
# Install the pinned Python packages
.venv-qa/bin/python -m pip install --disable-pip-version-check pytest==9.2.0 pyyaml==6.0.3 robotframework==7.5
# Install the adapter packages from the checkout (not editable, no dependency resolution)
.venv-qa/bin/python -m pip install --disable-pip-version-check --no-deps redevops-qa/packages/qa-adapter-kit redevops-qa/packages/qa-robot
# Check that the packages are imported from the virtual environment, not from the checkout
.venv-qa/bin/python -I -c 'import importlib,os,sys; root=os.path.realpath(sys.argv[1]); bad=[m for m in sys.argv[2:] if not os.path.realpath(importlib.import_module(m).__file__).startswith(root+os.sep)]; sys.exit(('"'"'not imported from the virtual environment: '"'"'+'"'"', '"'"'.join(bad)) if bad else 0)' .venv-qa qa_adapter_kit qa_robot robot
```

### Smoke test

```text
# Run the shared adapter kit tests (fake adapters, offline)
.venv-qa/bin/python -m pytest -q -p no:cacheprovider -c redevops-qa/pyproject.toml -o pythonpath= --junitxml=qa-evidence/junit-adapter-kit.xml redevops-qa/packages/qa-adapter-kit/tests
# Run the Robot adapter tests (recorded output.xml files, offline)
.venv-qa/bin/python -m pytest -q -p no:cacheprovider -c redevops-qa/pyproject.toml -o pythonpath= --junitxml=qa-evidence/junit-robot-offline.xml redevops-qa/packages/qa-robot/tests
# Run the Robot adapter against real Robot Framework 7.5
.venv-qa/bin/python -m pytest -q -p no:cacheprovider -c redevops-qa/pyproject.toml -o pythonpath= --junitxml=qa-evidence/junit-robot-real.xml -m robot_real redevops-qa/packages/qa-robot/tests/real
```

### Check the evidence

```text
# Fail on zero tests, any skip or any failure in junit-adapter-kit.xml
.venv-qa/bin/python redevops-qa/tools/check_junit.py qa-evidence/junit-adapter-kit.xml
# Fail on zero tests, any skip or any failure in junit-robot-offline.xml
.venv-qa/bin/python redevops-qa/tools/check_junit.py qa-evidence/junit-robot-offline.xml
# Fail on zero tests, any skip or any failure in junit-robot-real.xml
.venv-qa/bin/python redevops-qa/tools/check_junit.py qa-evidence/junit-robot-real.xml
```

### Uninstall

```text
# Remove the virtual environment (refuses a directory that is not one)
python3.12 -c 'import os,shutil,sys; p=sys.argv[1]; ok=os.path.isfile(os.path.join(p,'"'"'pyvenv.cfg'"'"')); ok or sys.exit('"'"'refusing to remove a directory that is not a virtual environment: '"'"'+p); shutil.rmtree(p)' .venv-qa
```

Evidence: One JUnit XML report per smoke step, written to the evidence directory; the check steps fail on zero tests, any skip or any failure. The reports show the adapter and the real engine passing their own tests; they are not an independent verdict. Files: `junit-adapter-kit.xml`, `junit-robot-offline.xml`, `junit-robot-real.xml`.

Uninstall: The steps leave two directories: the virtual environment (removed by the step above) and the evidence directory, which is yours to keep or delete. The checkout is an ordinary clone; delete it when you no longer need it. Nothing is installed outside these directories.

Limitations:

* There is no release tag and no package-registry package: the install is a checkout at the pinned commit.
* Transitive Python dependencies and the build backend are resolved by pip at install time and are not pinned or hash-checked.
* A native engine pass or fail is not an independent verdict; no verifier is installed.
* Robot Framework 7.5 only; only allowlisted libraries run, so this is not a browser profile.

## local-python-selenium

Selenium (interactive and suite) with the host's Chrome. Status: **verified**.

Python 3.12 (`python3.12`); pinned pip packages: `pytest==9.2.0`, `pyyaml==6.0.3`, `selenium==4.52.0`.

Prerequisites:

* Python 3.12 available as `python3.12` (the packages require 3.11 or newer; 3.12 is the version the steps were run with).
* git, and network access to https://github.com/redevops-io/redevops-qa (a public repository).
* Network access to a Python package index for the pinned packages and for the build backend (setuptools 77 or newer, not pinned here).
* All commands are run from one working directory, the one that contains the checkout, using a POSIX shell.
* Google Chrome and a matching ChromeDriver installed on the host, with their absolute paths given as chrome_binary and chromedriver_path; the steps never download a browser or a driver.

Hosts:

| Host | Status | Prerequisites | Verified by |
|---|---|---|---|
| linux-x86_64 | verified | Linux x86_64 with a POSIX shell; run on a GitHub-hosted ubuntu-24.04 runner. Chrome and ChromeDriver 156 were present on that runner image. | [run 41712009322](https://github.com/redevops-io/redevops-qa/actions/runs/41712009322) (whole run green, head `036861144582`), [job 126182197472](https://github.com/redevops-io/redevops-qa/actions/runs/41712009322/job/126182197472), installed from the pinned commit `55c746e35412`, 2026-11-03: install, smoke and check phases then uninstall: 369 + 154 + 12 tests passed, 0 skipped, 0 failed, real Chrome and ChromeDriver, installed from the pinned commit in a clean virtual environment; the whole run is green |
| macos-arm64 | experimental | macOS on Apple silicon with Python 3.12 as `python3.12`, Chrome and its ChromeDriver. | The same steps are written for this host but no CI job runs them here. |

Parameters:

* `checkout_dir`: where the repository is cloned (default `redevops-qa`)
* `chrome_binary`: absolute path of the host's Chrome executable (required)
* `chromedriver_path`: absolute path of the ChromeDriver executable that matches it (required)
* `evidence_dir`: where the smoke steps write their JUnit evidence (default `qa-evidence`)
* `venv_dir`: where the virtual environment is created (default `.venv-qa`)

### Get the source

```text
# Clone the repository
git clone https://github.com/redevops-io/redevops-qa.git redevops-qa
# Check out the pinned commit
git -C redevops-qa checkout --detach 55c746e35412a92a287ebbbc239a69de0fbebf10
```

### Install

```text
# Create a clean virtual environment
python3.12 -m venv .venv-qa
# Install the pinned Python packages
.venv-qa/bin/python -m pip install --disable-pip-version-check pytest==9.2.0 pyyaml==6.0.3 selenium==4.52.0
# Install the adapter packages from the checkout (not editable, no dependency resolution)
.venv-qa/bin/python -m pip install --disable-pip-version-check --no-deps redevops-qa/packages/qa-adapter-kit redevops-qa/packages/qa-selenium
# Check that the packages are imported from the virtual environment, not from the checkout
.venv-qa/bin/python -I -c 'import importlib,os,sys; root=os.path.realpath(sys.argv[1]); bad=[m for m in sys.argv[2:] if not os.path.realpath(importlib.import_module(m).__file__).startswith(root+os.sep)]; sys.exit(('"'"'not imported from the virtual environment: '"'"'+'"'"', '"'"'.join(bad)) if bad else 0)' .venv-qa qa_adapter_kit qa_selenium selenium
```

### Smoke test

```text
# Run the shared adapter kit tests (fake adapters, offline)
.venv-qa/bin/python -m pytest -q -p no:cacheprovider -c redevops-qa/pyproject.toml -o pythonpath= --junitxml=qa-evidence/junit-adapter-kit.xml redevops-qa/packages/qa-adapter-kit/tests
# Run the Selenium adapter tests (fake browser, recorded reports, offline)
.venv-qa/bin/python -m pytest -q -p no:cacheprovider -c redevops-qa/pyproject.toml -o pythonpath= --junitxml=qa-evidence/junit-selenium-offline.xml redevops-qa/packages/qa-selenium/tests
# Run both Selenium adapters against the real Chrome and ChromeDriver
QA_CHROMEDRIVER_PATH='{chromedriver_path}' QA_CHROME_BINARY='{chrome_binary}' .venv-qa/bin/python -m pytest -q -p no:cacheprovider -c redevops-qa/pyproject.toml -o pythonpath= --junitxml=qa-evidence/junit-selenium-browser.xml -m browser redevops-qa/packages/qa-selenium/tests/browser
```

### Check the evidence

```text
# Fail on zero tests, any skip or any failure in junit-adapter-kit.xml
.venv-qa/bin/python redevops-qa/tools/check_junit.py qa-evidence/junit-adapter-kit.xml
# Fail on zero tests, any skip or any failure in junit-selenium-offline.xml
.venv-qa/bin/python redevops-qa/tools/check_junit.py qa-evidence/junit-selenium-offline.xml
# Fail on zero tests, any skip or any failure in junit-selenium-browser.xml
.venv-qa/bin/python redevops-qa/tools/check_junit.py qa-evidence/junit-selenium-browser.xml
```

### Uninstall

```text
# Remove the virtual environment (refuses a directory that is not one)
python3.12 -c 'import os,shutil,sys; p=sys.argv[1]; ok=os.path.isfile(os.path.join(p,'"'"'pyvenv.cfg'"'"')); ok or sys.exit('"'"'refusing to remove a directory that is not a virtual environment: '"'"'+p); shutil.rmtree(p)' .venv-qa
```

Evidence: One JUnit XML report per smoke step, written to the evidence directory; the check steps fail on zero tests, any skip or any failure. The browser report shows the adapters driving the real Chrome against a page the test serves from loopback. Files: `junit-adapter-kit.xml`, `junit-selenium-offline.xml`, `junit-selenium-browser.xml`.

Uninstall: The steps leave two directories: the virtual environment (removed by the step above) and the evidence directory, which is yours to keep or delete. The checkout is an ordinary clone; delete it when you no longer need it. Nothing is installed outside these directories.

Limitations:

* There is no release tag and no package-registry package: the install is a checkout at the pinned commit.
* Transitive Python dependencies and the build backend are resolved by pip at install time and are not pinned or hash-checked.
* A native engine pass or fail is not an independent verdict; no verifier is installed.
* Chrome and ChromeDriver only; their versions are the host's and only the versions on the CI runner image were exercised.

## local-python-appium-android

Appium Android adapter: Python side only, with a manual device step. Status: **experimental**.

Python 3.12 (`python3.12`); pinned pip packages: `pytest==9.2.0`, `pyyaml==6.0.3`, `selenium==4.52.0`, `Appium-Python-Client==6.1.1`.

Prerequisites:

* Python 3.12 available as `python3.12` (the packages require 3.11 or newer; 3.12 is the version the steps were run with).
* git, and network access to https://github.com/redevops-io/redevops-qa (a public repository).
* Network access to a Python package index for the pinned packages and for the build backend (setuptools 77 or newer, not pinned here).
* All commands are run from one working directory, the one that contains the checkout, using a POSIX shell.
* For the manual device step only: an Appium 3.9.0 server with the UiAutomator2 8.7.3 driver listening on 127.0.0.1:4723, an Android SDK with platform tools, and an emulator or device attached, all provided by you. None of these is bundled, downloaded or installed by these steps, and a running server is not a UI session.

Hosts:

| Host | Status | Prerequisites | Verified by |
|---|---|---|---|
| macos-arm64 | experimental | macOS on Apple silicon; the one local emulator run was observed on this host type. | A local emulator run is recorded in the capability manifest; the steps here were not run as a profile. |
| linux-x86_64 | experimental | Linux x86_64 with a POSIX shell; run on a GitHub-hosted ubuntu-24.04 runner. Hosted runners have no emulator, so the manual device step cannot run there. | The Python-side steps are run by a CI job; the manual step is not. |

Parameters:

* `checkout_dir`: where the repository is cloned (default `redevops-qa`)
* `evidence_dir`: where the smoke steps write their JUnit evidence (default `qa-evidence`)
* `venv_dir`: where the virtual environment is created (default `.venv-qa`)

### Get the source

```text
# Clone the repository
git clone https://github.com/redevops-io/redevops-qa.git redevops-qa
# Check out the pinned commit
git -C redevops-qa checkout --detach 55c746e35412a92a287ebbbc239a69de0fbebf10
```

### Install

```text
# Create a clean virtual environment
python3.12 -m venv .venv-qa
# Install the pinned Python packages
.venv-qa/bin/python -m pip install --disable-pip-version-check pytest==9.2.0 pyyaml==6.0.3 selenium==4.52.0 Appium-Python-Client==6.1.1
# Install the adapter packages from the checkout (not editable, no dependency resolution)
.venv-qa/bin/python -m pip install --disable-pip-version-check --no-deps redevops-qa/packages/qa-adapter-kit redevops-qa/packages/qa-selenium redevops-qa/packages/qa-appium
# Check that the packages are imported from the virtual environment, not from the checkout
.venv-qa/bin/python -I -c 'import importlib,os,sys; root=os.path.realpath(sys.argv[1]); bad=[m for m in sys.argv[2:] if not os.path.realpath(importlib.import_module(m).__file__).startswith(root+os.sep)]; sys.exit(('"'"'not imported from the virtual environment: '"'"'+'"'"', '"'"'.join(bad)) if bad else 0)' .venv-qa qa_adapter_kit qa_selenium qa_appium appium
```

### Smoke test

```text
# Run the shared adapter kit tests (fake adapters, offline)
.venv-qa/bin/python -m pytest -q -p no:cacheprovider -c redevops-qa/pyproject.toml -o pythonpath= --junitxml=qa-evidence/junit-adapter-kit.xml redevops-qa/packages/qa-adapter-kit/tests
# Run the Appium adapter tests (fake device, offline; the iOS interface reports unavailable)
.venv-qa/bin/python -m pytest -q -p no:cacheprovider -c redevops-qa/pyproject.toml -o pythonpath= --junitxml=qa-evidence/junit-appium-offline.xml redevops-qa/packages/qa-appium/tests
# MANUAL: run the Android device test against your own server and attached emulator or device (manual: not run by CI)
QA_APPIUM_URL=http://127.0.0.1:4723 .venv-qa/bin/python -m pytest -q -p no:cacheprovider -c redevops-qa/pyproject.toml -o pythonpath= --junitxml=qa-evidence/junit-appium-android.xml -m appium_android redevops-qa/packages/qa-appium/tests/real
```

### Check the evidence

```text
# Fail on zero tests, any skip or any failure in junit-adapter-kit.xml
.venv-qa/bin/python redevops-qa/tools/check_junit.py qa-evidence/junit-adapter-kit.xml
# Fail on zero tests, any skip or any failure in junit-appium-offline.xml
.venv-qa/bin/python redevops-qa/tools/check_junit.py qa-evidence/junit-appium-offline.xml
# Fail on zero tests, any skip or any failure in junit-appium-android.xml (manual: not run by CI)
.venv-qa/bin/python redevops-qa/tools/check_junit.py qa-evidence/junit-appium-android.xml
```

### Uninstall

```text
# Remove the virtual environment (refuses a directory that is not one)
python3.12 -c 'import os,shutil,sys; p=sys.argv[1]; ok=os.path.isfile(os.path.join(p,'"'"'pyvenv.cfg'"'"')); ok or sys.exit('"'"'refusing to remove a directory that is not a virtual environment: '"'"'+p); shutil.rmtree(p)' .venv-qa
```

Evidence: The two offline reports come from the steps a CI job runs. The device report exists only if you run the manual step against your own device worker. Files: `junit-adapter-kit.xml`, `junit-appium-offline.xml`, `junit-appium-android.xml`.

Uninstall: The steps leave two directories: the virtual environment (removed by the step above) and the evidence directory, which is yours to keep or delete. The checkout is an ordinary clone; delete it when you no longer need it. Nothing is installed outside these directories.

Limitations:

* There is no release tag and no package-registry package: the install is a checkout at the pinned commit.
* Transitive Python dependencies and the build backend are resolved by pip at install time and are not pinned or hash-checked.
* A native engine pass or fail is not an independent verdict; no verifier is installed.
* Experimental: the device step is manual and has never run in CI; the one recorded emulator run is local (see the capability manifest).
* No device, emulator, Android SDK or Appium server is bundled or installed.

## local-python-playwright

Playwright with Chromium in a local Python environment. Status: **planned**.

Not offered: The adapter imports the pinned agent-harness tree (pins.toml names its tag and commit), which no tested step fetches or puts on the import path, and the browser comes from a separate download step; a tested path for both has not been written, so none is offered.

## local-python-appium-ios

Appium iOS. Status: **planned**.

Not offered: No iOS session has ever been run: the adapter reports UNAVAILABLE for every action. iOS needs macOS with Xcode, WebDriverAgent and a supported simulator or device, which are never bundled.

## local-python-qa

ReDevOps QA in a local Python environment: the pinned bundle, the Playwright Chromium and Robot Framework lanes, and the verifier. Status: **experimental**.

Python 3.12 (`python3.12`); pinned pip packages: none of its own (every wheel is pinned by hash in the bundle's requirements.lock).

Prerequisites:

* Python 3.12 available as `python3.12` with the `venv` module (Debian and Ubuntu: the `python3.12-venv` package). The bundle is built for CPython 3.12 and install.sh refuses any other minor.
* The bundle archive and its `.tar.sha256` file in one directory (`bundle_dir`): built from a checkout of https://github.com/redevops-io/redevops-qa with `python tools/build_bundle.py build --out DIR`, or taken from a workflow run. No bundle is published. Compare the sha256 of the archive with a value you obtained from somewhere its producer does not control.
* bash, tar, and root or sudo for the browser step's `--with-deps` (it installs the operating system libraries Chromium needs with apt).
* Network access to the Playwright download host for Chromium (the browser is not in the bundle; its archives are checked against sha256 values pinned in the bundle before they are unpacked). Nothing else is downloaded by these steps: the wheels are installed from the bundle with `--no-index --require-hashes`.
* All commands are run from one working directory, using a POSIX shell.

Hosts:

| Host | Status | Prerequisites | Verified by |
|---|---|---|---|
| linux-x86_64 | experimental | Linux x86_64 with a POSIX shell; the CI job runs these steps on a GitHub-hosted ubuntu-24.04 runner. | Every step of this profile is run by CI on every push (the job profile-local-python-qa), starting from the bundle the bundle job built. The host stays experimental until a run on the main branch is recorded here: verified needs a recorded run whose head commit is an ancestor of main. |
| linux-arm64 | planned |  | not run |
| macos-arm64 | planned |  | not run |

Parameters:

* `bundle_dir`: the directory that holds the bundle archive and its .tar.sha256 file (required)
* `evidence_dir`: where the demo writes its evidence bundle (default `qa-evidence`)
* `install_dir`: a new directory the installation is made in (it must not exist or be empty; uninstall removes it) (required)

### Get the source

```text
# Check that the archive has the digest in its .tar.sha256 file (the file only says what the producer wrote: compare the digest with a value from elsewhere)
python3.12 -I -c 'import hashlib,sys; a,b=sys.argv[1:3]; want=open(b,encoding='"'"'utf-8'"'"').read().split()[0]; got=hashlib.sha256(open(a,'"'"'rb'"'"').read()).hexdigest(); sys.exit(0 if got==want else '"'"'the archive does not have the digest in '"'"'+b)' '{bundle_dir}/redevops-qa-bundle-0.1.0.dev0-cp312-linux-x86_64.tar' '{bundle_dir}/redevops-qa-bundle-0.1.0.dev0-cp312-linux-x86_64.tar.sha256'
# Unpack the archive into the working directory
tar xf '{bundle_dir}/redevops-qa-bundle-0.1.0.dev0-cp312-linux-x86_64.tar'
```

### Install

```text
# Install into a new directory: checks the Python minor, the platform and every file of the bundle, then pip install --no-index --require-hashes from the wheelhouse
redevops-qa-bundle-0.1.0.dev0-cp312-linux-x86_64/install.sh --prefix '{install_dir}' --python python3.12
# The separate browser step: downloads Chromium (not part of the bundle; the archives and the unpacked tree are checked against the bundle's pin) and the operating system libraries it needs (not covered by the pin)
redevops-qa-bundle-0.1.0.dev0-cp312-linux-x86_64/install-browser.sh --prefix '{install_dir}' --with-deps
```

### Smoke test

```text
# Check the machine: Python, platform, the pinned dependencies against pins.toml, Playwright and a real Chromium launch, Robot Framework, the fixture app, the egress gateway
'{install_dir}/bin/redevops-qa' doctor
# Run the built-in plan: a Playwright Chromium lane and a Robot Framework lane against the fixture app, one run id, one evidence bundle (exit status 0 only when every frozen assertion is verified)
'{install_dir}/bin/redevops-qa' demo --out qa-evidence --run-id profile-demo
```

### Check the evidence

```text
# Re-verify the evidence bundle from the bundle alone, in a process of its own (exit status 0 for an accepted run that verified every assertion, 5 for any finding)
'{install_dir}/bin/redevops-qa' verify qa-evidence/profile-demo
```

### Uninstall

```text
# Remove the installation directory, and nothing else
redevops-qa-bundle-0.1.0.dev0-cp312-linux-x86_64/uninstall.sh --prefix '{install_dir}'
```

Evidence: The demo writes one evidence bundle, {evidence_dir}/profile-demo, and the check step re-verifies it; no JUnit file is involved.

Uninstall: uninstall.sh removes the installation directory (virtual environment, browser directory, launcher) and refuses a directory it did not make. The evidence directory and the operating system packages installed by --with-deps stay.

Limitations:

* CPython 3.12 on Linux x86_64 only. Another Python minor or platform is refused by install.sh; macOS and Windows are not claimed.
* No bundle is published and no release exists: the archive comes from a build of the repository or from a workflow run, and its digest is only as trustworthy as the place you obtained it from.
* Chromium is downloaded when the browser step runs and is not shipped in the bundle; the bundle pins the sha256 of the archives and the mode, size and sha256 of every file of the unpacked tree, the step refuses an archive that does not match, and doctor checks the installed tree. Not covered: the operating system libraries of --with-deps, and the availability of the download host.
* The runner in this release runs plans against the bundled fixture app only; a Robot lane that asks for the kernel layers (`origin-only`) is limited by them and does not start where they are unavailable (`doctor` measures them), and a Robot lane that says `not-enforced` is limited by nothing (see the egress matrix in the runner's README).
* `verify` recomputes the verdicts from the evidence bundle in a separate process with the same code the run used; the hash chain inside a bundle is unkeyed, so only a manifest digest (the anchor) obtained from somewhere the producer cannot rewrite, or a signature of it by a key the producer does not hold (optional), shows that a bundle is the one it was taken from or signed. A verified run does not show that the application under test is correct.
* The agent-harness and runtime-contracts trees are installed from the bundle at the commits pins.toml names; the name `agent-harness` on the public package index belongs to an unrelated project and is never installed.
