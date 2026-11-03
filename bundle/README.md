# redevops-qa bundle {{bundle_version}}

A pinned bundle of `redevops-qa`: the `redevops-qa` command, the packages it needs, the two pinned upstream trees it verifies itself against, and the third-party
wheels (Playwright, Robot Framework and their dependencies), as one wheelhouse with a hash for every wheel. It installs without a network (except for the browser
step) into a directory of your choice and uninstalls by removing that directory.

Scope: **CPython {{python}} on {{platform}}, nothing else.** Another Python minor or another platform is refused by `install.sh` before it creates anything. macOS and
Windows are not claimed. Selenium and Appium are not part of this bundle. Built from commit `{{commit}}` of `redevops-io/redevops-qa`; {{wheel_count}} wheels.

## Prerequisites

* `python3.12` on `PATH` with its `venv` module (Debian and Ubuntu: `apt-get install python3.12-venv`), `bash`, `tar`, `sha256sum`. `install.sh --python PATH` names another interpreter, which must still be CPython 3.12.
* `sudo` or root for the browser step's `--with-deps` (apt installs the operating system libraries Chromium needs). Without `--with-deps` the step needs those libraries to be present already.
* Network access to the Playwright download host for Chromium, and nothing else: the wheels are installed from this directory with `--no-index`.
* The prefix is an absolute path that does not exist (or is an empty directory), is not a symbolic link, and contains only letters, digits and `. _ / + -` (no spaces: the path is written into a launcher script). `install.sh` refuses anything else with exit status 2 or 5 before it creates anything.
* To build the bundle yourself (`tools/build_bundle.py`, not needed to install one): a host Python 3.11 or newer with `pip` (on a stock Ubuntu: `python3-pip`), `git`, and network access to the package index for the pinned, hash-checked wheels.

## Install, run, uninstall

These blocks are what the CI job of the repository runs, unchanged, on a clean `ubuntu-24.04` runner. `DIR` below is `$HOME/redevops-qa`; use any new directory.

Check the archive against the digest you were given, unpack it and enter it:

<!-- bundle-commands: unpack -->
```bash
sha256sum -c {{bundle_name}}.tar.sha256
tar xf {{bundle_name}}.tar
cd {{bundle_name}}
```

Install into a new directory, then the separate browser step (it downloads Chromium; `--with-deps` also installs the operating system libraries Chromium needs, once per
machine, with apt through sudo unless you are root):

<!-- bundle-commands: install -->
```bash
./install.sh --prefix "$HOME/redevops-qa"
./install-browser.sh --prefix "$HOME/redevops-qa" --with-deps
```

Check the machine, then run the built-in demonstration (a fixture app, a Playwright Chromium lane and a Robot Framework lane, one verifier; it exits 0 only when
every frozen assertion is verified):

<!-- bundle-commands: use -->
```bash
"$HOME/redevops-qa/bin/redevops-qa" doctor
"$HOME/redevops-qa/bin/redevops-qa" demo --out "$HOME/redevops-qa-evidence"
```

Uninstall. This removes the whole directory (virtual environment, browser directory, launcher) and nothing else; the evidence directory you chose above and the
operating system libraries of `--with-deps` stay:

<!-- bundle-commands: uninstall -->
```bash
./uninstall.sh --prefix "$HOME/redevops-qa"
```

`uninstall.sh` refuses a directory that `install.sh` did not make, or that holds anything `install.sh` did not create. `install.sh` refuses a prefix that exists and is
not empty, and a failed install removes what it made. `uninstall.sh` needs a Python (`python3.12` or `python3`) on `PATH` to read `INSTALL.json`, and refuses a directory unless it holds exactly what `install.sh` wrote for that directory (schema, entries, the recorded prefix, a virtual environment). The recorded prefix is the physical path at install time, so an installation that was moved, or is reached through another mount path, is refused (nothing is removed): remove such a directory by hand, or move it back.

## Roll back

Install the previous bundle into a new directory with its own `install.sh`, run its `doctor`, and remove the directory of the bundle you are leaving with `uninstall.sh`.
Two installations never share a file. Moving an installed directory does not work (the virtual environment has absolute paths): install again.

## What is checked, and what is not

* `install.sh` runs `pip install --no-index --find-links wheelhouse --require-hashes -r requirements.lock`: pip refuses any wheel whose sha256 is not the one in
  `requirements.lock`, any wheel that is not listed and any version that is not locked. Before that it checks every file of the bundle against `SHA256SUMS`, and the Python
  minor and platform against `BUNDLE.json`.
* `SHA256SUMS`, `requirements.lock` and `BUNDLE.json` are inside the bundle, so they detect damage and a partial replacement, not a replacement of the whole bundle.
  Whoever can replace the archive can replace them too. Compare the sha256 of the archive with a value you obtained from somewhere its producer does not control (the
  `.tar.sha256` file next to it is only as good as where you got it).
* **Chromium is downloaded** by the browser step, from the Playwright download host. It is not in the bundle and it is **not hashed** by it. `BUNDLE.json` records which build the
  pinned Playwright expects, and `redevops-qa doctor` reports the build that launches.
* `redevops-qa doctor` checks that every first-party package is imported from this installation (the launcher `bin/redevops-qa` runs `python -E -s`, so a `PYTHONPATH` holding another copy is not read) and that every file of the pinned `runtime-contracts` and `agent-harness` trees, `LICENSE` and `pyproject.toml` included, is the one the bundle shipped. **Not covered:** bytecode (`__pycache__`, `*.pyc`, skipped by the pin digest too); the first-party wheels after installation (pip checked them against `requirements.lock` when it installed them); a change made together with `pinned-files.json` itself. The virtual environment's pip is the host Python's (`ensurepip`), not part of the bundle.
* The build is deterministic in design (sorted entries, fixed timestamps, no compression of the archive). This README claims nothing about two builds being byte for byte equal.
* A run's evidence is hash-linked and the chain is unkeyed: someone who can rewrite a whole evidence bundle can rewrite its digests too. `redevops-qa verify --anchor` compares
  the manifest digest with a value you obtained elsewhere; a match shows the bundle is the one that value was taken from, and nothing in it authenticates where the value came from.
* The harness is installed from this bundle only. The name `agent-harness` on the public package index belongs to an unrelated project: do not install it by name.

## Licences

This bundle is an assembly of separately licensed parts; there is no single licence for the whole.

* The `redevops-qa` packages and `runtime-contracts`: source-available under the family licence (AGPL-3.0-or-later with the Commons Clause); not open source. Texts: `licences/redevops-qa/`
  and `licences/runtime-contracts/`.
* `agent-harness`: plain AGPL-3.0-or-later (without the Commons Clause). Text: `licences/agent-harness/`.
* The third-party wheels: their own licences, unmodified, each with its licence files in its `dist-info` (the list with the licence each wheel declares is in `BUNDLE.json`).
* Chromium: downloaded at install time under its own licences; not part of this bundle.
