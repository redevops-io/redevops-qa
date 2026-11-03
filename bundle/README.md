# redevops-qa bundle {{bundle_version}}

A pinned bundle of `redevops-qa`: the `redevops-qa` command, the packages it needs, the two pinned upstream trees it verifies itself against, and the third-party
wheels (Playwright, Robot Framework and their dependencies), as one wheelhouse with a hash for every wheel. It installs without a network (except for the browser
step) into a directory of your choice and uninstalls by removing that directory.

Scope: **CPython {{python}} on {{platform}}, nothing else.** Another Python minor or another platform is refused by `install.sh` before it creates anything. macOS and
Windows are not claimed. Selenium and Appium are not part of this bundle. Built from commit `{{commit}}` of `redevops-io/redevops-qa`; {{wheel_count}} wheels.

## Prerequisites

* `python3.12` on `PATH` with its `venv` module (Debian and Ubuntu: `apt-get install python3.12-venv`), `bash`, `tar`, `sha256sum`. `install.sh --python PATH` names another interpreter, which must still be CPython 3.12.
* `sudo` or root for the browser step's `--with-deps` (apt installs the operating system libraries Chromium needs). Without `--with-deps` the step needs those libraries to be present already.
* Optional, only for the signed anchor (`redevops-qa anchor sign`, `verify --anchor-sig`): the OpenSSH client's `ssh-keygen` (OpenSSH 8.0 or later) in `/usr/bin` or `/bin`. Without it a verification that is given a signature exits 7 and accepts nothing; everything else works without it.
* Network access to the Playwright download host for Chromium (`cdn.playwright.dev`, which redirects to a Google storage bucket; the URLs are in `browser.lock.json`), and nothing else: the wheels are installed from this directory with `--no-index`. The browser step fails, installing nothing, if the host is unreachable or serves bytes other than the pinned ones; `--mirror BASE` fetches the archives from a place you control instead (the bytes must still be the pinned ones).
* The prefix is an absolute path that does not exist (or is an empty directory), is not a symbolic link, and contains only letters, digits and `. _ / + -` (no spaces: the path is written into a launcher script). `install.sh` refuses anything else with exit status 2 or 5 before it creates anything.
* As root (HOME=/root), use a prefix outside `/root`, for example `/opt/redevops-qa`: `install.sh` refuses a prefix under any path the adapter kit's path policy refuses (`/root`, `/etc`, `/proc`, `/sys`, `/dev`, `/run`, `/var/run`, `/boot`, a component such as `.config` or `.ssh`; the list is read from the adapter kit inside the bundle) with exit status 2, because the Robot lane's command line names the interpreter and the guard script of the installation and a refused path there ends `demo` INCONCLUSIVE (`PROHIBITED_PATH`). The temporary directory must not be under such a path either (`TMPDIR`; `doctor` checks the interpreter, the guard script and the working directory a run makes under the temporary directory, and names the path and the rule (exit status 3); `run` and `demo` make the same check and do not start otherwise, so a run is never started into an INCONCLUSIVE). `HOME` and the evidence directory (`--out`) may be anywhere, including under `/root`: they are not on a lane's command line, and a run with both under `/root` (the installation under `/opt`) was checked and ends VERIFIED. The interpreter is judged by the path the installation gives it, so a virtual environment made from a Python kept under `/root` (a pyenv or uv Python) is fine with a prefix under `/opt`; only a plan with a Robot lane is checked (the browser lane's command line carries none of these paths). The refused-path list itself is not relaxed.
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

Install into a new directory, then the separate browser step (it downloads Chromium and checks it against the pin in `browser.lock.json`; `--with-deps` also installs the
operating system libraries Chromium needs, once per machine, with apt through sudo unless you are root; those packages are not covered by the pin):

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
* **Chromium is downloaded** by the browser step, from the Playwright download host. It is not in the bundle (it is about 330 MB of archives, 710 MB unpacked), and it is **pinned** by
  `browser.lock.json`, a reviewed file of the repository that the bundle carries (next to `install-browser.sh`, and under `share/redevops-qa/` of the installation). For Playwright {{playwright_version}} on
  Linux x86_64 it pins the revision {{chromium_revision}} (Chromium {{chromium_version}}) that the `browsers.json` of the Playwright wheel in this bundle expects (`tools/check_bundle.py` compares the two), the
  sha256 and the size of the three archives `playwright install chromium` downloads (Chrome for Testing, Chrome Headless Shell, FFmpeg), and the mode, size and sha256 of each of the
  {{browser_files}} files of the three install directories they unpack to. `install-browser.sh` refuses an archive whose sha256 or size is not the pinned one **before** it unpacks that archive (the message
  names the expected and the actual sha256; the check is per archive, so a bad later archive is found after the earlier ones were unpacked into staging), unpacks into `<prefix>/browsers/.staging-<pid>`, checks the unpacked tree against the lock and only then renames each install directory into place. A failure (exit status 6) or an INT, TERM or HUP removes the staging directory and anything the run placed; a kill with SIGKILL or a power loss cannot be caught, and the next run removes a `.staging-<pid>` whose process is gone. `redevops-qa doctor` makes the same tree check in a bundle installation (a missing `browser.lock.json` there is a failure, as is a lock that is not the one `install.sh` recorded in `INSTALL.json`; a missing browser is reported as `not installed`; a changed, missing or extra file or a changed mode fails, and the browser is then not
  launched), and `run` and `demo` make it before they start a plan with a browser lane (exit status 3); a plan with only a Robot lane does not need the browser and is not checked. In a source checkout there is no pin and no check (`doctor` says so with a warning). Run through the launcher `bin/redevops-qa`, which sets `PLAYWRIGHT_BROWSERS_PATH`: the lane children of a run get a temporary `HOME`, so `doctor` fails when the variable is not set rather than check a directory the lane would not use.
  **Not covered:** the operating system libraries Chromium loads (the apt packages of `--with-deps`, or whatever is already on the machine); the availability of the Playwright download host;
  files outside the three install directories; a change made to the tree after a check (the check is made at one moment, it does not guard the files); a signal in the instant between the renames and the final check (the run then removes what it placed on the way out, but that window is not exercised by a test); each download has a read timeout and a total limit (300 s plus the pinned size at 100 KB/s) and a file larger than its pinned size is refused; and the origin of the pin itself: the lock records
  the bytes the download host served when it was written, not a signature from the browser's publisher, and it sits inside the bundle, so it detects damage and a partial replacement, not a
  replacement of the whole bundle (compare the archive digest, as above). The same limit applies inside an installation: the lock, `INSTALL.json` (which records the lock's sha256) and `doctor` are in the same directory with the same trust, so an edit of the lock made together with the `browser_lock_sha256` key of `INSTALL.json`, removal of that key, or removal of both the lock and `INSTALL.json` is not detected (the installation then looks like a source checkout: `doctor` warns and exits 0, and `run` and `demo` print `browser pin: not checked (not a bundle install)` and start the browser lane). The anchor outside the installation is the digest of the archive. How the lock is regenerated when Playwright changes is in `docs/QA_BROWSER_PIN.md` of the repository. Playwright writes an empty `DEPENDENCIES_VALIDATED` file into an install directory the first time it launches the browser; it is the only file the check accepts that the lock does not list.
* `redevops-qa doctor` checks that `share/redevops-qa/THIRD_PARTY_NOTICES` is installed and that every file in it is the one the bundle shipped (`INDEX.json`, whose digest `INSTALL.json` records from `BUNDLE.json` at install time, next to the `browser_lock_sha256` it records); a change made together with `INDEX.json` and `INSTALL.json` is not covered. It also checks that every first-party package is imported from this installation (the launcher `bin/redevops-qa` runs `python -E -s`, so a `PYTHONPATH` holding another copy is not read) and that every file of the pinned `runtime-contracts` and `agent-harness` trees, `LICENSE` and `pyproject.toml` included, is the one the bundle shipped. **Not covered:** bytecode (`__pycache__`, `*.pyc`, skipped by the pin digest too); the first-party wheels after installation (pip checked them against `requirements.lock` when it installed them); a change made together with `pinned-files.json` itself. The virtual environment's pip is the host Python's (`ensurepip`), not part of the bundle.
* The build is deterministic in design (sorted entries, fixed timestamps, no compression of the archive). This README claims nothing about two builds being byte for byte equal.
* A run's evidence is hash-linked and the chain is unkeyed: someone who can rewrite a whole evidence bundle can rewrite its digests too. `redevops-qa verify --anchor` compares
  the manifest digest with a value you obtained elsewhere; a match shows the bundle is the one that value was taken from, and nothing in it authenticates where the value came from.
* An optional signed anchor: `redevops-qa verify --anchor-sig FILE --anchor-pub FILE` checks a detached OpenSSH signature of the manifest digest (made with `redevops-qa anchor statement` / `anchor sign` and a key you
  hold; this bundle holds no key) against ONE Ed25519 public key you supply, by calling the OpenSSH client's `ssh-keygen -Y verify`, which must be on the host (a verification without it exits 7 and accepts nothing). It shows
  that the manifest digest was signed by the holder of the matching private key and that a bundle rewritten after signing does not verify; it does not show who holds that key, that the key was not exposed, when the
  signature was made, or that the run was executed on an uncompromised host. A signature is only as trustworthy as the channel through which you obtained the public key. The check needs OpenSSH 8.0 or later (`ssh-keygen`, found in
  `/usr/bin` or `/bin`) on the host; nothing else in this bundle needs it.
* The harness is installed from this bundle only. The name `agent-harness` on the public package index belongs to an unrelated project: do not install it by name.

## Licences

This bundle is an assembly of separately licensed parts; there is no single licence for the whole.

* The `redevops-qa` packages and `runtime-contracts`: source-available under the family licence (AGPL-3.0-or-later with the Commons Clause); not open source. Texts: `licences/redevops-qa/`
  and `licences/runtime-contracts/`.
* `agent-harness`: plain AGPL-3.0-or-later (without the Commons Clause). Text: `licences/agent-harness/`.
* The third-party wheels: their own licences, unmodified, each with its licence files (the list with the licence each wheel declares is in `BUNDLE.json`). **The Playwright wheel contains a Node.js runtime binary** (`playwright/driver/node`, licence file `playwright/driver/LICENSE`), the Playwright driver with 79 distinct npm packages inlined into it (81 notice sections: two packages have a section in each of the two sidecar files) and libwebp, each under its own notice (`playwright/driver/package/lib/*.LICENSE`); its declared licence, Apache-2.0, does not describe them. The repository's licence matrix (`third_party/adapter-license-matrix.yaml`) records every third-party wheel of this bundle as `staged_unmodified`: **private staging only; public distribution requires an owner decision.**
* **Licence and notice texts: `THIRD_PARTY_NOTICES/`** (in this directory; `INDEX.json` lists every file with its sha256, its size and its origin). It holds the licence and notice files of the shipped wheels and, for components whose shipped files carry no licence text, the text fetched from the upstream source of the exact version found. `install.sh` installs the same tree as `share/redevops-qa/THIRD_PARTY_NOTICES` under the installation's virtual environment (`<prefix>/venv/share/redevops-qa/THIRD_PARTY_NOTICES`), and `redevops-qa doctor` checks that it is present and that every file is the one the bundle shipped.
* What the matrix records as established (identification from the shipped bytes, and the licence text of that exact version fetched from the primary source, with the URL, the retrieval date and the sha256 of what was fetched): the Node.js runtime is Node.js 24.22.1, byte for byte the executable of the official nodejs.org release, and its licence file is that release's `LICENSE`, which lists 44 externally maintained libraries (their licences are tabulated as the text names them: MIT, Apache-2.0, BSD, ISC, Zlib, Unicode-3.0, Blue Oak, CC0 and, for the npm tree that is not in the wheel, the Artistic License 2.0); of the 79 inlined npm packages, 78 (77 with an MIT, ISC or BSD notice, and minimatch with the Blue Oak Model License 1.0.0) match the registry entry and the published tarball of the exact version named in the notice; the WebP codec (libwebp and Emscripten) has its notice reproduced from the pinned sources; React, CodeMirror, xterm.js, yaml and zip.js in the Playwright trace viewer, report and dashboard bundles, the Visual Studio Code colour and codicon CSS rules, the `xdg-open` script, and the third-party source files vendored in Playwright's repository, have their texts; the six Open Iconic icons in the Robot Framework `log.css` are byte for byte files of the Open Iconic repository under its MIT icon licence; jQuery 3.5.1 (with Sizzle) in `robot/htmldata/lib/jquery.min.js` is byte for byte the official file under the MIT text of its tag; the JavaScript inlined into `robot/htmldata/libdoc/libdoc.html` was reproduced byte for byte from Robot Framework's own build inputs and is Handlebars 4.7.9 (MIT), mark.js 8.11.1 (MIT), source-map 0.6.1 (BSD 3-clause) and the Parcel bundler runtime (MIT).
* What is not established, and stays open: **`proxy-agent-negotiate` 1.1.0**, inlined in the Playwright driver, is a real npm package declared MIT and has no licence text in any source that was looked at (the Playwright notice, the published package, its upstream repository); **jQuery tablesorter 2.30.5** (`robot/htmldata/lib/jquery.tablesorter.min.js`) is identified exactly and declared `(MIT OR GPL-2.0)` by its upstream, which publishes no licence text for the fork (the original project's MIT text is shipped as a related text, labelled as such); **jQuery Templates** (MIT or GPL Version 2 header), **jQuery Highlight** (MIT header), **JSXCompressor** (Apache-2.0 or LGPL-3.0 header), **`robot/utils/asserts.py`** (unittest-derived: "the same terms as Python itself") and **`robot/output/console/highlighting.py`** (code adapted from Andre Burgaud, MIT named, no text) have declarations and no licence text tied to the shipped file; the tablesorter blue-theme styles and icons in `robot/htmldata/rebot/common.css` (same project and same declared-only position as tablesorter) and the tab styles in `robot/htmldata/rebot/report.css` (adapted from an HTML Dog article, attribution comment only) carry no licence statement at all; the **codicon icon font** has two candidate licences (a Visual Studio Code MIT text in Playwright's folder, CC BY 4.0 in its upstream project); the **browser logo SVGs** of the Playwright dashboard have no licence for the artwork. Also open: which of the Node.js libraries are linked into the executable, and the signature of the Node.js release checksums (not verified).
* Owner decisions are recorded per item in the matrix (`owner_decision`, with date and conditions that the checker evaluates). On 2026-11-03 the owner decided: Node.js 24.22.1 accepted provisionally; ICU (Unicode License V3) accepted; minimatch (Blue Oak) accepted with its licence text and attribution; `proxy-agent-negotiate` and jQuery tablesorter conditionally accepted (the MIT declaration is evidence of licensing and the missing text stays documented; for tablesorter the MIT alternative is elected, not GPL-2.0). Every other shipped item says `none yet`, and public distribution of the bundle stays an owner decision until every one has a decision.
* None of this settles distribution. The texts state obligations (notice preservation, and for some a patent licence or a restriction on using names). Besides permissive licences, the Node.js licence file reproduces a GPL notice with the Autoconf exception (in ICU's section, for ICU4C build-script files) and the Artistic License 2.0 text of the npm tree that is not in the wheel, and tablesorter's declaration offers GPL-2.0 as an alternative to MIT. Whether the facts are acceptable for distributing this bundle is an owner decision.
* Chromium: downloaded at install time under its own licences (pinned by sha256 in `browser.lock.json`); not part of this bundle.
