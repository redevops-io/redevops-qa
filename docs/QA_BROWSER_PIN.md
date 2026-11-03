# ReDevOps QA: the browser pin and how to regenerate it

Purpose: the pinned bundle does not ship Chromium. Its browser step downloads it and checks it against `bundle/browser.lock.json`. This page says what the pin holds, and the maintainer procedure for changing it. The mechanism is in `packages/qa-runner/src/qa_runner/browser_pin.py` (the check and the install), `bundle/install-browser.sh` (the step), `tools/make_browser_lock.py` (the generator), and `tools/build_bundle.py` / `tools/check_bundle.py` (carrying and checking the lock).

## What the lock holds

For one Playwright version on Linux x86_64: the sha256 of the Playwright wheel's `browsers.json` (so the revision cannot drift from the wheel), the URLs, sha256 and size of the three archives `playwright install chromium` downloads (Chrome for Testing, Chrome Headless Shell, FFmpeg), and the mode, size and sha256 of every file, and the mode of every directory, of the three install directories they unpack to. `install-browser.sh` checks each archive before unpacking it and the unpacked tree before placing it; `redevops-qa doctor` and `run` check the tree again in a bundle installation.

Not covered: the operating system libraries Chromium loads, the availability of the download host, files outside the three install directories, a change made after a check, and where the pin itself came from (the lock records the bytes the host served when it was written; it is not a publisher signature).

## When to regenerate

* Every time the pinned Playwright version changes (`bundle/third-party.lock.json`). The builder refuses a lock that is not for the Playwright wheel it bundles (version, `browsers.json` digest, revision, browser version), and `tools/check_bundle.py` makes the same comparison, so a stale lock fails the `bundle` CI job.
* Not when the download host serves other bytes for the same Playwright version. That is an event to look into, not something to absorb by regenerating: the browser step fails closed (exit 6, expected and actual sha256 named) until the cause is understood and recorded in the pull request.

## Procedure

Run on a Linux x86_64 host (an `ubuntu:24.04` linux/amd64 container is fine; an emulated amd64 container on another processor is not evidence for the runner, so say which one was used). Python 3.12 with `venv`, network access to the Playwright download host. `W` is a scratch directory; the commands download about 330 MB per tree.

```bash
# 1. the new Playwright wheel (its sha256 must be the one in bundle/third-party.lock.json) and an environment with it
python3.12 -m venv "$W/pw" && "$W/pw/bin/pip" install playwright==NEW
"$W/pw/bin/pip" download --no-deps --only-binary=:all: playwright==NEW -d "$W/wheel"

# 2. two independent fresh installs by Playwright's own installer, and what it says it downloads
for n in 1 2; do PLAYWRIGHT_BROWSERS_PATH="$W/tree-$n" "$W/pw/bin/python" -m playwright install chromium; done
PLAYWRIGHT_BROWSERS_PATH="$W/tree-1" "$W/pw/bin/python" -m playwright install --dry-run chromium > "$W/dryrun.txt"

# 3. the archives named in dryrun.txt, fetched twice (the two copies must be identical)
mkdir "$W/archives" && cd "$W/archives" && for u in $(sed -n 's/.*Download url: *//p' "$W/dryrun.txt"); do curl -fsSLO "$u"; done && sha256sum *.zip

# 4. the lock, once from each tree; the two must be identical
for n in 1 2; do python3.12 tools/make_browser_lock.py --wheel "$W"/wheel/playwright-NEW-*.whl --dry-run "$W/dryrun.txt" --archives "$W/archives" --tree "$W/tree-$n" --out "$W/lock-$n.json"; done
cmp "$W/lock-1.json" "$W/lock-2.json" && cp "$W/lock-1.json" bundle/browser.lock.json
```

`make_browser_lock.py` also unpacks every archive the way `install-browser.sh` does and refuses to write a lock unless that gives exactly the tree Playwright's installer wrote. Then build the bundle (`python tools/build_bundle.py build ...`), run `python -I tools/check_bundle.py` on it, and install it on a clean machine with `install-browser.sh` and `doctor`; CI does the same on a GitHub runner, together with the tamper cases and `python -I packages/qa-runner/src/qa_runner/browser_pin.py urls --lock bundle/browser.lock.json --fallbacks-only`.

## What the pull request must carry

* The three archive sha256 values and sizes, and the file and directory counts of the lock.
* That the two independent installs gave identical trees (the `cmp` in step 4) and identical archives, and on which host they were made.
* The output of `python -I packages/qa-runner/src/qa_runner/browser_pin.py urls --lock bundle/browser.lock.json` (every URL of the lock serves the pinned bytes).
* The CI run id of the `bundle install on a clean runner` job (the real install, the tree check, the tamper cases), and the bundle archive and `SHA256SUMS` sha256 from the CI `bundle` job next to a fresh local build.
* The diff of `bundle/browser.lock.json`, read by a human reviewer. The file is generator output: it is not edited by hand (a hand edit that is also made consistent is not caught by the builder or the checker, only by the first real install and the CI install job), and a change of a hash or a mode without a changed Playwright version needs an explanation.
